import { existsSync, readFileSync } from 'node:fs';
import type { JsonObject, RuntimeExecutionContext } from '../core.ts';
import { canonicalize, sha256 } from '../core.ts';
import { validateReleaseRecord } from './schemas.ts';
import type { ReleaseApplianceStore } from './store.ts';

export const MAINTENANCE_KINDS = [
  'PACKAGE_UPDATE',
  'SERVICE_RUNTIME_UPDATE',
  'SOFT_REBOOT',
  'FULL_REBOOT',
  'KEXEC',
  'LIVEPATCH',
  'FILESYSTEM',
  'OTHER_APPROVED',
] as const;

export const MAINTENANCE_STATES = [
  'REQUESTED',
  'SIMULATING',
  'SCHEDULED',
  'AWAITING_APPROVAL',
  'VERIFYING_DISPOSABLE',
  'APPLYING',
  'REBOOT_REQUIRED',
  'VERIFYING_HOST',
  'SUCCEEDED',
  'FAILED',
  'RECOVERY_REQUIRED',
  'AMBIGUOUS',
] as const;

export type MaintenanceKind = typeof MAINTENANCE_KINDS[number];
export type MaintenanceState = typeof MAINTENANCE_STATES[number];
export type MaintenanceRiskClass = 'LOW' | 'MEDIUM' | 'HIGH' | 'UNKNOWN';

const TERMINAL_STATES = new Set<MaintenanceState>(['SUCCEEDED', 'FAILED', 'RECOVERY_REQUIRED', 'AMBIGUOUS']);
const MAX_RECORD_SCAN = 10_000;
const HIGH_IMPACT_PACKAGE_PATTERNS = [
  /^linux-(?:image|headers|modules|generic|virtual)/u,
  /^libc6(?:$|:)/u,
  /^systemd(?:$|-)/u,
  /^caddy$/u,
  /^zfs/u,
  /^openssh-(?:server|client)$/u,
  /^(?:nftables|iptables|netplan\.io)$/u,
  /^(?:grub|shim|efibootmgr)/u,
  /^(?:cryptsetup|openssl|libssl)/u,
  /^(?:postgresql|mysql-server|mariadb-server)/u,
];
const KERNEL_PACKAGE_PATTERN = /^(?:linux-(?:image|headers|modules|generic|virtual)|kmod|initramfs-tools)/u;

export class MaintenanceAuthorityError extends Error {
  constructor(readonly code: string, message: string, readonly details: JsonObject = {}) {
    super(message);
    this.name = 'MaintenanceAuthorityError';
  }
}

export interface HostMaintenanceProvider {
  readonly authority: 'host-maintenance-provider';
  describe?(): JsonObject;
  observeInventory(context: RuntimeExecutionContext): Promise<JsonObject> | JsonObject;
  simulatePackages?(input: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  verifyDisposable?(record: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  applyMaintenance?(record: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  observeMaintenance?(record: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  certifyHost?(record: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject>;
  planReboot?(record: JsonObject, mode: 'SOFT' | 'FULL' | 'KEXEC', context: RuntimeExecutionContext): Promise<JsonObject> | JsonObject;
}

export interface MaintenanceAuthorityServiceOptions {
  store: ReleaseApplianceStore;
  provider?: HostMaintenanceProvider;
  now?: () => string;
}

function object(value: unknown, label: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new MaintenanceAuthorityError('release_invalid_request', `${label} must be an object`);
  return value as JsonObject;
}

function strictObject(value: unknown, label: string, allowed: readonly string[], required: readonly string[] = []): JsonObject {
  const result = object(value, label);
  for (const key of Object.keys(result)) if (!allowed.includes(key)) throw new MaintenanceAuthorityError('release_invalid_request', `${label}.${key} is not supported`);
  for (const key of required) if (result[key] === undefined) throw new MaintenanceAuthorityError('release_invalid_request', `${label}.${key} is required`);
  return result;
}

function text(value: unknown, label: string, maxLength = 512): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > maxLength) throw new MaintenanceAuthorityError('release_invalid_request', `${label} must be a bounded non-empty string`);
  return value;
}

function optionalText(value: unknown, label: string, maxLength = 512): string | undefined {
  return value === undefined ? undefined : text(value, label, maxLength);
}

function identifier(value: unknown, label: string): string {
  const result = text(value, label, 128);
  if (!/^[a-z0-9][a-z0-9._:-]{0,127}$/u.test(result)) throw new MaintenanceAuthorityError('release_invalid_request', `${label} is not a valid identifier`);
  return result;
}

function integer(value: unknown, label: string, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) throw new MaintenanceAuthorityError('release_invalid_request', `${label} must be an integer in range`);
  return Number(value);
}

function timestamp(value: unknown, label: string): string {
  const result = text(value, label, 64);
  if (!Number.isFinite(Date.parse(result))) throw new MaintenanceAuthorityError('release_invalid_request', `${label} must be an ISO timestamp`);
  return result;
}

function strings(value: unknown, label: string, maximum = 256): string[] {
  if (!Array.isArray(value) || value.length > maximum) throw new MaintenanceAuthorityError('release_invalid_request', `${label} must be a bounded array`);
  return value.map((entry, index) => text(entry, `${label}[${index}]`, 256));
}

function objectArray(value: unknown, label: string, maximum = 128): JsonObject[] {
  if (!Array.isArray(value) || value.length > maximum) throw new MaintenanceAuthorityError('release_invalid_request', `${label} must be a bounded array`);
  return value.map((entry, index) => object(entry, `${label}[${index}]`));
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function principal(context: RuntimeExecutionContext): string {
  const owner = identifier(context.subject, 'context.subject');
  const authority = context.authorityClass;
  if (authority !== 'unrestricted-owner' && authority !== 'owner' && authority !== 'maintenance-owner') {
    throw new MaintenanceAuthorityError('release_wrong_principal', 'host maintenance authority is required');
  }
  return owner;
}

function idempotency(context: RuntimeExecutionContext): string {
  return identifier(context.idempotencyKey, 'context.idempotencyKey');
}

function safeError(code: string, phase: string, retryable: boolean, details: JsonObject = {}): JsonObject {
  return {
    code,
    message: 'host maintenance operation did not produce positively verified completion',
    retryable,
    phase,
    productionImpact: 'UNKNOWN',
    detailsDigest: sha256(canonicalize(details)),
  };
}

function providerFailure(error: unknown): JsonObject {
  return {
    errorType: error instanceof Error ? error.name : 'UnknownError',
    errorDigest: sha256(error instanceof Error ? error.message : String(error)),
  };
}

function readRootFilesystem(): JsonObject {
  try {
    const mounts = readFileSync('/proc/mounts', 'utf8').split('\n').map((line) => line.trim().split(/\s+/u)).filter((entry) => entry.length >= 3);
    const root = mounts.find((entry) => entry[1] === '/');
    if (root !== undefined) {
      const filesystemType = String(root[2]);
      return {
        observed: true,
        filesystemType,
        hostWideSnapshotAvailable: filesystemType === 'zfs',
        rollbackClassification: filesystemType === 'zfs' ? 'FILESYSTEM_SNAPSHOT_POSSIBLE' : 'PROVIDER_BACKUP_ONLY',
        limitation: filesystemType === 'zfs' ? null : 'root filesystem is not ZFS; host-wide atomic snapshots are unavailable',
      };
    }
  } catch {
    // Unknown is safer than fabricated inventory.
  }
  return { observed: false, filesystemType: 'UNKNOWN', hostWideSnapshotAvailable: false, rollbackClassification: 'UNKNOWN', limitation: 'root filesystem truth is unavailable' };
}

export class ReadOnlyHostMaintenanceProvider implements HostMaintenanceProvider {
  readonly authority = 'host-maintenance-provider' as const;
  describe(): JsonObject { return { authority: this.authority, readOnlyInventory: true, packageMutation: false, rebootExecution: false }; }
  observeInventory(): JsonObject {
    const rebootRequired = existsSync('/var/run/reboot-required');
    const proClientInstalled = existsSync('/usr/bin/pro') || existsSync('/usr/bin/ua');
    return {
      observedAt: new Date().toISOString(),
      rootFilesystem: readRootFilesystem(),
      ubuntuPro: { clientInstalled: proClientInstalled, attachmentState: 'UNKNOWN', entitled: false, observationMethod: 'FILESYSTEM_ONLY' },
      livepatch: { clientInstalled: existsSync('/snap/bin/canonical-livepatch'), subscriptionAttached: false, entitled: false, patchesApplied: 'UNKNOWN', kernelCoverage: 'UNKNOWN' },
      reboot: {
        required: rebootRequired,
        softReboot: { available: existsSync('/usr/bin/systemctl'), userspaceOnly: true, satisfiesKernelUpdate: false },
        fullReboot: { automatic: false, outageExpected: true, secondServingNode: false },
      },
      unattendedUpgrades: { configurationObserved: false, automaticReboot: false, highImpactPackagesGoverned: true },
      providerBackup: { configured: false, capability: 'UNKNOWN' },
      zfs: { applicableDatasetsOnly: true, hostRootProtected: false },
    };
  }
}

function normalizeInventory(value: unknown): JsonObject {
  const input = object(value, 'maintenance inventory');
  const rootValue = input.rootFilesystem === undefined ? {} : object(input.rootFilesystem, 'rootFilesystem');
  const filesystemType = typeof rootValue.filesystemType === 'string' ? rootValue.filesystemType : 'UNKNOWN';
  const rootFilesystem: JsonObject = {
    observed: rootValue.observed === true,
    filesystemType,
    hostWideSnapshotAvailable: filesystemType === 'zfs' && rootValue.hostWideSnapshotAvailable === true,
    rollbackClassification: filesystemType === 'zfs' && rootValue.hostWideSnapshotAvailable === true ? 'FILESYSTEM_SNAPSHOT_POSSIBLE' : (rootValue.rollbackClassification ?? 'PROVIDER_BACKUP_ONLY'),
    limitation: filesystemType === 'zfs' ? (rootValue.limitation ?? null) : 'root filesystem is not ZFS; host-wide atomic snapshots are unavailable',
  };
  const ubuntuValue = input.ubuntuPro === undefined ? {} : object(input.ubuntuPro, 'ubuntuPro');
  const attachmentState = ['ATTACHED', 'UNATTACHED', 'UNKNOWN'].includes(String(ubuntuValue.attachmentState)) ? String(ubuntuValue.attachmentState) : 'UNKNOWN';
  const livepatchValue = input.livepatch === undefined ? {} : object(input.livepatch, 'livepatch');
  const rebootValue = input.reboot === undefined ? {} : object(input.reboot, 'reboot');
  const softValue = rebootValue.softReboot === undefined ? {} : object(rebootValue.softReboot, 'reboot.softReboot');
  const fullValue = rebootValue.fullReboot === undefined ? {} : object(rebootValue.fullReboot, 'reboot.fullReboot');
  return {
    observedAt: typeof input.observedAt === 'string' && Number.isFinite(Date.parse(input.observedAt)) ? input.observedAt : null,
    rootFilesystem,
    ubuntuPro: {
      clientInstalled: ubuntuValue.clientInstalled === true,
      attachmentState,
      entitled: attachmentState === 'ATTACHED' && ubuntuValue.entitled === true,
      observationMethod: typeof ubuntuValue.observationMethod === 'string' ? ubuntuValue.observationMethod : 'UNKNOWN',
    },
    livepatch: {
      clientInstalled: livepatchValue.clientInstalled === true,
      subscriptionAttached: attachmentState === 'ATTACHED' && livepatchValue.subscriptionAttached === true,
      entitled: attachmentState === 'ATTACHED' && livepatchValue.entitled === true,
      patchesApplied: livepatchValue.patchesApplied ?? 'UNKNOWN',
      kernelCoverage: livepatchValue.kernelCoverage ?? 'UNKNOWN',
    },
    reboot: {
      required: rebootValue.required === true,
      softReboot: { available: softValue.available === true, userspaceOnly: true, satisfiesKernelUpdate: false },
      fullReboot: { automatic: false, outageExpected: true, secondServingNode: false, ...fullValue, automatic: false, outageExpected: true, secondServingNode: false },
    },
    unattendedUpgrades: input.unattendedUpgrades === undefined ? { configurationObserved: false, automaticReboot: false, highImpactPackagesGoverned: true } : { ...object(input.unattendedUpgrades, 'unattendedUpgrades'), automaticReboot: false, highImpactPackagesGoverned: true },
    providerBackup: input.providerBackup === undefined ? { configured: false, capability: 'UNKNOWN' } : object(input.providerBackup, 'providerBackup'),
    zfs: input.zfs === undefined ? { applicableDatasetsOnly: true, hostRootProtected: false } : { ...object(input.zfs, 'zfs'), applicableDatasetsOnly: true, hostRootProtected: filesystemType === 'zfs' },
  };
}

function normalizeKind(value: unknown): MaintenanceKind {
  const result = text(value, 'maintenanceKind', 64) as MaintenanceKind;
  if (!MAINTENANCE_KINDS.includes(result)) throw new MaintenanceAuthorityError('release_invalid_request', 'maintenanceKind is unsupported');
  return result;
}

function packageName(entry: JsonObject): string {
  return text(entry.name, 'package.name', 256).toLowerCase();
}

function normalizeSimulation(value: unknown, requestedPackages: string[]): JsonObject {
  const input = object(value, 'package simulation');
  const packagesValue = input.packages ?? input.candidatePackages ?? [];
  const packages = objectArray(packagesValue, 'simulation.packages', 512).map((entry) => ({
    name: packageName(entry),
    currentVersion: entry.currentVersion === undefined ? null : text(entry.currentVersion, 'package.currentVersion', 256),
    candidateVersion: entry.candidateVersion === undefined ? null : text(entry.candidateVersion, 'package.candidateVersion', 256),
    origin: entry.origin === undefined ? null : text(entry.origin, 'package.origin', 256),
    serviceRestartRequired: entry.serviceRestartRequired === true,
    kernelAffecting: entry.kernelAffecting === true,
    highImpact: entry.highImpact === true,
  }));
  const seen = new Set(packages.map((entry) => entry.name));
  for (const name of requestedPackages) if (!seen.has(name.toLowerCase())) packages.push({ name:name.toLowerCase(), currentVersion:null, candidateVersion:null, origin:null, serviceRestartRequired:false, kernelAffecting:false, highImpact:false });
  const affectedServices = input.affectedServices === undefined ? [] : strings(input.affectedServices, 'simulation.affectedServices', 256);
  const diskBytesRequired = input.diskBytesRequired === undefined ? 0 : integer(input.diskBytesRequired, 'simulation.diskBytesRequired');
  const memoryBytesRequired = input.memoryBytesRequired === undefined ? 0 : integer(input.memoryBytesRequired, 'simulation.memoryBytesRequired');
  return {
    classification: 'SIMULATED',
    packages,
    affectedServices,
    diskBytesRequired,
    memoryBytesRequired,
    providerRebootRequired: input.rebootRequired === true,
    repositoryDigest: input.repositoryDigest === undefined ? null : text(input.repositoryDigest, 'simulation.repositoryDigest', 128),
  };
}

function classifySimulation(simulation: JsonObject, kind: MaintenanceKind): { riskClass: MaintenanceRiskClass; approvalRequired: boolean; disposableVerificationRequired: boolean; kernelAffected: boolean; rebootRequired: boolean; reasons: string[] } {
  const packages = objectArray(simulation.packages, 'simulation.packages', 512);
  const names = packages.map(packageName);
  const kernelAffected = kind === 'KEXEC' || names.some((name) => KERNEL_PACKAGE_PATTERN.test(name)) || packages.some((entry) => entry.kernelAffecting === true);
  const highImpact = kernelAffected || kind === 'FULL_REBOOT' || kind === 'FILESYSTEM' || kind === 'KEXEC' || names.some((name) => HIGH_IMPACT_PACKAGE_PATTERNS.some((pattern) => pattern.test(name))) || packages.some((entry) => entry.highImpact === true);
  const restartRequired = packages.some((entry) => entry.serviceRestartRequired === true) || (Array.isArray(simulation.affectedServices) && simulation.affectedServices.length > 0);
  const reasons: string[] = [];
  if (kernelAffected) reasons.push('KERNEL_OR_BOOT_COMPONENT');
  if (highImpact) reasons.push('HIGH_IMPACT_COMPONENT');
  if (restartRequired) reasons.push('SERVICE_RESTART_REQUIRED');
  if (kind === 'LIVEPATCH') reasons.push('LIVEPATCH_ENTITLEMENT_AND_COVERAGE_REQUIRED');
  const riskClass: MaintenanceRiskClass = highImpact ? 'HIGH' : restartRequired || kind === 'SERVICE_RUNTIME_UPDATE' || kind === 'LIVEPATCH' || kind === 'SOFT_REBOOT' ? 'MEDIUM' : 'LOW';
  return {
    riskClass,
    approvalRequired: riskClass === 'HIGH',
    disposableVerificationRequired: riskClass !== 'LOW' || packages.length > 0,
    kernelAffected,
    rebootRequired: kernelAffected || simulation.providerRebootRequired === true || kind === 'FULL_REBOOT' || kind === 'KEXEC',
    reasons,
  };
}

function normalizeApproval(value: unknown): JsonObject[] {
  if (value === undefined) return [];
  return objectArray(value, 'approvalEvidence', 32).map((entry, index) => {
    const evidence = strictObject(entry, `approvalEvidence[${index}]`, ['approverPrincipal','approvalDigest','approvedAt','expiresAt','reason'], ['approverPrincipal','approvalDigest','approvedAt']);
    const result: JsonObject = {
      approverPrincipal: identifier(evidence.approverPrincipal, 'approverPrincipal'),
      approvalDigest: text(evidence.approvalDigest, 'approvalDigest', 128),
      approvedAt: timestamp(evidence.approvedAt, 'approvedAt'),
    };
    if (evidence.expiresAt !== undefined) result.expiresAt = timestamp(evidence.expiresAt, 'expiresAt');
    if (evidence.reason !== undefined) result.reason = text(evidence.reason, 'reason', 1024);
    return result;
  });
}

function approvalValid(evidence: JsonObject[], now: string): boolean {
  return evidence.some((entry) => entry.expiresAt === undefined || Date.parse(String(entry.expiresAt)) > Date.parse(now));
}

function resultClassification(result: JsonObject): string {
  return typeof result.classification === 'string' ? result.classification : 'UNKNOWN';
}

export class MaintenanceAuthorityService {
  readonly authority = 'host-maintenance-authority' as const;
  private readonly now: () => string;
  private readonly inventoryProvider: HostMaintenanceProvider;
  constructor(private readonly options: MaintenanceAuthorityServiceOptions) {
    this.now = options.now ?? (() => new Date().toISOString());
    this.inventoryProvider = options.provider ?? new ReadOnlyHostMaintenanceProvider();
  }

  private async inventory(context: RuntimeExecutionContext): Promise<JsonObject> {
    try { return normalizeInventory(await this.inventoryProvider.observeInventory(context)); }
    catch (error) {
      return normalizeInventory({
        observedAt: this.now(),
        rootFilesystem: { observed:false, filesystemType:'UNKNOWN' },
        ubuntuPro: { clientInstalled:false, attachmentState:'UNKNOWN' },
        livepatch: {},
        reboot: {},
        providerFailure: providerFailure(error),
      });
    }
  }

  async describe(_payload: JsonObject = {}, context: RuntimeExecutionContext = {}): Promise<JsonObject> {
    const inventory = await this.inventory(context);
    return {
      operation: 'babyx.maintenance.describe',
      authority: this.authority,
      failureDomain: 'HOST_MAINTENANCE',
      separateFromDeploymentState: true,
      provider: this.options.provider === undefined ? { configured:false, ...this.inventoryProvider.describe?.() } : { configured:true, authority:this.options.provider.authority, ...this.options.provider.describe?.() },
      capabilities: {
        inventory: true,
        packageSimulation: this.options.provider?.simulatePackages !== undefined,
        disposableVerification: this.options.provider?.verifyDisposable !== undefined,
        packageApplication: this.options.provider?.applyMaintenance !== undefined,
        postUpdateCertification: this.options.provider?.certifyHost !== undefined,
        automaticFullReboot: false,
        rebootExecution: false,
      },
      inventory,
    };
  }

  private record(maintenanceId: string): JsonObject {
    return this.options.store.getRecord('MaintenanceRecordV1', maintenanceId);
  }

  private assertOwner(record: JsonObject, context: RuntimeExecutionContext): string {
    const owner = principal(context);
    if (record.ownerPrincipal !== owner) throw new MaintenanceAuthorityError('release_wrong_principal', 'maintenance record belongs to a different owner');
    return owner;
  }

  private transition(recordValue: JsonObject, nextState: MaintenanceState, context: RuntimeExecutionContext, phase: string, patch: JsonObject = {}): JsonObject {
    const record = clone(recordValue);
    const owner = this.assertOwner(record, context);
    const sequence = integer(record.sequence, 'record.sequence');
    const now = this.now();
    const candidateValue: JsonObject = {
      ...record,
      ...patch,
      state: nextState,
      sequence: sequence + 1,
      updatedAt: now,
      ...(TERMINAL_STATES.has(nextState) ? { completedAt: now } : {}),
    };
    if (candidateValue.error === null || candidateValue.error === undefined) delete candidateValue.error;
    const candidate = validateReleaseRecord('MaintenanceRecordV1', candidateValue);
    return this.options.store.applyMutation({
      schemaId: 'MaintenanceRecordV1',
      recordId: String(record.maintenanceId),
      ownerPrincipal: owner,
      expectedSequence: sequence,
      idempotencyKey: `${idempotency(context)}:${phase}:${sequence + 1}`,
      requestDigest: sha256(canonicalize(candidate)),
      operation: `babyx.maintenance.${phase}`,
      phase,
      record: candidate,
      occurredAt: now,
      childJobIds: Array.isArray(candidate.allJobIds) ? candidate.allJobIds.map(String) : [],
      observationDigest: patch.observationDigest === undefined ? undefined : String(patch.observationDigest),
    });
  }

  async plan(payloadValue: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const payload = strictObject(payloadValue, 'maintenance plan', ['maintenanceKind','targetPackages','scheduledFor','reason','automaticAllowed','metadata'], ['maintenanceKind']);
    const owner = principal(context);
    const key = idempotency(context);
    const kind = normalizeKind(payload.maintenanceKind);
    const targetPackages = payload.targetPackages === undefined ? [] : strings(payload.targetPackages, 'targetPackages', 256).map((entry) => entry.toLowerCase());
    const scheduledFor = payload.scheduledFor === undefined ? undefined : timestamp(payload.scheduledFor, 'scheduledFor');
    const request = {
      maintenanceKind: kind,
      targetPackages: [...new Set(targetPackages)].sort(),
      scheduledFor: scheduledFor ?? null,
      reason: optionalText(payload.reason, 'reason', 1024) ?? null,
      automaticAllowed: payload.automaticAllowed === true,
      metadata: payload.metadata === undefined ? {} : object(payload.metadata, 'metadata'),
    };
    const creationRequestDigest = sha256(canonicalize(request));
    const maintenanceId = `maintenance-${sha256(canonicalize({ owner, key })).slice(0, 40)}`;
    if (this.options.store.hasRecord('MaintenanceRecordV1', maintenanceId)) {
      const existing = this.record(maintenanceId);
      if (existing.creationRequestDigest !== creationRequestDigest) throw new MaintenanceAuthorityError('release_idempotency_conflict', 'maintenance idempotency key was reused with a different request');
      return { operation:'babyx.maintenance.plan', replayed:true, maintenance:existing };
    }
    const now = this.now();
    const inventory = await this.inventory(context);
    const initial = validateReleaseRecord('MaintenanceRecordV1', {
      schemaVersion: '1.0.0',
      maintenanceId,
      ownerPrincipal: owner,
      idempotencyKey: key,
      creationRequestDigest,
      failureDomain: 'HOST_MAINTENANCE',
      maintenanceKind: kind,
      targetPackages: request.targetPackages,
      requestedReason: request.reason,
      metadata: request.metadata,
      packagePlan: null,
      approvalEvidence: [],
      approvalRequired: kind === 'FULL_REBOOT' || kind === 'KEXEC' || kind === 'FILESYSTEM',
      riskClass: kind === 'FULL_REBOOT' || kind === 'KEXEC' || kind === 'FILESYSTEM' ? 'HIGH' : 'UNKNOWN',
      disposableVerificationRequired: false,
      disposableVerification: null,
      state: 'REQUESTED',
      sequence: 1,
      activeJobIds: [],
      allJobIds: [],
      rebootRequired: kind === 'FULL_REBOOT' || kind === 'KEXEC',
      kernelAffected: kind === 'KEXEC',
      livepatchState: object(inventory.livepatch, 'inventory.livepatch'),
      preSnapshot: inventory,
      providerBackupCapability: inventory.providerBackup,
      zfsSnapshotReferences: [],
      activeServices: [],
      rollbackReleases: [],
      drainPlan: null,
      rollbackPlan: { classification:'RECOVERY_PLAN_REQUIRED', providerBackupOnly:object(inventory.rootFilesystem, 'rootFilesystem').hostWideSnapshotAvailable !== true },
      rebootPlan: null,
      postSnapshot: null,
      postUpdateCertification: null,
      evidenceIndexId: null,
      scheduledFor: scheduledFor ?? null,
      automaticAllowed: request.automaticAllowed,
      createdAt: now,
      updatedAt: now,
      completedAt: null,
    });
    let record = this.options.store.applyMutation({
      schemaId:'MaintenanceRecordV1', recordId:maintenanceId, ownerPrincipal:owner, expectedSequence:0,
      idempotencyKey:`${key}:requested:1`, requestDigest:creationRequestDigest, operation:'babyx.maintenance.plan', phase:'requested', record:initial, occurredAt:now,
    });

    if (scheduledFor !== undefined && Date.parse(scheduledFor) > Date.parse(now)) {
      record = this.transition(record, 'SCHEDULED', context, 'plan-scheduled', { scheduledFor });
      return { operation:'babyx.maintenance.plan', replayed:false, maintenance:record };
    }

    if (kind === 'SOFT_REBOOT' || kind === 'FULL_REBOOT' || kind === 'KEXEC') {
      const mode = kind === 'SOFT_REBOOT' ? 'SOFT' : kind === 'KEXEC' ? 'KEXEC' : 'FULL';
      const rebootPlan = await this.buildRebootPlan(record, mode, context);
      record = this.transition(record, 'AWAITING_APPROVAL', context, 'plan-reboot', {
        riskClass: kind === 'SOFT_REBOOT' ? 'MEDIUM' : 'HIGH',
        approvalRequired: true,
        rebootRequired: kind !== 'SOFT_REBOOT',
        rebootPlan,
      });
      return { operation:'babyx.maintenance.plan', replayed:false, maintenance:record };
    }

    if (this.options.provider?.simulatePackages === undefined) {
      record = this.transition(record, 'RECOVERY_REQUIRED', context, 'plan-provider-unavailable', {
        error:safeError('release_maintenance_provider_unavailable','simulation',true,{ providerConfigured:false }),
      });
      return { operation:'babyx.maintenance.plan', replayed:false, maintenance:record };
    }

    record = this.transition(record, 'SIMULATING', context, 'plan-simulating');
    try {
      const simulation = normalizeSimulation(await this.options.provider.simulatePackages({ ...request, inventory }, context), request.targetPackages);
      const classification = classifySimulation(simulation, kind);
      const packagePlan = {
        ...simulation,
        simulationDigest: sha256(canonicalize(simulation)),
        riskClass: classification.riskClass,
        approvalRequired: classification.approvalRequired,
        disposableVerificationRequired: classification.disposableVerificationRequired,
        kernelAffected: classification.kernelAffected,
        rebootRequired: classification.rebootRequired,
        classificationReasons: classification.reasons,
      };
      const nextState: MaintenanceState = classification.approvalRequired ? 'AWAITING_APPROVAL' : classification.disposableVerificationRequired ? 'VERIFYING_DISPOSABLE' : 'REQUESTED';
      record = this.transition(record, nextState, context, 'plan-simulated', {
        packagePlan,
        riskClass: classification.riskClass,
        approvalRequired: classification.approvalRequired,
        disposableVerificationRequired: classification.disposableVerificationRequired,
        rebootRequired: classification.rebootRequired,
        kernelAffected: classification.kernelAffected,
        error:null,
      });
    } catch (error) {
      record = this.transition(record, 'FAILED', context, 'plan-simulation-failed', {
        error:safeError('release_maintenance_simulation_failed','simulation',false,providerFailure(error)),
      });
    }
    return { operation:'babyx.maintenance.plan', replayed:false, maintenance:record };
  }

  private async buildRebootPlan(record: JsonObject, mode: 'SOFT' | 'FULL' | 'KEXEC', context: RuntimeExecutionContext): Promise<JsonObject> {
    const base: JsonObject = mode === 'SOFT'
      ? { mode, userspaceOnly:true, satisfiesKernelUpdate:false, automatic:false, outageExpected:true, executionAuthorized:false }
      : { mode, userspaceOnly:false, satisfiesKernelUpdate:true, automatic:false, outageExpected:true, secondServingNode:false, executionAuthorized:false };
    if (this.options.provider?.planReboot === undefined) return base;
    try { return { ...base, ...object(await this.options.provider.planReboot(record, mode, context), 'reboot plan'), mode, automatic:false, executionAuthorized:false, ...(mode === 'SOFT' ? { userspaceOnly:true, satisfiesKernelUpdate:false } : {}) }; }
    catch (error) { return { ...base, providerPlan:'UNKNOWN', providerFailure:providerFailure(error) }; }
  }

  private async verifyDisposable(recordValue: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    let record = recordValue;
    if (record.disposableVerificationRequired !== true) return record;
    if (this.options.provider?.verifyDisposable === undefined) {
      return this.transition(record, 'RECOVERY_REQUIRED', context, 'verify-disposable-unavailable', {
        disposableVerification:{ classification:'UNAVAILABLE', verified:false },
        error:safeError('release_maintenance_verification_failed','disposable-verification',true,{ providerConfigured:false }),
      });
    }
    try {
      const result = object(await this.options.provider.verifyDisposable(record, context), 'disposable verification');
      const classification = resultClassification(result);
      const jobIds = result.jobIds === undefined ? [] : strings(result.jobIds, 'disposableVerification.jobIds', 128);
      const patch = { disposableVerification:{ ...result, classification, verificationDigest:sha256(canonicalize(result)) }, activeJobIds:[], allJobIds:[...new Set([...(record.allJobIds as string[]),...jobIds])] };
      if (classification === 'PASSED') return this.transition(record, 'APPLYING', context, 'verify-disposable-passed', patch);
      if (classification === 'FAILED') return this.transition(record, 'FAILED', context, 'verify-disposable-failed', { ...patch, error:safeError('release_maintenance_verification_failed','disposable-verification',false,{ classification }) });
      return this.transition(record, 'RECOVERY_REQUIRED', context, 'verify-disposable-unknown', { ...patch, error:safeError('release_maintenance_recovery_required','disposable-verification',true,{ classification }) });
    } catch (error) {
      return this.transition(record, 'RECOVERY_REQUIRED', context, 'verify-disposable-error', {
        disposableVerification:{ classification:'UNKNOWN', verified:false },
        error:safeError('release_maintenance_recovery_required','disposable-verification',true,providerFailure(error)),
      });
    }
  }

  private async certify(recordValue: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    let record = recordValue;
    if (this.options.provider?.certifyHost === undefined) {
      return this.transition(record, 'RECOVERY_REQUIRED', context, 'certify-unavailable', {
        postUpdateCertification:{ classification:'UNAVAILABLE', certified:false },
        error:safeError('release_maintenance_certification_failed','post-update-certification',true,{ providerConfigured:false }),
      });
    }
    try {
      const result = object(await this.options.provider.certifyHost(record, context), 'post-update certification');
      const classification = resultClassification(result);
      const certification = { ...result, classification, certificationDigest:sha256(canonicalize(result)) };
      if (classification === 'PASSED') {
        const postSnapshot = await this.inventory(context);
        return this.transition(record, 'SUCCEEDED', context, 'certify-passed', { postUpdateCertification:certification, postSnapshot, rebootRequired:false, activeJobIds:[], error:null });
      }
      if (classification === 'FAILED') return this.transition(record, 'FAILED', context, 'certify-failed', { postUpdateCertification:certification, error:safeError('release_maintenance_certification_failed','post-update-certification',false,{ classification }) });
      return this.transition(record, 'RECOVERY_REQUIRED', context, 'certify-unknown', { postUpdateCertification:certification, error:safeError('release_maintenance_recovery_required','post-update-certification',true,{ classification }) });
    } catch (error) {
      return this.transition(record, 'RECOVERY_REQUIRED', context, 'certify-error', { error:safeError('release_maintenance_recovery_required','post-update-certification',true,providerFailure(error)) });
    }
  }

  async apply(payloadValue: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const payload = strictObject(payloadValue, 'maintenance apply', ['maintenanceId','expectedSequence','approvalEvidence'], ['maintenanceId','expectedSequence']);
    let record = this.record(identifier(payload.maintenanceId, 'maintenanceId'));
    this.assertOwner(record, context);
    if (integer(payload.expectedSequence, 'expectedSequence') !== record.sequence) throw new MaintenanceAuthorityError('release_stale_sequence', 'maintenance sequence is stale');
    if (['SOFT_REBOOT','FULL_REBOOT','KEXEC'].includes(String(record.maintenanceKind))) throw new MaintenanceAuthorityError('release_maintenance_reboot_forbidden', 'reboot execution is not performed by maintenance apply; use reboot planning');
    if (TERMINAL_STATES.has(String(record.state) as MaintenanceState) || record.state === 'REBOOT_REQUIRED') return { operation:'babyx.maintenance.apply', maintenance:record, replayed:true };
    if (record.state === 'SCHEDULED') {
      if (record.scheduledFor !== null && Date.parse(String(record.scheduledFor)) > Date.parse(this.now())) return { operation:'babyx.maintenance.apply', maintenance:record, deferred:true };
      record = this.transition(record, record.approvalRequired === true ? 'AWAITING_APPROVAL' : record.disposableVerificationRequired === true ? 'VERIFYING_DISPOSABLE' : 'REQUESTED', context, 'apply-schedule-due');
    }
    if (record.state === 'REQUESTED') {
      record = this.transition(record, record.disposableVerificationRequired === true ? 'VERIFYING_DISPOSABLE' : 'APPLYING', context, 'apply-started');
    }
    const suppliedApproval = normalizeApproval(payload.approvalEvidence);
    const approvals = [...objectArray(record.approvalEvidence, 'record.approvalEvidence', 64), ...suppliedApproval];
    if (record.approvalRequired === true && !approvalValid(approvals, this.now())) throw new MaintenanceAuthorityError('release_maintenance_approval_required', 'valid owner approval is required');
    if (suppliedApproval.length > 0 || record.state === 'AWAITING_APPROVAL') {
      record = this.transition(record, record.disposableVerificationRequired === true ? 'VERIFYING_DISPOSABLE' : 'APPLYING', context, 'apply-approved', { approvalEvidence:approvals });
    }
    if (record.state === 'VERIFYING_DISPOSABLE') record = await this.verifyDisposable(record, context);
    if (record.state !== 'APPLYING') return { operation:'babyx.maintenance.apply', maintenance:record };
    if (this.options.provider?.applyMaintenance === undefined) {
      record = this.transition(record, 'RECOVERY_REQUIRED', context, 'apply-provider-unavailable', { error:safeError('release_maintenance_provider_unavailable','apply',true,{ providerConfigured:false }) });
      return { operation:'babyx.maintenance.apply', maintenance:record };
    }
    try {
      const result = object(await this.options.provider.applyMaintenance(record, context), 'maintenance application');
      const classification = resultClassification(result);
      const jobIds = result.jobIds === undefined ? [] : strings(result.jobIds, 'application.jobIds', 128);
      const allJobIds = [...new Set([...(record.allJobIds as string[]), ...jobIds])];
      if (classification === 'NOT_APPLIED' || classification === 'FAILED') {
        record = this.transition(record, 'FAILED', context, 'apply-not-applied', { activeJobIds:[], allJobIds, applicationResult:result, error:safeError('release_maintenance_apply_failed','apply',false,{ classification }) });
      } else if (classification !== 'APPLIED') {
        record = this.transition(record, 'RECOVERY_REQUIRED', context, 'apply-unknown', { activeJobIds:[], allJobIds, applicationResult:result, error:safeError('release_maintenance_recovery_required','apply',true,{ classification }) });
      } else {
        const rebootRequired = record.rebootRequired === true || result.rebootRequired === true;
        record = this.transition(record, rebootRequired ? 'REBOOT_REQUIRED' : 'VERIFYING_HOST', context, 'apply-observed', {
          activeJobIds:[], allJobIds, applicationResult:{ ...result, applicationDigest:sha256(canonicalize(result)) }, rebootRequired, error:null,
        });
        if (record.state === 'VERIFYING_HOST') record = await this.certify(record, context);
      }
    } catch (error) {
      record = this.transition(record, 'RECOVERY_REQUIRED', context, 'apply-response-unknown', { error:safeError('release_maintenance_recovery_required','apply',true,providerFailure(error)) });
    }
    return { operation:'babyx.maintenance.apply', maintenance:record };
  }

  status(payloadValue: JsonObject, context: RuntimeExecutionContext): JsonObject {
    const payload = strictObject(payloadValue, 'maintenance status', ['maintenanceId','state','limit']);
    const owner = principal(context);
    if (payload.maintenanceId !== undefined) {
      const record = this.record(identifier(payload.maintenanceId, 'maintenanceId'));
      this.assertOwner(record, context);
      return { operation:'babyx.maintenance.status', maintenance:record };
    }
    const limit = payload.limit === undefined ? 50 : integer(payload.limit, 'limit', 1, 200);
    const state = payload.state === undefined ? undefined : text(payload.state, 'state', 64);
    const records = this.options.store.listRecordIdentities(MAX_RECORD_SCAN)
      .filter((entry) => entry.schemaId === 'MaintenanceRecordV1')
      .map((entry) => this.options.store.getRecord(entry.schemaId, entry.recordId))
      .filter((record) => record.ownerPrincipal === owner && (state === undefined || record.state === state))
      .sort((left, right) => String(right.updatedAt).localeCompare(String(left.updatedAt)))
      .slice(0, limit);
    return { operation:'babyx.maintenance.status', maintenance:records, count:records.length, limit };
  }

  private async reconcileOne(recordValue: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    let record = recordValue;
    if (TERMINAL_STATES.has(String(record.state) as MaintenanceState) || record.state === 'REBOOT_REQUIRED' || record.state === 'AWAITING_APPROVAL') return record;
    if (record.state === 'SCHEDULED') {
      if (record.scheduledFor !== null && Date.parse(String(record.scheduledFor)) > Date.parse(this.now())) return record;
      return this.transition(record, record.approvalRequired === true ? 'AWAITING_APPROVAL' : record.disposableVerificationRequired === true ? 'VERIFYING_DISPOSABLE' : 'REQUESTED', context, 'reconcile-schedule-due');
    }
    if (record.state === 'VERIFYING_HOST') return this.certify(record, context);
    if (record.state === 'VERIFYING_DISPOSABLE') return this.verifyDisposable(record, context);
    if (record.state === 'APPLYING') {
      if (this.options.provider?.observeMaintenance === undefined) return this.transition(record, 'RECOVERY_REQUIRED', context, 'reconcile-apply-unobservable', { error:safeError('release_maintenance_recovery_required','apply-readback',true,{ providerConfigured:false }) });
      try {
        const observation = object(await this.options.provider.observeMaintenance(record, context), 'maintenance observation');
        const classification = resultClassification(observation);
        if (classification === 'APPLIED') {
          record = this.transition(record, observation.rebootRequired === true || record.rebootRequired === true ? 'REBOOT_REQUIRED' : 'VERIFYING_HOST', context, 'reconcile-apply-observed', { applicationResult:observation, rebootRequired:observation.rebootRequired === true || record.rebootRequired === true, error:null });
          return record.state === 'VERIFYING_HOST' ? this.certify(record, context) : record;
        }
        if (classification === 'NOT_APPLIED') return this.transition(record, 'FAILED', context, 'reconcile-not-applied', { applicationResult:observation, error:safeError('release_maintenance_apply_failed','apply-readback',false,{ classification }) });
        return this.transition(record, 'RECOVERY_REQUIRED', context, 'reconcile-apply-unknown', { applicationResult:observation, error:safeError('release_maintenance_recovery_required','apply-readback',true,{ classification }) });
      } catch (error) {
        return this.transition(record, 'RECOVERY_REQUIRED', context, 'reconcile-apply-error', { error:safeError('release_maintenance_recovery_required','apply-readback',true,providerFailure(error)) });
      }
    }
    return record;
  }

  async reconcile(payloadValue: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const payload = strictObject(payloadValue, 'maintenance reconcile', ['maintenanceId','limit']);
    const owner = principal(context);
    const records = payload.maintenanceId !== undefined
      ? [this.record(identifier(payload.maintenanceId, 'maintenanceId'))]
      : this.options.store.listRecordIdentities(MAX_RECORD_SCAN).filter((entry) => entry.schemaId === 'MaintenanceRecordV1').map((entry) => this.options.store.getRecord(entry.schemaId, entry.recordId)).filter((record) => record.ownerPrincipal === owner).slice(0, payload.limit === undefined ? 50 : integer(payload.limit, 'limit', 1, 100));
    const reconciled: JsonObject[] = [];
    for (const record of records) { this.assertOwner(record, context); reconciled.push(await this.reconcileOne(record, context)); }
    return { operation:'babyx.maintenance.reconcile', reconciled, count:reconciled.length };
  }

  async reboot(payloadValue: JsonObject, context: RuntimeExecutionContext): Promise<JsonObject> {
    const payload = strictObject(payloadValue, 'maintenance reboot', ['maintenanceId','expectedSequence','mode','approvalEvidence','scheduledFor','reason'], ['mode']);
    const modeValue = text(payload.mode, 'mode', 16);
    if (!['SOFT','FULL','KEXEC'].includes(modeValue)) throw new MaintenanceAuthorityError('release_invalid_request', 'reboot mode is unsupported');
    const mode = modeValue as 'SOFT' | 'FULL' | 'KEXEC';
    if (payload.maintenanceId === undefined) {
      const planned = await this.plan({ maintenanceKind:mode === 'SOFT' ? 'SOFT_REBOOT' : mode === 'KEXEC' ? 'KEXEC' : 'FULL_REBOOT', scheduledFor:payload.scheduledFor, reason:payload.reason }, context);
      return { operation:'babyx.maintenance.reboot', maintenance:planned.maintenance, executionPerformed:false };
    }
    let record = this.record(identifier(payload.maintenanceId, 'maintenanceId'));
    this.assertOwner(record, context);
    if (payload.expectedSequence === undefined || integer(payload.expectedSequence, 'expectedSequence') !== record.sequence) throw new MaintenanceAuthorityError('release_stale_sequence', 'maintenance sequence is stale');
    if (mode === 'SOFT' && record.kernelAffected === true) throw new MaintenanceAuthorityError('release_maintenance_reboot_forbidden', 'soft reboot cannot satisfy a kernel update');
    const approvals = [...objectArray(record.approvalEvidence, 'record.approvalEvidence', 64), ...normalizeApproval(payload.approvalEvidence)];
    if (!approvalValid(approvals, this.now())) throw new MaintenanceAuthorityError('release_maintenance_approval_required', 'reboot planning requires valid owner approval');
    const rebootPlan = await this.buildRebootPlan(record, mode, context);
    record = this.transition(record, 'REBOOT_REQUIRED', context, 'reboot-planned', {
      approvalEvidence:approvals,
      rebootRequired: mode !== 'SOFT' || record.rebootRequired === true,
      rebootPlan,
      error:null,
    });
    return { operation:'babyx.maintenance.reboot', maintenance:record, executionPerformed:false };
  }
}
