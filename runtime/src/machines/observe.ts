import { existsSync, lstatSync, realpathSync } from 'node:fs';
import type { CommandResult, Executor } from '../core.ts';
import { canonicalMachineRequestDigest, type DisposableMachineRecordV1, type MachineObservationSetV1, type MachineObservedState } from './schemas.ts';
import { MachineServiceError } from './errors.ts';

export interface SourceSnapshotObservation {
  status: 'present' | 'absent' | 'unknown';
  snapshot: string;
  dataset: string;
  guid?: string;
  creationTxg?: string;
  observedAt: string;
  command: CommandResult;
}

export interface CloneDatasetObservation {
  status: 'present' | 'absent' | 'unknown';
  dataset: string;
  guid?: string;
  origin?: string;
  mountpoint?: string;
  properties: Record<string, string>;
  observedAt: string;
  command: CommandResult;
}

export interface MachineRuntimeObservation {
  status: 'running' | 'stopped' | 'absent' | 'unknown';
  properties: Record<string, string>;
  observedAt: string;
  command: CommandResult;
}

export interface MachineListObservation {
  status: 'available' | 'unknown';
  machineNames: string[];
  observedAt: string;
  command: CommandResult;
}

export interface MachineStatusObservation {
  observations: MachineObservationSetV1;
  observedState: MachineObservedState;
  discrepancies: string[];
  source: SourceSnapshotObservation;
  clone: CloneDatasetObservation;
  machine: MachineRuntimeObservation;
}

const OWNERSHIP_PROPERTIES = [
  'com.stealtheye.babyx:machine-id',
  'com.stealtheye.babyx:provider',
  'com.stealtheye.babyx:request-digest',
  'com.stealtheye.babyx:owner-principal',
] as const;

function output(result: CommandResult): string {
  try { return Buffer.from(result.stdout, 'base64').toString('utf8'); }
  catch { return ''; }
}

function errorOutput(result: CommandResult): string {
  try { return Buffer.from(result.stderr, 'base64').toString('utf8'); }
  catch { return ''; }
}

function parsePropertyOutput(result: CommandResult): Record<string, string> {
  const properties: Record<string, string> = {};
  for (const line of output(result).split('\n')) {
    if (!line) continue;
    const tab = line.indexOf('\t');
    if (tab <= 0) continue;
    properties[line.slice(0, tab)] = line.slice(tab + 1);
  }
  return properties;
}

function parseMachineOutput(result: CommandResult): Record<string, string> {
  const properties: Record<string, string> = {};
  for (const line of output(result).split('\n')) {
    const index = line.indexOf('=');
    if (index > 0) properties[line.slice(0, index)] = line.slice(index + 1);
  }
  return properties;
}

function zfsObjectIsAbsent(result: CommandResult): boolean {
  if (result.exitCode === 0) return false;
  return /(?:dataset does not exist|no such dataset|cannot open .+?: dataset does not exist)/iu.test(errorOutput(result));
}

function machineIsAbsent(result: CommandResult): boolean {
  if (result.exitCode === 0) return false;
  return /(?:no machine|no such machine|machine .+? does not exist|not found)/iu.test(errorOutput(result));
}

function rootObservation(record: DisposableMachineRecordV1): MachineObservationSetV1['rootPath'] {
  if (!existsSync(record.clone.mountpoint)) return 'absent';
  try {
    const stat = lstatSync(record.clone.mountpoint);
    if (stat.isSymbolicLink()) return 'present-conflict';
    return realpathSync(record.clone.mountpoint) === record.clone.mountpoint ? 'present-matching' : 'present-conflict';
  } catch {
    return 'unknown';
  }
}

export class DisposableMachineObserver {
  constructor(private readonly executor: Pick<Executor, 'run'>) {}

  async source(snapshot: string): Promise<SourceSnapshotObservation> {
    const result = await this.executor.run({
      argv: ['/usr/sbin/zfs', 'get', '-H', '-p', '-o', 'property,value', 'guid,createtxg', snapshot],
    });
    const observedAt = new Date().toISOString();
    const dataset = snapshot.slice(0, snapshot.indexOf('@'));
    if (zfsObjectIsAbsent(result)) return { status: 'absent', snapshot, dataset, observedAt, command: result };
    if (result.exitCode !== 0) return { status: 'unknown', snapshot, dataset, observedAt, command: result };
    const properties = parsePropertyOutput(result);
    return {
      status: 'present', snapshot, dataset, observedAt, command: result,
      ...(properties.guid === undefined ? {} : { guid: properties.guid }),
      ...(properties.createtxg === undefined ? {} : { creationTxg: properties.createtxg }),
    };
  }

  async clone(dataset: string): Promise<CloneDatasetObservation> {
    const requested = ['guid', 'origin', 'mountpoint', ...OWNERSHIP_PROPERTIES];
    const result = await this.executor.run({
      argv: ['/usr/sbin/zfs', 'get', '-H', '-p', '-o', 'property,value', requested.join(','), dataset],
    });
    const observedAt = new Date().toISOString();
    if (zfsObjectIsAbsent(result)) return { status: 'absent', dataset, properties: {}, observedAt, command: result };
    if (result.exitCode !== 0) return { status: 'unknown', dataset, properties: {}, observedAt, command: result };
    const properties = parsePropertyOutput(result);
    return {
      status: 'present', dataset, properties, observedAt, command: result,
      ...(properties.guid === undefined ? {} : { guid: properties.guid }),
      ...(properties.origin === undefined ? {} : { origin: properties.origin }),
      ...(properties.mountpoint === undefined ? {} : { mountpoint: properties.mountpoint }),
    };
  }

  async listMachines(limit = 1_000): Promise<MachineListObservation> {
    const result = await this.executor.run({ argv: ['/usr/bin/machinectl', '--no-pager', '--no-legend', 'list'] });
    const observedAt = new Date().toISOString();
    if (result.exitCode !== 0) return { status: 'unknown', machineNames: [], observedAt, command: result };
    const machineNames = output(result).split('\n').map((line) => line.trim().split(/\s+/u)[0]).filter((name): name is string => typeof name === 'string' && name.length > 0).slice(0, limit);
    return { status: 'available', machineNames, observedAt, command: result };
  }

  async machine(machineName: string): Promise<MachineRuntimeObservation> {
    const result = await this.executor.run({
      argv: ['/usr/bin/machinectl', '--no-pager', 'show', machineName, '--property', 'Name', '--property', 'State', '--property', 'RootDirectory', '--property', 'Leader'],
    });
    const observedAt = new Date().toISOString();
    if (machineIsAbsent(result)) return { status: 'absent', properties: {}, observedAt, command: result };
    if (result.exitCode !== 0) return { status: 'unknown', properties: {}, observedAt, command: result };
    const properties = parseMachineOutput(result);
    const state = properties.State;
    return { status: state === 'running' ? 'running' : 'stopped', properties, observedAt, command: result };
  }

  async status(record: DisposableMachineRecordV1): Promise<MachineStatusObservation> {
    const [source, clone, machine] = await Promise.all([
      this.source(record.source.snapshot),
      this.clone(record.clone.dataset),
      this.machine(record.machineName),
    ]);
    const discrepancies: string[] = [];
    const expectedProperties: Record<string, string> = {
      'com.stealtheye.babyx:machine-id': record.machineId,
      'com.stealtheye.babyx:provider': record.providerId,
      'com.stealtheye.babyx:request-digest': record.creationRequestDigest,
      'com.stealtheye.babyx:owner-principal': record.ownerPrincipal,
    };
    const snapshotState: MachineObservationSetV1['snapshot'] = source.status === 'present'
      ? (record.source.snapshotGuid === undefined || source.guid === record.source.snapshotGuid ? 'present-matching' : 'present-conflict')
      : source.status === 'absent' ? 'absent' : 'unknown';
    if (snapshotState === 'present-conflict') discrepancies.push('source snapshot GUID differs from the durable binding');
    if (snapshotState === 'absent') discrepancies.push('source snapshot is absent');

    let datasetState: MachineObservationSetV1['dataset'];
    let mountpointState: MachineObservationSetV1['mountpoint'];
    if (clone.status === 'unknown') {
      datasetState = 'unknown'; mountpointState = 'unknown';
    } else if (clone.status === 'absent') {
      datasetState = 'absent'; mountpointState = 'absent';
    } else {
      const ownershipMatches = Object.entries(expectedProperties).every(([key, value]) => clone.properties[key] === value);
      const identityMatches = clone.origin === record.source.snapshot
        && clone.mountpoint === record.clone.mountpoint
        && (record.clone.datasetGuid === undefined || clone.guid === record.clone.datasetGuid);
      datasetState = ownershipMatches && identityMatches ? 'present-matching' : 'present-conflict';
      mountpointState = clone.mountpoint === record.clone.mountpoint ? 'present-matching' : 'present-conflict';
      if (!ownershipMatches) discrepancies.push('clone ownership properties differ from the durable binding');
      if (clone.origin !== record.source.snapshot) discrepancies.push('clone origin differs from the source snapshot');
      if (clone.mountpoint !== record.clone.mountpoint) discrepancies.push('clone mountpoint differs from the durable binding');
      if (record.clone.datasetGuid !== undefined && clone.guid !== record.clone.datasetGuid) discrepancies.push('clone dataset GUID differs from the durable binding');
    }

    let machinectlState: MachineObservationSetV1['machinectl'];
    if (machine.status === 'unknown') machinectlState = 'unknown';
    else if (machine.status === 'absent') machinectlState = 'absent';
    else if (machine.properties.Name !== record.machineName || (machine.properties.RootDirectory && machine.properties.RootDirectory !== record.clone.mountpoint)) {
      machinectlState = 'present-conflict'; discrepancies.push('machinectl identity differs from the durable binding');
    } else machinectlState = machine.status === 'running' ? 'running-matching' : 'stopped-matching';

    const rootPath = rootObservation(record);
    if (rootPath === 'present-conflict') discrepancies.push('machine root path identity is conflicting');
    const process: MachineObservationSetV1['process'] = machine.status === 'running' ? 'running-matching' : machine.status === 'unknown' ? 'unknown' : 'absent';
    const observedAt = new Date().toISOString();
    const observationsWithoutDigest = { dataset: datasetState, snapshot: snapshotState, mountpoint: mountpointState, machinectl: machinectlState, process, rootPath, observedAt };
    const observations: MachineObservationSetV1 = { ...observationsWithoutDigest, observationDigest: canonicalMachineRequestDigest(observationsWithoutDigest) };
    const anyUnknown = Object.values(observationsWithoutDigest).includes('unknown');
    const anyConflict = Object.values(observationsWithoutDigest).some((value) => value === 'present-conflict');
    const observedState: MachineObservedState = anyUnknown ? 'UNKNOWN'
      : anyConflict ? 'CONFLICT'
      : machine.status === 'running' ? 'RUNNING'
      : datasetState === 'present-matching' && rootPath === 'present-matching' ? (machine.status === 'stopped' ? 'STOPPED_INTACT' : 'CLONE_ONLY')
      : datasetState === 'absent' && machine.status === 'absent' && rootPath === 'absent' ? 'ABSENT'
      : 'PARTIALLY_REMOVED';
    return { observations, observedState, discrepancies, source, clone, machine };
  }

  requireProviderObservation<T extends { status: string; command: CommandResult }>(observation: T, operation: string): T {
    if (observation.status === 'unknown') throw new MachineServiceError('machine_provider_unavailable', `${operation} observation is unavailable`, { exitCode: observation.command.exitCode, stderrSha256: observation.command.stderrSha256 });
    return observation;
  }
}
