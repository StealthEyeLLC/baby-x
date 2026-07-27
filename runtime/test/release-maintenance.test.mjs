import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  BabyXRuntime,
  MaintenanceAuthorityService,
  ReleaseApplianceStore,
  canonicalize,
  operationDefinitions,
  sha256,
  validateReleaseRecord,
} from '../../dist/runtime/index.js';

const NOW = '2026-07-27T05:00:00.000Z';
const FUTURE = '2026-07-27T07:00:00.000Z';
const OWNER = 'owner-maintenance';
const OTHER = 'other-maintenance';

function context(key, subject = OWNER, authorityClass = 'unrestricted-owner') {
  return { subject, authorityClass, idempotencyKey:key };
}

function approval(overrides = {}) {
  return {
    approverPrincipal: OWNER,
    approvalDigest: 'a'.repeat(64),
    approvedAt: NOW,
    expiresAt: '2026-07-28T05:00:00.000Z',
    reason: 'approved maintenance window',
    ...overrides,
  };
}

function baseInventory(overrides = {}) {
  return {
    observedAt: NOW,
    rootFilesystem: { observed:true, filesystemType:'ext4', hostWideSnapshotAvailable:false },
    ubuntuPro: { clientInstalled:true, attachmentState:'UNATTACHED', entitled:false, observationMethod:'PRO_STATUS' },
    livepatch: { clientInstalled:true, subscriptionAttached:false, entitled:false, patchesApplied:'NONE', kernelCoverage:'NONE' },
    reboot: { required:false, softReboot:{available:true}, fullReboot:{} },
    unattendedUpgrades: { configurationObserved:true, automaticReboot:true },
    providerBackup: { configured:true, capability:'DISK_SNAPSHOT' },
    zfs: { applicableDatasetsOnly:true, hostRootProtected:false },
    ...overrides,
  };
}

function baseSimulation(overrides = {}) {
  return {
    packages: [],
    affectedServices: [],
    diskBytesRequired: 0,
    memoryBytesRequired: 0,
    rebootRequired: false,
    repositoryDigest: 'b'.repeat(64),
    ...overrides,
  };
}

function fixture(options = {}) {
  const root = mkdtempSync(join(tmpdir(), 'babyx-maintenance-test-'));
  const store = new ReleaseApplianceStore(root);
  store.startupScan();
  const calls = { inventory:0, simulate:[], verify:[], apply:[], observe:[], certify:[], reboot:[] };
  let now = options.now ?? NOW;
  const provider = {
    authority: 'host-maintenance-provider',
    describe: () => ({ provider:'fake-maintenance', packageMutation:true, rebootExecution:false }),
    observeInventory: async () => {
      calls.inventory += 1;
      if (options.inventoryThrows) throw new Error(options.inventorySecret ?? 'inventory provider failed');
      return structuredClone(options.inventory ?? baseInventory());
    },
    simulatePackages: async (input) => {
      calls.simulate.push(structuredClone(input));
      if (options.simulateThrows) throw new Error(options.simulateSecret ?? 'simulation failed');
      return structuredClone(options.simulation ?? baseSimulation());
    },
    verifyDisposable: async (record) => {
      calls.verify.push(structuredClone(record));
      if (options.verifyThrows) throw new Error(options.verifySecret ?? 'verification failed');
      return structuredClone(options.verifyResult ?? { classification:'PASSED', jobIds:['job-verify-1'], candidateId:'candidate-maintenance-1' });
    },
    applyMaintenance: async (record) => {
      calls.apply.push(structuredClone(record));
      if (options.applyThrows) throw new Error(options.applySecret ?? 'apply failed');
      return structuredClone(options.applyResult ?? { classification:'APPLIED', jobIds:['job-apply-1'], rebootRequired:false, transactionId:'maintenance-transaction-1' });
    },
    observeMaintenance: async (record) => {
      calls.observe.push(structuredClone(record));
      if (options.observeThrows) throw new Error(options.observeSecret ?? 'observation failed');
      return structuredClone(options.observeResult ?? { classification:'APPLIED', rebootRequired:false, observationId:'observation-1' });
    },
    certifyHost: async (record) => {
      calls.certify.push(structuredClone(record));
      if (options.certifyThrows) throw new Error(options.certifySecret ?? 'certification failed');
      return structuredClone(options.certifyResult ?? { classification:'PASSED', jobIds:['job-certify-1'], certificateId:'host-certification-1' });
    },
    planReboot: async (record, mode) => {
      calls.reboot.push({record:structuredClone(record),mode});
      if (options.rebootPlanThrows) throw new Error('reboot plan unavailable');
      return structuredClone(options.rebootPlan ?? { mode, maintenanceWindow:'window-1' });
    },
  };
  for (const name of options.omit ?? []) delete provider[name];
  const service = new MaintenanceAuthorityService({ store, provider: options.noProvider ? undefined : provider, now:() => now });
  return {
    root, store, provider, service, calls,
    setNow(value) { now = value; },
    close() { rmSync(root,{recursive:true,force:true}); },
  };
}

async function plan(fx, payload = {}, key = 'plan-1') {
  return fx.service.plan({ maintenanceKind:'PACKAGE_UPDATE', ...payload }, context(key));
}

function forceState(fx, record, state, key, patch = {}) {
  const candidateValue = { ...record, ...patch, state, sequence:Number(record.sequence)+1, updatedAt:NOW };
  if (candidateValue.error === null || candidateValue.error === undefined) delete candidateValue.error;
  const candidate = validateReleaseRecord('MaintenanceRecordV1', candidateValue);
  return fx.store.applyMutation({
    schemaId:'MaintenanceRecordV1', recordId:String(record.maintenanceId), ownerPrincipal:OWNER,
    expectedSequence:Number(record.sequence), idempotencyKey:key, requestDigest:sha256(canonicalize(candidate)),
    operation:'test.maintenance.force', phase:'test-force', record:candidate, occurredAt:NOW,
  });
}

function code(expected) {
  return (error) => error?.code === expected;
}

function allFiles(root) {
  const result=[];
  const walk=(path) => { for(const name of readdirSync(path)){const file=join(path,name);if(statSync(file).isDirectory())walk(file);else result.push(file);} };
  walk(root);
  return result;
}

test('J01 describe reports ext4 host-wide snapshot limitation truthfully', async () => {
  const fx=fixture(); try {
    const result=await fx.service.describe({},context('describe-ext4'));
    assert.equal(result.failureDomain,'HOST_MAINTENANCE');
    assert.equal(result.separateFromDeploymentState,true);
    assert.equal(result.inventory.rootFilesystem.filesystemType,'ext4');
    assert.equal(result.inventory.rootFilesystem.hostWideSnapshotAvailable,false);
    assert.equal(result.inventory.rootFilesystem.rollbackClassification,'PROVIDER_BACKUP_ONLY');
    assert.match(result.inventory.rootFilesystem.limitation,/not ZFS/u);
  } finally { fx.close(); }
});

test('J02 unattached Ubuntu Pro and Livepatch are never reported as entitled', async () => {
  const fx=fixture(); try {
    const result=await fx.service.describe({},context('describe-pro'));
    assert.equal(result.inventory.ubuntuPro.attachmentState,'UNATTACHED');
    assert.equal(result.inventory.ubuntuPro.entitled,false);
    assert.equal(result.inventory.livepatch.subscriptionAttached,false);
    assert.equal(result.inventory.livepatch.entitled,false);
  } finally { fx.close(); }
});

test('J03 soft reboot truth is userspace-only and never satisfies a kernel update', async () => {
  const fx=fixture(); try {
    const result=await fx.service.describe({},context('describe-soft'));
    assert.equal(result.inventory.reboot.softReboot.userspaceOnly,true);
    assert.equal(result.inventory.reboot.softReboot.satisfiesKernelUpdate,false);
    assert.equal(result.capabilities.rebootExecution,false);
    assert.equal(result.capabilities.automaticFullReboot,false);
  } finally { fx.close(); }
});

test('J04 six maintenance operations are exact, unique, and mutation-classified', () => {
  const definitions=operationDefinitions();
  assert.equal(definitions.length,252);
  assert.equal(new Set(definitions.map((entry)=>entry.operation)).size,252);
  const expected={
    'babyx.maintenance.describe':false,
    'babyx.maintenance.plan':true,
    'babyx.maintenance.apply':true,
    'babyx.maintenance.status':false,
    'babyx.maintenance.reconcile':true,
    'babyx.maintenance.reboot':true,
  };
  for(const [operation,mutation] of Object.entries(expected)){
    const matches=definitions.filter((entry)=>entry.operation===operation);
    assert.equal(matches.length,1,operation);
    assert.equal(matches[0].mutation,mutation,operation);
    assert.equal(matches[0].input.additionalProperties,false,operation);
  }
});

test('J05 low-risk package simulation requires disposable verification without approval', async () => {
  const fx=fixture(); try {
    const result=await plan(fx,{targetPackages:['curl']},'plan-low');
    assert.equal(result.maintenance.state,'VERIFYING_DISPOSABLE');
    assert.equal(result.maintenance.riskClass,'LOW');
    assert.equal(result.maintenance.approvalRequired,false);
    assert.equal(result.maintenance.disposableVerificationRequired,true);
    assert.match(result.maintenance.packagePlan.simulationDigest,/^[a-f0-9]{64}$/u);
    assert.equal(result.maintenance.failureDomain,'HOST_MAINTENANCE');
  } finally { fx.close(); }
});

test('J06 service restart simulation is MEDIUM and requires disposable verification', async () => {
  const fx=fixture({simulation:baseSimulation({packages:[{name:'nginx',currentVersion:'1',candidateVersion:'2',serviceRestartRequired:true}],affectedServices:['nginx.service']})}); try {
    const result=await plan(fx,{targetPackages:['nginx']},'plan-medium');
    assert.equal(result.maintenance.riskClass,'MEDIUM');
    assert.equal(result.maintenance.approvalRequired,false);
    assert.equal(result.maintenance.disposableVerificationRequired,true);
    assert.equal(result.maintenance.state,'VERIFYING_DISPOSABLE');
  } finally { fx.close(); }
});

test('J07 kernel and high-impact package simulation requires approval and reboot truth', async () => {
  const fx=fixture({simulation:baseSimulation({packages:[{name:'linux-image-generic',currentVersion:'1',candidateVersion:'2'}],rebootRequired:true})}); try {
    const result=await plan(fx,{targetPackages:['linux-image-generic']},'plan-kernel');
    assert.equal(result.maintenance.riskClass,'HIGH');
    assert.equal(result.maintenance.approvalRequired,true);
    assert.equal(result.maintenance.kernelAffected,true);
    assert.equal(result.maintenance.rebootRequired,true);
    assert.equal(result.maintenance.state,'AWAITING_APPROVAL');
  } finally { fx.close(); }
});

test('J08 Caddy and systemd updates are classified as high impact', async () => {
  for (const packageName of ['caddy','systemd']) {
    const fx=fixture({simulation:baseSimulation({packages:[{name:packageName,currentVersion:'1',candidateVersion:'2'}]})});
    try {
      const result=await plan(fx,{targetPackages:[packageName]},`plan-${packageName}`);
      assert.equal(result.maintenance.riskClass,'HIGH',packageName);
      assert.equal(result.maintenance.approvalRequired,true,packageName);
    } finally { fx.close(); }
  }
});

test('J09 high-impact apply rejects missing approval before verification or package mutation', async () => {
  const fx=fixture({simulation:baseSimulation({packages:[{name:'systemd',currentVersion:'1',candidateVersion:'2'}]})}); try {
    const planned=(await plan(fx,{targetPackages:['systemd']},'plan-approval-required')).maintenance;
    await assert.rejects(fx.service.apply({maintenanceId:planned.maintenanceId,expectedSequence:planned.sequence},context('apply-no-approval')),code('release_maintenance_approval_required'));
    assert.equal(fx.calls.verify.length,0);
    assert.equal(fx.calls.apply.length,0);
    assert.equal(fx.store.getRecord('MaintenanceRecordV1',planned.maintenanceId).sequence,planned.sequence);
  } finally { fx.close(); }
});

test('J10 approved high-impact maintenance verifies disposable, applies, and certifies before success', async () => {
  const fx=fixture({simulation:baseSimulation({packages:[{name:'systemd',currentVersion:'1',candidateVersion:'2'}]})}); try {
    const planned=(await plan(fx,{targetPackages:['systemd']},'plan-happy-high')).maintenance;
    const result=await fx.service.apply({maintenanceId:planned.maintenanceId,expectedSequence:planned.sequence,approvalEvidence:[approval()]},context('apply-happy-high'));
    assert.equal(result.maintenance.state,'SUCCEEDED');
    assert.equal(result.maintenance.postUpdateCertification.classification,'PASSED');
    assert.equal(fx.calls.verify.length,1);
    assert.equal(fx.calls.apply.length,1);
    assert.equal(fx.calls.certify.length,1);
    assert.deepEqual(result.maintenance.activeJobIds,[]);
    assert.ok(result.maintenance.allJobIds.includes('job-verify-1'));
    assert.ok(result.maintenance.allJobIds.includes('job-apply-1'));
  } finally { fx.close(); }
});

test('J11 disposable verification failure blocks package application', async () => {
  const fx=fixture({simulation:baseSimulation({packages:[{name:'nginx',serviceRestartRequired:true}]}),verifyResult:{classification:'FAILED',jobIds:['job-verify-failed']}}); try {
    const planned=(await plan(fx,{targetPackages:['nginx']},'plan-verify-fail')).maintenance;
    const result=await fx.service.apply({maintenanceId:planned.maintenanceId,expectedSequence:planned.sequence},context('apply-verify-fail'));
    assert.equal(result.maintenance.state,'FAILED');
    assert.equal(result.maintenance.error.code,'release_maintenance_verification_failed');
    assert.equal(fx.calls.apply.length,0);
  } finally { fx.close(); }
});

test('J12 unknown disposable verification truth enters RECOVERY_REQUIRED', async () => {
  const fx=fixture({simulation:baseSimulation({packages:[{name:'nginx',serviceRestartRequired:true}]}),verifyResult:{classification:'UNKNOWN'}}); try {
    const planned=(await plan(fx,{targetPackages:['nginx']},'plan-verify-unknown')).maintenance;
    const result=await fx.service.apply({maintenanceId:planned.maintenanceId,expectedSequence:planned.sequence},context('apply-verify-unknown'));
    assert.equal(result.maintenance.state,'RECOVERY_REQUIRED');
    assert.equal(fx.calls.apply.length,0);
  } finally { fx.close(); }
});

test('J13 terminal application failure is FAILED and unknown application truth requires recovery', async () => {
  const failed=fixture({applyResult:{classification:'FAILED',jobIds:['job-apply-failed']}}); try {
    const planned=(await plan(failed,{},'plan-apply-failed')).maintenance;
    const result=await failed.service.apply({maintenanceId:planned.maintenanceId,expectedSequence:planned.sequence},context('apply-failed'));
    assert.equal(result.maintenance.state,'FAILED');
    assert.equal(result.maintenance.error.code,'release_maintenance_apply_failed');
  } finally { failed.close(); }
  const unknown=fixture({applyResult:{classification:'UNKNOWN'}}); try {
    const planned=(await plan(unknown,{},'plan-apply-unknown')).maintenance;
    const result=await unknown.service.apply({maintenanceId:planned.maintenanceId,expectedSequence:planned.sequence},context('apply-unknown'));
    assert.equal(result.maintenance.state,'RECOVERY_REQUIRED');
  } finally { unknown.close(); }
});

test('J14 provider exception text and secret material are not persisted', async () => {
  const secret='maintenance-provider-secret-value-should-never-persist';
  const fx=fixture({applyThrows:true,applySecret:secret}); try {
    const planned=(await plan(fx,{},'plan-secret')).maintenance;
    const result=await fx.service.apply({maintenanceId:planned.maintenanceId,expectedSequence:planned.sequence},context('apply-secret'));
    assert.equal(result.maintenance.state,'RECOVERY_REQUIRED');
    assert.equal(result.maintenance.error.message.includes(secret),false);
    const bytes=allFiles(fx.root).map((file)=>readFileSync(file)).filter((value)=>!value.includes(0)).map((value)=>value.toString('utf8')).join('\n');
    assert.equal(bytes.includes(secret),false);
  } finally { fx.close(); }
});

test('J15 reboot-required application stops before post-update certification', async () => {
  const fx=fixture({simulation:baseSimulation({packages:[{name:'linux-image-generic'}],rebootRequired:true}),applyResult:{classification:'APPLIED',jobIds:['job-kernel-apply'],rebootRequired:true}}); try {
    const planned=(await plan(fx,{targetPackages:['linux-image-generic']},'plan-reboot-required')).maintenance;
    const result=await fx.service.apply({maintenanceId:planned.maintenanceId,expectedSequence:planned.sequence,approvalEvidence:[approval()]},context('apply-reboot-required'));
    assert.equal(result.maintenance.state,'REBOOT_REQUIRED');
    assert.equal(result.maintenance.rebootRequired,true);
    assert.equal(fx.calls.certify.length,0);
  } finally { fx.close(); }
});

test('J16 failed or unknown post-update certification cannot produce success', async () => {
  const failed=fixture({certifyResult:{classification:'FAILED',certificateId:'failed-cert'}}); try {
    const planned=(await plan(failed,{},'plan-cert-failed')).maintenance;
    const result=await failed.service.apply({maintenanceId:planned.maintenanceId,expectedSequence:planned.sequence},context('apply-cert-failed'));
    assert.equal(result.maintenance.state,'FAILED');
    assert.equal(result.maintenance.error.code,'release_maintenance_certification_failed');
  } finally { failed.close(); }
  const unknown=fixture({certifyResult:{classification:'UNKNOWN'}}); try {
    const planned=(await plan(unknown,{},'plan-cert-unknown')).maintenance;
    const result=await unknown.service.apply({maintenanceId:planned.maintenanceId,expectedSequence:planned.sequence},context('apply-cert-unknown'));
    assert.equal(result.maintenance.state,'RECOVERY_REQUIRED');
  } finally { unknown.close(); }
});

test('J17 APPLYING response-loss recovery uses observation and never blindly reapplies', async () => {
  const fx=fixture({observeResult:{classification:'APPLIED',rebootRequired:false,observationId:'observed-exact'}}); try {
    const planned=(await plan(fx,{},'plan-observe')).maintenance;
    const applying=forceState(fx,planned,'APPLYING','force-applying');
    const result=await fx.service.reconcile({maintenanceId:applying.maintenanceId},context('reconcile-observe'));
    assert.equal(result.reconciled[0].state,'SUCCEEDED');
    assert.equal(fx.calls.observe.length,1);
    assert.equal(fx.calls.apply.length,0);
    assert.equal(fx.calls.certify.length,1);
  } finally { fx.close(); }
});

test('J18 unobservable APPLYING state enters recovery instead of blind package mutation', async () => {
  const fx=fixture({omit:['observeMaintenance']}); try {
    const planned=(await plan(fx,{},'plan-unobservable')).maintenance;
    const applying=forceState(fx,planned,'APPLYING','force-unobservable');
    const result=await fx.service.reconcile({maintenanceId:applying.maintenanceId},context('reconcile-unobservable'));
    assert.equal(result.reconciled[0].state,'RECOVERY_REQUIRED');
    assert.equal(fx.calls.apply.length,0);
  } finally { fx.close(); }
});

test('J19 full reboot is approval-gated planning only and never automatic execution', async () => {
  const fx=fixture(); try {
    const result=await fx.service.reboot({mode:'FULL',reason:'kernel maintenance'},context('plan-full-reboot'));
    assert.equal(result.executionPerformed,false);
    assert.equal(result.maintenance.state,'AWAITING_APPROVAL');
    assert.equal(result.maintenance.rebootPlan.mode,'FULL');
    assert.equal(result.maintenance.rebootPlan.automatic,false);
    assert.equal(result.maintenance.rebootPlan.outageExpected,true);
    assert.equal(result.maintenance.rebootPlan.secondServingNode,false);
    assert.equal(result.maintenance.rebootPlan.executionAuthorized,false);
  } finally { fx.close(); }
});

test('J20 soft reboot cannot satisfy a kernel-affecting maintenance record', async () => {
  const fx=fixture({simulation:baseSimulation({packages:[{name:'linux-image-generic'}],rebootRequired:true})}); try {
    const planned=(await plan(fx,{targetPackages:['linux-image-generic']},'plan-soft-kernel')).maintenance;
    await assert.rejects(fx.service.reboot({maintenanceId:planned.maintenanceId,expectedSequence:planned.sequence,mode:'SOFT',approvalEvidence:[approval()]},context('soft-kernel-reboot')),code('release_maintenance_reboot_forbidden'));
    assert.equal(fx.store.getRecord('MaintenanceRecordV1',planned.maintenanceId).sequence,planned.sequence);
  } finally { fx.close(); }
});

test('J21 maintenance.apply rejects reboot kinds before durable mutation', async () => {
  const fx=fixture(); try {
    const planned=(await fx.service.plan({maintenanceKind:'FULL_REBOOT'},context('plan-reboot-apply'))).maintenance;
    await assert.rejects(fx.service.apply({maintenanceId:planned.maintenanceId,expectedSequence:planned.sequence,approvalEvidence:[approval()]},context('apply-reboot-kind')),code('release_maintenance_reboot_forbidden'));
    assert.equal(fx.store.getRecord('MaintenanceRecordV1',planned.maintenanceId).sequence,planned.sequence);
    assert.equal(fx.calls.apply.length,0);
  } finally { fx.close(); }
});

test('J22 future scheduled maintenance remains durable and performs no simulation or mutation early', async () => {
  const fx=fixture(); try {
    const planned=(await plan(fx,{scheduledFor:FUTURE,targetPackages:['curl']},'plan-future')).maintenance;
    assert.equal(planned.state,'SCHEDULED');
    assert.equal(fx.calls.simulate.length,0);
    const applied=await fx.service.apply({maintenanceId:planned.maintenanceId,expectedSequence:planned.sequence},context('apply-future'));
    assert.equal(applied.deferred,true);
    assert.equal(applied.maintenance.state,'SCHEDULED');
    assert.equal(fx.calls.apply.length,0);
  } finally { fx.close(); }
});

test('J23 exact idempotent replay returns one durable record and conflicting reuse fails', async () => {
  const fx=fixture(); try {
    const first=await plan(fx,{targetPackages:['curl']},'same-plan-key');
    const replay=await plan(fx,{targetPackages:['curl']},'same-plan-key');
    assert.equal(replay.replayed,true);
    assert.equal(replay.maintenance.maintenanceId,first.maintenance.maintenanceId);
    assert.equal(fx.store.listRecordIdentities().filter((entry)=>entry.schemaId==='MaintenanceRecordV1').length,1);
    await assert.rejects(plan(fx,{targetPackages:['wget']},'same-plan-key'),code('release_idempotency_conflict'));
  } finally { fx.close(); }
});

test('J24 wrong principal and stale sequence fail before maintenance provider mutation', async () => {
  const fx=fixture(); try {
    const planned=(await plan(fx,{},'plan-authority')).maintenance;
    assert.throws(()=>fx.service.status({maintenanceId:planned.maintenanceId},context('status-other',OTHER)),code('release_wrong_principal'));
    await assert.rejects(fx.service.apply({maintenanceId:planned.maintenanceId,expectedSequence:planned.sequence-1},context('apply-stale')),code('release_stale_sequence'));
    assert.equal(fx.calls.apply.length,0);
  } finally { fx.close(); }
});

test('J25 maintenance failures remain a distinct failure domain and never create deployment records', async () => {
  const fx=fixture({applyResult:{classification:'FAILED'}}); try {
    const planned=(await plan(fx,{},'plan-distinct-domain')).maintenance;
    const result=await fx.service.apply({maintenanceId:planned.maintenanceId,expectedSequence:planned.sequence},context('apply-distinct-domain'));
    assert.equal(result.maintenance.failureDomain,'HOST_MAINTENANCE');
    assert.equal(result.maintenance.state,'FAILED');
    assert.equal(fx.store.listRecordIdentities().some((entry)=>entry.schemaId==='DeploymentRecordV1'),false);
  } finally { fx.close(); }
});

test('J26 maintenance status is owner-scoped and bounded', async () => {
  const fx=fixture(); try {
    await plan(fx,{},'plan-owner-status');
    const own=fx.service.status({limit:10},context('status-owner'));
    const other=fx.service.status({limit:10},context('status-other-list',OTHER));
    assert.equal(own.count,1);
    assert.equal(other.count,0);
  } finally { fx.close(); }
});

test('J27 runtime dispatch uses the injected maintenance authority', async () => {
  const fx=fixture();
  const runtimeRoot=mkdtempSync(join(tmpdir(),'babyx-maintenance-runtime-'));
  try {
    const runtime=new BabyXRuntime({stateRoot:runtimeRoot,maintenanceAuthorityService:fx.service});
    const result=await runtime.execute('babyx.maintenance.describe',{},context('runtime-describe'));
    assert.equal(result.failureDomain,'HOST_MAINTENANCE');
    assert.equal(result.inventory.rootFilesystem.filesystemType,'ext4');
  } finally { rmSync(runtimeRoot,{recursive:true,force:true}); fx.close(); }
});

test('J28 unconfigured authority is read-only truthful and package planning fails closed', async () => {
  const root=mkdtempSync(join(tmpdir(),'babyx-maintenance-unconfigured-'));
  try {
    const store=new ReleaseApplianceStore(root); store.startupScan();
    const service=new MaintenanceAuthorityService({store,now:()=>NOW});
    const described=await service.describe({},context('unconfigured-describe'));
    assert.equal(described.provider.configured,false);
    assert.equal(described.capabilities.packageApplication,false);
    assert.equal(described.capabilities.rebootExecution,false);
    const planned=await service.plan({maintenanceKind:'PACKAGE_UPDATE'},context('unconfigured-plan'));
    assert.equal(planned.maintenance.state,'RECOVERY_REQUIRED');
    assert.equal(planned.maintenance.error.code,'release_maintenance_provider_unavailable');
  } finally { rmSync(root,{recursive:true,force:true}); }
});

test('J29 maintenance authority contains no direct package, shell, service, or reboot primitive', () => {
  const source=readFileSync(new URL('../src/release/maintenance.ts',import.meta.url),'utf8');
  for(const forbidden of [
    "from 'node:child_process'", 'spawn(', 'execFile(', 'execSync(', 'apt-get', 'apt ', 'dpkg ',
    'systemctl restart', 'systemctl reboot', '/sbin/reboot', 'shutdown -r', 'rebootNow', 'new JobManager',
    'new MachineManager', 'new DisposableMachineService', 'zfs snapshot',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/HostMaintenanceProvider/u);
  assert.match(source,/applyMaintenance/u);
  assert.match(source,/executionPerformed:false/u);
});

test('J30 invalid public inputs fail before durable records or provider effects', async () => {
  const fx=fixture(); try {
    await assert.rejects(fx.service.plan({maintenanceKind:'ROOT_SHELL'},context('invalid-kind')),code('release_invalid_request'));
    await assert.rejects(fx.service.plan({maintenanceKind:'PACKAGE_UPDATE',unexpected:true},context('invalid-field')),code('release_invalid_request'));
    assert.equal(fx.store.listRecordIdentities().filter((entry)=>entry.schemaId==='MaintenanceRecordV1').length,0);
    assert.equal(fx.calls.simulate.length,0);
    assert.equal(fx.calls.apply.length,0);
  } finally { fx.close(); }
});
