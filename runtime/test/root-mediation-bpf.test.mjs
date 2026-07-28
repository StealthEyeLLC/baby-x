import assert from 'node:assert/strict';
import test from 'node:test';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BpfLsmController } from '../../dist/runtime/root-platform/mediation/bpf-lsm.js';

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'baby-x-bpf-lsm-'));
  const sourcePath = join(root, 'observe.bpf.c');
  const objectPath = join(root, 'observe.bpf.o');
  writeFileSync(sourcePath, 'fixture-source');
  writeFileSync(objectPath, 'fixture-object');
  return { root, sourcePath, objectPath };
}

test('live BPF LSM probe reports exact support rather than source presence', () => {
  const probe = new BpfLsmController().probe();
  assert.ok(['UNAVAILABLE', 'DEGRADED', 'EXPERIMENTAL'].includes(probe.supportState));
  assert.equal(typeof probe.health.reason, 'string');
  if (!probe.health.activeLsms.includes('bpf')) {
    assert.equal(probe.supportState, 'UNAVAILABLE');
    assert.equal(probe.health.reason, 'bpf_lsm_not_active');
  }
});

test('BPF LSM fixture load, health, detach, and reconciliation are bounded', () => {
  const f = fixture();
  const calls = [];
  try {
    const run = (argv) => {
      calls.push(argv);
      if (argv[0] === 'prog' && argv[1] === 'loadall') {
        mkdirSync(argv[3], { recursive: true });
        writeFileSync(join(argv[3], 'babyx_observe_exec'), 'pinned');
      }
      return { status: 0, stdout: argv.includes('-j') ? '[]' : '', stderr: '' };
    };
    const controller = new BpfLsmController({ run, sourcePath: f.sourcePath, objectPath: f.objectPath, activeLsms: ['landlock', 'bpf'], bpftoolAvailable: true, btfAvailable: true });
    assert.equal(controller.probe().supportState, 'EXPERIMENTAL');
    const pinRoot = join(f.root, 'pins');
    assert.equal(controller.load(pinRoot).ok, true);
    assert.equal(controller.reconcile(pinRoot, 'ATTACHED').ok, true);
    assert.equal(controller.detach(pinRoot).ok, true);
    assert.equal(existsSync(pinRoot), false);
    assert.ok(calls.some((argv) => argv[1] === 'loadall'));
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test('BPF LSM load failure is bounded and unavailable LSM is rejected', () => {
  const f = fixture();
  try {
    const failed = new BpfLsmController({ run: () => ({ status: 1, stdout: '', stderr: 'fixture attach failure' }), sourcePath: f.sourcePath, objectPath: f.objectPath, activeLsms: ['bpf'], bpftoolAvailable: true, btfAvailable: true });
    assert.throws(() => failed.load(join(f.root, 'failed-pins')), (error) => error.code === 'mediation_native_failed' && !String(error.message).includes('fixture attach failure'));
    const unavailable = new BpfLsmController({ sourcePath: f.sourcePath, objectPath: f.objectPath, activeLsms: ['landlock'], bpftoolAvailable: true, btfAvailable: true });
    assert.throws(() => unavailable.load(join(f.root, 'unavailable-pins')), (error) => error.code === 'mediation_bpf_unavailable');
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});
