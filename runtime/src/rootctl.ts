import { BabyXRuntime, canonicalize, type JsonObject, type RuntimeExecutionContext } from './core.ts';

const [command, ...args] = process.argv.slice(2);
const allowed = new Set(['status', 'freeze', 'unfreeze', 'kill-transaction', 'kill-skill', 'kill-all', 'reconcile']);
if (command === undefined || !allowed.has(command)) {
  process.stderr.write('usage: baby-x-rootctl status|freeze|unfreeze|kill-transaction|kill-skill|kill-all|reconcile [arguments]\n');
  process.exitCode = 2;
} else {
  const runtime = new BabyXRuntime({
    stateRoot: process.env.BABYX_STATE_ROOT ?? '/var/lib/baby-x',
    sourceCommit: process.env.BABYX_RELEASE_COMMIT ?? 'development',
    sourceTree: process.env.BABYX_RELEASE_TREE ?? 'development',
  });
  const context = (suffix: string): RuntimeExecutionContext => ({ subject: 'stealtheye-owner', authorityClass: 'unrestricted-owner', idempotencyKey: `rootctl-${command}-${suffix}` });
  let operation: string;
  let payload: JsonObject;
  if (command === 'status') { operation = 'babyx.root.compatibility.get'; payload = {}; }
  else if (command === 'freeze' || command === 'unfreeze') {
    const [scope, selector, ...reasonParts] = args;
    if (!scope || !selector) throw new Error(`${command} requires scope and selector`);
    operation = 'babyx.root.freeze.set';
    payload = { scope, selector, active: command === 'freeze', reason: reasonParts.join(' ') || `local ${command}`, expiresAt: null };
  } else if (command === 'kill-transaction' || command === 'kill-skill') {
    const [selector, ...reasonParts] = args;
    if (!selector) throw new Error(`${command} requires a selector`);
    operation = 'babyx.root.kill';
    payload = { scope: command === 'kill-transaction' ? 'TRANSACTION' : 'SKILL', selector, reason: reasonParts.join(' ') || `local ${command}` };
  } else if (command === 'kill-all') {
    operation = 'babyx.root.kill'; payload = { scope: 'ALL', selector: '*', reason: args.join(' ') || 'local kill-all' };
  } else {
    operation = 'babyx.root.reconcile'; payload = args[0] ? { transactionId: args[0] } : {};
  }
  runtime.execute(operation, payload, context(sha(operation, payload))).then((result) => process.stdout.write(`${canonicalize({ operation, result })}\n`)).catch((error) => { process.stderr.write(`${canonicalize({ operation, error: { message: error instanceof Error ? error.message : 'unknown error' } })}\n`); process.exitCode = 1; });
}

function sha(operation: string, payload: JsonObject): string {
  let value = 2166136261;
  for (const byte of Buffer.from(canonicalize({ operation, payload }))) value = Math.imul(value ^ byte, 16777619) >>> 0;
  return value.toString(16).padStart(8, '0');
}
