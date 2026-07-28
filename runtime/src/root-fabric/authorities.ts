import { isAbsolute } from 'node:path';
import { Executor, type CommandResult, type JsonObject } from '../core.ts';
import { RootFabricError, digest, integer, strictObject, stringArray, text } from './model.ts';
import type { EffectNetworkAuthority, EffectStorageAuthority } from './effects.ts';

const ZFS_NAME = /^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}$/u;
const NFT_TOKEN = /^[A-Za-z0-9_.:/@+-]{1,255}$/u;
const PROTECTED = new Set(['babycert/base/noble@golden-v1']);

function command(result: CommandResult): JsonObject {
  return result as unknown as JsonObject;
}

function zfsName(value: unknown, field: string, snapshot: boolean | null = null): string {
  const normalized = text(value, field, 256);
  if (!ZFS_NAME.test(normalized) || normalized.startsWith('-')) throw new RootFabricError('invalid_request', `${field} is not a safe ZFS name`);
  if (snapshot === true && !normalized.includes('@')) throw new RootFabricError('invalid_request', `${field} must be a snapshot`);
  if (snapshot === false && normalized.includes('@')) throw new RootFabricError('invalid_request', `${field} must be a dataset`);
  return normalized;
}

function absolute(value: unknown, field: string): string {
  const normalized = text(value, field, 4_096);
  if (!isAbsolute(normalized)) throw new RootFabricError('invalid_request', `${field} must be absolute`);
  return normalized;
}

function underAny(value: string, roots: readonly string[]): boolean {
  return roots.some((root) => value === root || value.startsWith(`${root}/`) || value.startsWith(`${root}@`));
}

export class RootStorageEffectAuthority implements EffectStorageAuthority {
  constructor(private readonly options: { executor?: Pick<Executor, 'run'>; datasetRoots: readonly string[]; mountRoots: readonly string[] }) {
    this.executor = options.executor ?? new Executor();
    for (const root of options.datasetRoots) zfsName(root, 'datasetRoot', false);
    for (const root of options.mountRoots) absolute(root, 'mountRoot');
  }
  private readonly executor: Pick<Executor, 'run'>;

  private dataset(value: unknown, field: string, snapshot: boolean | null = null): string {
    const normalized = zfsName(value, field, snapshot);
    const dataset = normalized.split('@', 1)[0]!;
    if (!underAny(dataset, this.options.datasetRoots)) throw new RootFabricError('policy_denied', `${field} is outside configured Baby-X storage roots`);
    return normalized;
  }

  private mountTarget(value: unknown, field: string): string {
    const normalized = absolute(value, field);
    if (!this.options.mountRoots.some((root) => normalized === root || normalized.startsWith(`${root}/`))) throw new RootFabricError('policy_denied', `${field} is outside configured Baby-X mount roots`);
    return normalized;
  }

  async prepareSnapshot(inputValue: JsonObject): Promise<JsonObject> {
    const input = strictObject(inputValue, 'snapshot prepare input', ['dataset', 'snapshotName', 'retention']);
    const dataset = this.dataset(input.dataset, 'dataset', false);
    const snapshotName = text(input.snapshotName, 'snapshotName', 128);
    if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u.test(snapshotName)) throw new RootFabricError('invalid_request', 'snapshotName is invalid');
    const snapshot = `${dataset}@${snapshotName}`;
    if (PROTECTED.has(snapshot)) throw new RootFabricError('protected_source_mismatch', 'protected golden snapshot cannot be created or replaced');
    const create = await this.executor.run({ argv: ['/usr/sbin/zfs', 'snapshot', snapshot] });
    if (create.exitCode !== 0) throw new RootFabricError('snapshot_failed', 'ZFS snapshot creation failed', { exitCode: create.exitCode, stderrSha256: create.stderrSha256 });
    return { snapshot, create: command(create), readback: await this.verifySnapshot({ snapshot }) };
  }

  async verifySnapshot(inputValue: JsonObject): Promise<JsonObject> {
    const input = strictObject(inputValue, 'snapshot verify input', ['snapshot', 'expectedGuid', 'expectedCreationTxg']);
    const snapshot = this.dataset(input.snapshot, 'snapshot', true);
    const result = await this.executor.run({ argv: ['/usr/sbin/zfs', 'get', '-Hp', '-o', 'property,value', 'guid,createtxg', snapshot] });
    if (result.exitCode !== 0) return { snapshot, present: false, command: command(result) };
    const values = Object.fromEntries(result.stdout.trim().split('\n').filter(Boolean).map((line) => line.split('\t', 2) as [string, string]));
    const guid = values.guid ?? null;
    const creationTxg = values.createtxg ?? null;
    const matches = (input.expectedGuid === undefined || String(input.expectedGuid) === guid) && (input.expectedCreationTxg === undefined || String(input.expectedCreationTxg) === creationTxg);
    return { snapshot, present: true, guid, creationTxg, matches, command: command(result) };
  }

  async rollbackSnapshot(inputValue: JsonObject): Promise<JsonObject> {
    const input = strictObject(inputValue, 'snapshot rollback input', ['snapshot', 'expectedGuid', 'expectedCreationTxg', 'recursive']);
    const snapshot = this.dataset(input.snapshot, 'snapshot', true);
    if (PROTECTED.has(snapshot)) throw new RootFabricError('protected_source_mismatch', 'protected golden snapshot may not be rolled back');
    const before = await this.verifySnapshot({ snapshot, expectedGuid: input.expectedGuid, expectedCreationTxg: input.expectedCreationTxg });
    if (before.present !== true || before.matches !== true) throw new RootFabricError('protected_source_mismatch', 'snapshot identity does not match the requested rollback source');
    const argv = ['/usr/sbin/zfs', 'rollback'];
    if (input.recursive === true) argv.push('-r');
    argv.push(snapshot);
    const result = await this.executor.run({ argv });
    if (result.exitCode !== 0) throw new RootFabricError('snapshot_failed', 'ZFS rollback failed', { exitCode: result.exitCode, stderrSha256: result.stderrSha256 });
    return { snapshot, rolledBack: true, command: command(result), readback: await this.verifySnapshot({ snapshot, expectedGuid: input.expectedGuid, expectedCreationTxg: input.expectedCreationTxg }) };
  }

  async releaseSnapshot(inputValue: JsonObject): Promise<JsonObject> {
    const input = strictObject(inputValue, 'snapshot release input', ['snapshot', 'expectedGuid', 'expectedCreationTxg']);
    const snapshot = this.dataset(input.snapshot, 'snapshot', true);
    if (PROTECTED.has(snapshot)) throw new RootFabricError('protected_source_mismatch', 'protected golden snapshot may not be released');
    const before = await this.verifySnapshot({ snapshot, expectedGuid: input.expectedGuid, expectedCreationTxg: input.expectedCreationTxg });
    if (before.present !== true || before.matches !== true) throw new RootFabricError('protected_source_mismatch', 'snapshot identity does not match the requested release source');
    const result = await this.executor.run({ argv: ['/usr/sbin/zfs', 'destroy', snapshot] });
    if (result.exitCode !== 0) throw new RootFabricError('snapshot_failed', 'ZFS snapshot release failed', { exitCode: result.exitCode, stderrSha256: result.stderrSha256 });
    const after = await this.verifySnapshot({ snapshot });
    if (after.present !== false) throw new RootFabricError('cleanup_failed', 'released snapshot remains present');
    return { snapshot, released: true, command: command(result), readback: after };
  }

  async mountStatus(inputValue: JsonObject): Promise<JsonObject> {
    const input = strictObject(inputValue, 'mount status input', ['target']);
    const target = this.mountTarget(input.target, 'target');
    const result = await this.executor.run({ argv: ['/usr/bin/findmnt', '--json', '--target', target] });
    return { target, mounted: result.exitCode === 0, command: command(result) };
  }

  async mountCreate(inputValue: JsonObject): Promise<JsonObject> {
    const input = strictObject(inputValue, 'mount create input', ['source', 'target', 'filesystem', 'options']);
    const source = text(input.source, 'source', 4_096);
    const target = this.mountTarget(input.target, 'target');
    const filesystem = text(input.filesystem, 'filesystem', 64);
    if (!/^[A-Za-z0-9_.+-]+$/u.test(filesystem)) throw new RootFabricError('invalid_request', 'filesystem is invalid');
    const options = stringArray(input.options ?? [], 'options', 64);
    if (options.some((option) => option.startsWith('-') || option.includes('\0'))) throw new RootFabricError('invalid_request', 'mount option is invalid');
    const argv = ['/usr/bin/mount', '-t', filesystem];
    if (options.length > 0) argv.push('-o', options.join(','));
    argv.push('--', source, target);
    const result = await this.executor.run({ argv });
    if (result.exitCode !== 0) throw new RootFabricError('execution_failed', 'mount creation failed', { exitCode: result.exitCode, stderrSha256: result.stderrSha256 });
    const readback = await this.mountStatus({ target });
    if (readback.mounted !== true) throw new RootFabricError('validation_failed', 'mount readback failed');
    return { source, target, filesystem, options, command: command(result), readback };
  }

  async mountRemove(inputValue: JsonObject): Promise<JsonObject> {
    const input = strictObject(inputValue, 'mount remove input', ['target', 'lazy']);
    const target = this.mountTarget(input.target, 'target');
    const argv = ['/usr/bin/umount'];
    if (input.lazy === true) argv.push('-l');
    argv.push('--', target);
    const result = await this.executor.run({ argv });
    if (result.exitCode !== 0) throw new RootFabricError('execution_failed', 'unmount failed', { exitCode: result.exitCode, stderrSha256: result.stderrSha256 });
    const readback = await this.mountStatus({ target });
    if (readback.mounted !== false) throw new RootFabricError('cleanup_failed', 'mount remains present after removal');
    return { target, command: command(result), readback };
  }
}

export class RootNetworkEffectAuthority implements EffectNetworkAuthority {
  constructor(private readonly options: { executor?: Pick<Executor, 'run'>; table?: string } = {}) {
    this.executor = options.executor ?? new Executor();
    this.table = options.table ?? 'babyx_root';
    if (!/^babyx_[A-Za-z0-9_.:@+-]{1,248}$/u.test(this.table)) throw new RootFabricError('policy_denied', 'network effects are confined to a Baby-X-owned nftables table');
  }
  private readonly executor: Pick<Executor, 'run'>;
  private readonly table: string;

  async portCheck(inputValue: JsonObject): Promise<JsonObject> {
    const input = strictObject(inputValue, 'port check input', ['protocol', 'address', 'port']);
    const protocol = text(input.protocol, 'protocol', 8);
    if (protocol !== 'tcp' && protocol !== 'udp') throw new RootFabricError('invalid_request', 'protocol must be tcp or udp');
    const address = text(input.address, 'address', 256);
    const port = integer(input.port, 'port', 1, 65_535);
    const result = await this.executor.run({ argv: ['/usr/bin/ss', '-H', '-l', protocol === 'tcp' ? '-t' : '-u', '-n', `sport = :${port}`] });
    const listeners = result.stdout.split('\n').filter(Boolean);
    return { protocol, address, port, available: listeners.length === 0, listeners, command: command(result) };
  }

  async listenerVerify(inputValue: JsonObject): Promise<JsonObject> {
    const input = strictObject(inputValue, 'listener verify input', ['protocol', 'address', 'port']);
    const check = await this.portCheck(input);
    return { ...check, listening: check.available === false };
  }

  private normalizeRule(inputValue: JsonObject): { chain: string; ruleId: string; expression: string[] } {
    const input = strictObject(inputValue, 'owned network rule input', ['chain', 'ruleId', 'expression']);
    const chain = text(input.chain, 'chain', 128);
    const ruleId = text(input.ruleId, 'ruleId', 128);
    if (!NFT_TOKEN.test(chain) || !NFT_TOKEN.test(ruleId)) throw new RootFabricError('invalid_request', 'owned network rule identity is invalid');
    const expression = stringArray(input.expression, 'expression', 64, false);
    if (expression.some((token) => !NFT_TOKEN.test(token))) throw new RootFabricError('invalid_request', 'owned network rule expression contains an unsafe token');
    return { chain, ruleId, expression };
  }

  async applyOwnedRule(inputValue: JsonObject): Promise<JsonObject> {
    const rule = this.normalizeRule(inputValue);
    const comment = `babyx:${rule.ruleId}`;
    await this.executor.run({ argv: ['/usr/sbin/nft', 'add', 'table', 'inet', this.table] });
    await this.executor.run({ argv: ['/usr/sbin/nft', 'add', 'chain', 'inet', this.table, rule.chain] });
    const result = await this.executor.run({ argv: ['/usr/sbin/nft', 'add', 'rule', 'inet', this.table, rule.chain, ...rule.expression, 'comment', comment] });
    if (result.exitCode !== 0) throw new RootFabricError('execution_failed', 'Baby-X owned nftables rule creation failed', { exitCode: result.exitCode, stderrSha256: result.stderrSha256 });
    return { ...rule, table: this.table, comment, command: command(result), ownedOnly: true };
  }

  async removeOwnedRule(inputValue: JsonObject): Promise<JsonObject> {
    const rule = this.normalizeRule(inputValue);
    const list = await this.executor.run({ argv: ['/usr/sbin/nft', '-a', 'list', 'chain', 'inet', this.table, rule.chain] });
    const marker = `comment \"babyx:${rule.ruleId}\"`;
    const line = list.stdout.split('\n').find((candidate) => candidate.includes(marker) && /# handle \d+$/u.test(candidate));
    if (line === undefined) return { ...rule, table: this.table, absent: true, command: command(list) };
    const match = /# handle (\d+)$/u.exec(line);
    if (match === null) throw new RootFabricError('ambiguous', 'owned nftables rule handle could not be identified');
    const result = await this.executor.run({ argv: ['/usr/sbin/nft', 'delete', 'rule', 'inet', this.table, rule.chain, 'handle', match[1]!] });
    if (result.exitCode !== 0) throw new RootFabricError('cleanup_failed', 'Baby-X owned nftables rule removal failed', { exitCode: result.exitCode, stderrSha256: result.stderrSha256 });
    return { ...rule, table: this.table, removed: true, command: command(result) };
  }
}
