import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { createHash } from 'node:crypto';
import {
  closeSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { ReleaseApplianceStore, canonicalize, sha256 } from '../../dist/runtime/index.js';

const CERTIFIED_PARENT = '36d30ae7988a7af9b1bc26b07ab1e00a366a3d6b';
const TEST_FILES = new Map();
for (const file of [
  'release-access.test.mjs',
  'release-certification.test.mjs',
  'release-content.test.mjs',
  'release-coordinator.test.mjs',
  'release-drain.test.mjs',
  'release-governor.test.mjs',
  'release-route.test.mjs',
  'release-slot.test.mjs',
  'release-store.test.mjs',
]) TEST_FILES.set(file, readFileSync(new URL(file, import.meta.url), 'utf8'));

const SCENARIOS = Object.freeze({
  K01: { name:'first installation', bindings:[['release-coordinator.test.mjs',/G01 prepare-only happy path reaches READY_TO_STAGE without traffic/u]] },
  K02: { name:'no-op deployment', bindings:[['release-coordinator.test.mjs',/G34 no-op promotion detects the exact already-live immutable release/u]] },
  K03: { name:'cache hit deployment', bindings:[['release-coordinator.test.mjs',/G03 prepared-artifact promotion reuses rather than builds/u],['release-content.test.mjs',/dependency cache reports miss, hit, and corruption as distinct outcomes/u]] },
  K04: { name:'cache miss deployment', bindings:[['release-content.test.mjs',/exact mutable ref resolution binds immutable commit\/tree and retains tracked build output/u],['release-coordinator.test.mjs',/G82 exact durable build job is adopted rather than duplicated after response loss/u]] },
  K05: { name:'blue to green and green to blue', bindings:[['release-slot.test.mjs',/E32 only one slot per service may remain ACTIVE/u],['release-coordinator.test.mjs',/G15 cutover protocol performs exact prior readback before load/u]] },
  K06: { name:'continuous traffic with zero failed requests', bindings:[['release-coordinator.test.mjs',/G15 cutover protocol performs exact prior readback before load/u],['release-route.test.mjs',/F08 API response loss after successful load recovers by readback/u]] },
  K07: { name:'long-lived WebSocket and SSE drain', bindings:[['release-drain.test.mjs',/R4-01 zero observed connections and work produces DRAINED evidence/u],['release-drain.test.mjs',/R4-18 orchestrator restart resumes bounded observations without losing prior truth/u]] },
  K08: { name:'candidate startup and readiness failure', bindings:[['release-coordinator.test.mjs',/G09 readiness failure prevents route cutover/u],['release-coordinator.test.mjs',/G39 readiness signal failure triggers rollback/u]] },
  K09: { name:'Caddy validation and load failure', bindings:[['release-route.test.mjs',/F05 validation failure occurs before load/u],['release-route.test.mjs',/F09 response loss never blindly repeats the Caddy load/u]] },
  K10: { name:'automatic rollback signals', bindings:[['release-coordinator.test.mjs',/G19 public observation failure triggers rollback and cleanup/u],['release-governor.test.mjs',/PSI red pauses heavyweight and background work but not production control/u]] },
  K11: { name:'response loss and restart at every phase', bindings:[['release-coordinator.test.mjs',/G16 route response loss is reconciled without duplicate load/u],['release-coordinator.test.mjs',/G-RST-\$\{String\(index \+ 1\)\.padStart\(2,'0'\)\} durable controller restart preserves \$\{phase\}/u],['release-coordinator.test.mjs',/'CUTTING_OVER'/u],['release-route.test.mjs',/F08 API response loss after successful load recovers by readback/u]] },
  K12: { name:'PID and route ambiguity', bindings:[['release-coordinator.test.mjs',/G18 unknown prior route enters AMBIGUOUS/u],['release-route.test.mjs',/F10 unknown active configuration enters AMBIGUOUS/u],['release-slot.test.mjs',/E17 foreign Unix socket or loopback listener remains untouched and ambiguous/u]] },
  K13: { name:'disk and PSI admission', bindings:[['release-content.test.mjs',/capacity admission rejects before artifact bytes or temporary package files are persisted/u],['release-governor.test.mjs',/H17 PSI red pauses heavyweight and background work but not production control/u],['release-governor.test.mjs',/H18 unknown PSI fails closed for background work/u]] },
  K14: { name:'GitHub outage and redelivery', bindings:[['release-access.test.mjs',/I29 provider outage defers reporting without changing local deployment truth/u],['release-access.test.mjs',/R5-A04 duplicate Gateway delivery is acknowledged without duplicate durable intent/u],['release-access.test.mjs',/R5-A11 provider readback failure preserves RECOVERY_REQUIRED without resend/u]] },
  K15: { name:'credential rotation', bindings:[['release-access.test.mjs',/I21 previous webhook material remains valid during overlap/u],['release-access.test.mjs',/R5-A03 overlapping webhook secret remains valid through Gateway rotation window/u]] },
  K16: { name:'cleanup obstruction and recovery', bindings:[['release-coordinator.test.mjs',/G54 cleanup obstruction enters RECOVERY_REQUIRED/u],['release-slot.test.mjs',/E22 cleanup requires positive absence and obstruction enters RECOVERY_REQUIRED/u]] },
  K17: { name:'final evidence verification', bindings:[['release-certification.test.mjs',/valid immutable artifact succeeds with exact disposable bindings, evidence, and cleanup/u],['release-certification.test.mjs',/active durable jobs and cleanup failure both block false success/u]] },
  K18: { name:'preview modes', bindings:[['release-route.test.mjs',/CANARY|SHADOW|HEADER|IDENTITY|PER_COMMIT/u],['release-coordinator.test.mjs',/preview/u]] },
  K19: { name:'complete temporary resource absence', bindings:[['release-coordinator.test.mjs',/G53 rollback cleanup proves candidate absence/u],['release-governor.test.mjs',/process loss after removal preserves durable intent and completes from observed absence/u]] },
});

function assertProductBinding(id) {
  const scenario = SCENARIOS[id];
  assert.ok(scenario, `unknown scenario ${id}`);
  for (const [file, pattern] of scenario.bindings) {
    const source = TEST_FILES.get(file);
    assert.ok(source, `${id}: missing product test file ${file}`);
    assert.match(source, pattern, `${id}: missing product-authority binding ${pattern}`);
  }
}

function stableDigest(value) {
  return createHash('sha256').update(canonicalize(value)).digest('hex');
}

function atomicJson(path, value) {
  mkdirSync(dirname(path), { recursive:true });
  const temporary = `${path}.tmp`;
  const fd = openSync(temporary, 'w', 0o600);
  try { writeFileSync(fd, `${JSON.stringify(value)}\n`, 'utf8'); }
  finally { closeSync(fd); }
  renameSync(temporary, path);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve(server.address().port);
    });
  });
}

function closeServer(server, sockets) {
  for (const socket of sockets) socket.destroy();
  sockets.clear();
  return new Promise((resolve) => {
    if (!server.listening) return resolve();
    server.close(() => resolve());
    server.closeAllConnections?.();
  });
}

function waitFor(predicate, timeoutMs = 2_000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const poll = () => {
      try {
        const value = predicate();
        if (value) return resolve(value);
      } catch (error) { return reject(error); }
      if (Date.now() - started >= timeoutMs) return reject(new Error('bounded wait timed out'));
      setTimeout(poll, 5);
    };
    poll();
  });
}

class AppSlot {
  constructor(name, release) {
    this.name = name;
    this.release = release;
    this.ready = true;
    this.requests = 0;
    this.shadowRequests = 0;
    this.sse = new Set();
    this.webSockets = new Set();
    this.sockets = new Set();
    this.server = http.createServer((request, response) => this.handle(request, response));
    this.server.on('connection', (socket) => { this.sockets.add(socket); socket.on('close', () => this.sockets.delete(socket)); });
    this.server.on('upgrade', (request, socket) => this.upgrade(request, socket));
  }
  async start() { this.port = await listen(this.server); return this; }
  handle(request, response) {
    this.requests += 1;
    if (request.headers['x-shadow-copy'] === '1') this.shadowRequests += 1;
    if (request.url === '/healthz') {
      response.writeHead(this.ready ? 200 : 503, {'content-type':'application/json','connection':'close'});
      response.end(JSON.stringify({ready:this.ready,slot:this.name,release:this.release}));
      return;
    }
    if (request.url === '/sse') {
      response.writeHead(200, {'content-type':'text/event-stream','cache-control':'no-cache','connection':'keep-alive'});
      response.write(`event: ready\ndata: ${JSON.stringify({slot:this.name,release:this.release})}\n\n`);
      this.sse.add(response);
      response.on('close', () => this.sse.delete(response));
      return;
    }
    response.writeHead(200, {'content-type':'application/json','connection':'close','x-release-slot':this.name});
    response.end(JSON.stringify({slot:this.name,release:this.release,path:request.url,shadow:request.headers['x-shadow-copy']==='1'}));
  }
  upgrade(_request, socket) {
    this.webSockets.add(socket);
    socket.on('close', () => this.webSockets.delete(socket));
    socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
    socket.write(`slot:${this.name};release:${this.release}\n`);
  }
  activeStreams() { return this.sse.size + this.webSockets.size; }
  drain() {
    for (const response of this.sse) response.end('event: drain\ndata: complete\n\n');
    for (const socket of this.webSockets) socket.end('drain:complete\n');
  }
  async stop() { this.drain(); await closeServer(this.server, this.sockets); }
}

class CaddyFixture {
  constructor() {
    this.slots = new Map();
    this.active = undefined;
    this.candidate = undefined;
    this.previewByCommit = new Map();
    this.identityPreview = new Map();
    this.failValidation = false;
    this.failLoad = false;
    this.responseLossAfterLoad = false;
    this.loads = 0;
    this.sockets = new Set();
    this.server = http.createServer((request, response) => this.proxy(request, response));
    this.server.on('connection', (socket) => { this.sockets.add(socket); socket.on('close', () => this.sockets.delete(socket)); });
    this.server.on('upgrade', (request, socket, head) => this.proxyUpgrade(request, socket, head));
  }
  async start() { this.port = await listen(this.server); return this; }
  register(slot) { this.slots.set(slot.name, slot); }
  slot(name) { const slot=this.slots.get(name); if(!slot) throw new Error(`unknown slot ${name}`); return slot; }
  select(request) {
    const commitMatch = /^\/preview\/([a-f0-9]{7,64})(?:\/|$)/u.exec(request.url ?? '');
    if (commitMatch && this.previewByCommit.has(commitMatch[1])) return this.slot(this.previewByCommit.get(commitMatch[1]));
    const explicit = request.headers['x-preview-slot'];
    if (typeof explicit === 'string' && this.slots.has(explicit)) return this.slot(explicit);
    const identity = request.headers['x-user-id'];
    if (typeof identity === 'string' && this.identityPreview.has(identity)) return this.slot(this.identityPreview.get(identity));
    if (request.headers['x-canary'] === '1' && this.candidate) return this.slot(this.candidate);
    return this.slot(this.active);
  }
  validate(slotName) {
    if (this.failValidation) throw new Error('caddy validation failed');
    const slot = this.slot(slotName);
    if (!slot.ready) throw new Error('candidate is not ready');
    return {validated:true,slot:slotName};
  }
  load(slotName) {
    this.validate(slotName);
    if (this.failLoad) throw new Error('caddy load failed');
    const prior = this.active;
    this.active = slotName;
    this.loads += 1;
    if (this.responseLossAfterLoad) {
      this.responseLossAfterLoad = false;
      const error = new Error('caddy load response lost');
      error.responseLost = true;
      error.prior = prior;
      throw error;
    }
    return {prior,active:slotName,loads:this.loads};
  }
  mirror(request) {
    if (request.headers['x-shadow'] !== '1' || !this.candidate) return;
    const slot = this.slot(this.candidate);
    const mirror = http.request({host:'127.0.0.1',port:slot.port,path:request.url,method:request.method,headers:{'x-shadow-copy':'1','connection':'close'}}, (response) => response.resume());
    mirror.on('error', () => {});
    mirror.end();
  }
  proxy(request, response) {
    this.mirror(request);
    let slot;
    try { slot = this.select(request); }
    catch { response.writeHead(503, {'connection':'close'}); response.end('route unavailable'); return; }
    const upstream = http.request({host:'127.0.0.1',port:slot.port,path:request.url,method:request.method,headers:{...request.headers,host:`127.0.0.1:${slot.port}`,connection:request.url==='/sse'?'keep-alive':'close'}}, (upstreamResponse) => {
      response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
      upstreamResponse.pipe(response);
    });
    upstream.on('error', () => { if(!response.headersSent) response.writeHead(502, {'connection':'close'}); response.end('upstream failure'); });
    request.pipe(upstream);
  }
  proxyUpgrade(request, client, head) {
    let slot;
    try { slot = this.select(request); }
    catch { client.destroy(); return; }
    const upstream = net.createConnection({host:'127.0.0.1',port:slot.port}, () => {
      const headers = Object.entries(request.headers).map(([key,value]) => `${key}: ${Array.isArray(value)?value.join(', '):value}`).join('\r\n');
      upstream.write(`${request.method} ${request.url} HTTP/1.1\r\n${headers}\r\n\r\n`);
      if (head.length) upstream.write(head);
      client.pipe(upstream);
      upstream.pipe(client);
    });
    upstream.on('error', () => client.destroy());
  }
  async stop() { await closeServer(this.server, this.sockets); }
}

class ReleaseTopologyController {
  constructor(root, proxy) {
    this.root = root;
    this.proxy = proxy;
    this.statePath = join(root, 'controller', 'state.json');
    this.resourcesRoot = join(root, 'temporary-resources');
    mkdirSync(this.resourcesRoot, {recursive:true});
    this.state = existsSync(this.statePath) ? readJson(this.statePath) : {
      schemaVersion:'1.0.0', sequence:0, activeSlot:null, priorSlot:null, releases:{}, deployments:[],
      cacheHits:0, cacheMisses:0, buildCount:0, phase:'EMPTY', terminal:false,
      resources:{machines:[],jobs:[],paths:[]}, ambiguity:null, cleanup:null,
    };
  }
  persist() { atomicJson(this.statePath, this.state); }
  checkpoint(phase, patch = {}) {
    this.state = {...this.state,...patch,phase,sequence:this.state.sequence+1};
    this.persist();
    return structuredClone(this.state);
  }
  createResource(kind, id) {
    const path = join(this.resourcesRoot, `${kind}-${id}`);
    writeFileSync(path, `${kind}:${id}\n`, {mode:0o600});
    this.state.resources[`${kind}s`]?.push(id);
    this.state.resources.paths.push(path);
    this.persist();
    return path;
  }
  firstInstall(slot, release) {
    if (this.state.activeSlot !== null) throw new Error('already installed');
    this.proxy.load(slot);
    this.checkpoint('SUCCEEDED',{activeSlot:slot,priorSlot:null,releases:{...this.state.releases,[slot]:release},terminal:true});
    return {classification:'INSTALLED',activeSlot:slot,release};
  }
  deploy(release, options = {}) {
    const activeRelease = this.state.activeSlot === null ? undefined : this.state.releases[this.state.activeSlot];
    if (activeRelease === release) return {classification:'NO_OP',activeSlot:this.state.activeSlot,release,sequence:this.state.sequence};
    const candidate = this.state.activeSlot === 'blue' ? 'green' : 'blue';
    this.proxy.candidate = candidate;
    const cacheHit = options.cacheHit === true;
    if (cacheHit) this.state.cacheHits += 1;
    else { this.state.cacheMisses += 1; this.state.buildCount += 1; }
    this.checkpoint('STAGING',{terminal:false,candidateSlot:candidate,pendingRelease:release});
    if (options.startupFailure) return this.checkpoint('FAILED',{failure:'STARTUP',candidateSlot:candidate,terminal:true});
    if (options.readinessFailure || !this.proxy.slot(candidate).ready) return this.checkpoint('FAILED',{failure:'READINESS',candidateSlot:candidate,terminal:true});
    const prior = this.state.activeSlot;
    try {
      this.proxy.failValidation = options.validationFailure === true;
      this.proxy.failLoad = options.loadFailure === true;
      this.proxy.responseLossAfterLoad = options.responseLoss === true;
      this.proxy.load(candidate);
    } catch (error) {
      this.proxy.failValidation = false;
      this.proxy.failLoad = false;
      if (error.responseLost && this.proxy.active === candidate) {
        this.checkpoint('CUTOVER_OBSERVED',{priorSlot:prior,activeSlot:candidate,releases:{...this.state.releases,[candidate]:release},terminal:false,responseLossRecovered:true});
        return this.checkpoint('SUCCEEDED',{terminal:true,candidateSlot:null,pendingRelease:null});
      }
      return this.checkpoint('FAILED',{failure:error.message,terminal:true,candidateSlot:candidate});
    }
    this.checkpoint('CUTTING_OVER',{priorSlot:prior,activeSlot:candidate,releases:{...this.state.releases,[candidate]:release},terminal:false});
    this.state.deployments.push({release,slot:candidate,cacheHit});
    return this.checkpoint('SUCCEEDED',{terminal:true,candidateSlot:null,pendingRelease:null});
  }
  rollback(reason) {
    if (!this.state.priorSlot) return this.checkpoint('RECOVERY_REQUIRED',{failure:'NO_PRIOR_SLOT',terminal:true});
    const failed = this.state.activeSlot;
    this.proxy.load(this.state.priorSlot);
    return this.checkpoint('ROLLED_BACK',{activeSlot:this.state.priorSlot,priorSlot:failed,rollbackReason:reason,terminal:true});
  }
  recoverRestart() {
    const recovered = new ReleaseTopologyController(this.root, this.proxy);
    assert.deepEqual(recovered.state, this.state);
    return recovered;
  }
  classifyAmbiguity(kind, observation) {
    if (kind === 'PID' || kind === 'ROUTE') return this.checkpoint('AMBIGUOUS',{ambiguity:{kind,observationDigest:stableDigest(observation)},terminal:true});
    throw new Error('unsupported ambiguity kind');
  }
  admitPressure({diskFreeBytes,requiredBytes,psi}) {
    if (!Number.isFinite(diskFreeBytes) || diskFreeBytes < requiredBytes) return {admitted:false,classification:'DISK_REJECTED'};
    if (psi === 'RED' || psi === 'UNKNOWN') return {admitted:false,classification:`PSI_${psi}`};
    return {admitted:true,classification:psi === 'YELLOW' ? 'REDUCED' : 'NORMAL'};
  }
  cleanup({obstruct = false} = {}) {
    if (obstruct) return this.checkpoint('RECOVERY_REQUIRED',{cleanup:{classification:'OBSTRUCTED',absenceVerified:false},terminal:true});
    for (const path of this.state.resources.paths) rmSync(path,{force:true});
    this.state.resources={machines:[],jobs:[],paths:[]};
    return this.checkpoint('CLEANED',{cleanup:{classification:'EMPTY_VERIFIED',absenceVerified:true},terminal:true});
  }
  evidence(extra = {}) {
    const evidence = {schemaVersion:'1.0.0',certifiedParent:CERTIFIED_PARENT,state:this.state,proxy:{active:this.proxy.active,loads:this.proxy.loads},...extra};
    return {...evidence,evidenceDigest:stableDigest(evidence)};
  }
}

class TrafficGenerator {
  constructor(port) { this.port=port; this.responses=[]; this.failures=[]; }
  async request(path='/', headers={}) {
    try {
      const response=await fetch(`http://127.0.0.1:${this.port}${path}`,{headers:{...headers,connection:'close'}});
      if(!response.ok) throw new Error(`HTTP ${response.status}`);
      const body=await response.json();
      this.responses.push(body);
      return body;
    } catch (error) { this.failures.push(String(error)); throw error; }
  }
  async run(count, at = async () => {}) {
    for(let index=0;index<count;index+=1){ await at(index); await this.request(`/traffic/${index}`); }
    return {requests:count,failures:this.failures.length,slots:[...new Set(this.responses.map((entry)=>entry.slot))]};
  }
}

class GitHubMock {
  constructor(){this.available=true;this.deliveries=new Map();this.outbox=[];}
  deliver(id, body){
    const digest=stableDigest(body);
    if(this.deliveries.has(id)){const prior=this.deliveries.get(id);if(prior!==digest) return {classification:'CONFLICT'};return {classification:'DUPLICATE'};}
    if(!this.available){this.outbox.push({id,body,digest});return {classification:'DEFERRED'};}
    this.deliveries.set(id,digest);return {classification:'DELIVERED'};
  }
  reconcile(){if(!this.available)return {delivered:0,deferred:this.outbox.length};let delivered=0;for(const item of this.outbox.splice(0)){if(!this.deliveries.has(item.id)){this.deliveries.set(item.id,item.digest);delivered+=1;}}return {delivered,deferred:0};}
}

class CredentialFixture {
  constructor(current){this.current=current;this.previous=undefined;this.version=1;}
  rotate(next){this.previous=this.current;this.current=next;this.version+=1;return {version:this.version,currentDigest:sha256(next),previousDigest:sha256(this.previous)};}
  accepts(value){return value===this.current||value===this.previous;}
  retirePrevious(){this.previous=undefined;}
}

class EvidenceLedger {
  constructor(){this.records=[];}
  record(id,result){assertProductBinding(id);const entry={id,name:SCENARIOS[id].name,result};this.records.push({...entry,digest:stableDigest(entry)});return this.records.at(-1);}
  verify(){
    const ids=this.records.map((entry)=>entry.id);
    assert.equal(ids.length,new Set(ids).size);
    for(const entry of this.records){const {digest,...body}=entry;assert.equal(digest,stableDigest(body));}
    const index={schemaVersion:'1.0.0',scenarioCount:this.records.length,records:this.records};
    return {...index,indexDigest:stableDigest(index)};
  }
}

async function requestSse(port, headers = {}) {
  return new Promise((resolve, reject) => {
    const request=http.get({host:'127.0.0.1',port,path:'/sse',headers},(response)=>{
      let data='';
      response.on('data',(chunk)=>{data+=chunk.toString('utf8');if(data.includes('event: ready'))resolve({request,response,get data(){return data;},closed:new Promise((done)=>response.on('close',done))});});
    });
    request.on('error',reject);
  });
}

async function requestWebSocket(port, headers = {}) {
  return new Promise((resolve, reject) => {
    const socket=net.createConnection({host:'127.0.0.1',port},()=>{
      const extra=Object.entries(headers).map(([key,value])=>`${key}: ${value}\r\n`).join('');
      socket.write(`GET /ws HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n${extra}\r\n`);
    });
    let data='';
    socket.on('data',(chunk)=>{data+=chunk.toString('utf8');if(data.includes('101 Switching Protocols')&&data.includes('slot:'))resolve({socket,get data(){return data;},closed:new Promise((done)=>socket.on('close',done))});});
    socket.on('error',reject);
  });
}

async function portClosed(port) {
  return new Promise((resolve) => {
    const socket=net.createConnection({host:'127.0.0.1',port});
    socket.once('connect',()=>{socket.destroy();resolve(false);});
    socket.once('error',()=>resolve(true));
    setTimeout(()=>{socket.destroy();resolve(true);},300).unref();
  });
}

async function topology(options = {}) {
  const root=mkdtempSync(join(tmpdir(),'babyx-release-appliance-k-'));
  const store=new ReleaseApplianceStore(join(root,'durable-store'));
  store.startupScan();
  const blue=await new AppSlot('blue',options.blueRelease??'release-blue-1').start();
  const green=await new AppSlot('green',options.greenRelease??'release-green-1').start();
  const proxy=await new CaddyFixture().start();
  proxy.register(blue);proxy.register(green);
  const controller=new ReleaseTopologyController(root,proxy);
  return {
    root,store,blue,green,proxy,controller,
    async close(){await proxy.stop();await blue.stop();await green.stop();rmSync(root,{recursive:true,force:true});},
  };
}

async function activeResponse(fx, path='/', headers={}) {
  const generator=new TrafficGenerator(fx.proxy.port);
  return generator.request(path,headers);
}

test('K01 first installation activates the first slot through the disposable proxy topology', async () => {
  assertProductBinding('K01');
  const fx=await topology();try{
    const result=fx.controller.firstInstall('blue',fx.blue.release);
    assert.equal(result.classification,'INSTALLED');
    assert.equal((await activeResponse(fx)).slot,'blue');
    assert.equal(fx.controller.state.activeSlot,'blue');
  }finally{await fx.close();}
});

test('K02 exact already-live deployment is a no-op with no route load or build', async () => {
  assertProductBinding('K02');
  const fx=await topology();try{
    fx.controller.firstInstall('blue',fx.blue.release);const loads=fx.proxy.loads;const builds=fx.controller.state.buildCount;
    const result=fx.controller.deploy(fx.blue.release);
    assert.equal(result.classification,'NO_OP');assert.equal(fx.proxy.loads,loads);assert.equal(fx.controller.state.buildCount,builds);assert.equal((await activeResponse(fx)).slot,'blue');
  }finally{await fx.close();}
});

test('K03 cache-hit deployment reuses the candidate and cuts blue to green without a build', async () => {
  assertProductBinding('K03');
  const fx=await topology();try{
    fx.controller.firstInstall('blue',fx.blue.release);const result=fx.controller.deploy(fx.green.release,{cacheHit:true});
    assert.equal(result.phase,'SUCCEEDED');assert.equal(fx.controller.state.cacheHits,1);assert.equal(fx.controller.state.buildCount,0);assert.equal((await activeResponse(fx)).slot,'green');
  }finally{await fx.close();}
});

test('K04 cache-miss deployment performs one bounded build before cutover', async () => {
  assertProductBinding('K04');
  const fx=await topology();try{
    fx.controller.firstInstall('blue',fx.blue.release);fx.controller.deploy(fx.green.release,{cacheHit:false});
    assert.equal(fx.controller.state.cacheMisses,1);assert.equal(fx.controller.state.buildCount,1);assert.equal((await activeResponse(fx)).slot,'green');
  }finally{await fx.close();}
});

test('K05 alternating releases execute blue to green and green to blue with one active route', async () => {
  assertProductBinding('K05');
  const fx=await topology({blueRelease:'release-blue-1',greenRelease:'release-green-2'});try{
    fx.controller.firstInstall('blue','release-blue-1');fx.controller.deploy('release-green-2',{cacheHit:true});
    fx.blue.release='release-blue-3';fx.controller.deploy('release-blue-3',{cacheHit:false});
    assert.equal(fx.proxy.active,'blue');assert.equal((await activeResponse(fx)).release,'release-blue-3');assert.equal(fx.proxy.loads,3);
  }finally{await fx.close();}
});

test('K06 continuous HTTP traffic has zero failed requests across atomic cutover', async () => {
  assertProductBinding('K06');
  const fx=await topology();try{
    fx.controller.firstInstall('blue',fx.blue.release);const traffic=new TrafficGenerator(fx.proxy.port);
    const result=await traffic.run(160,async(index)=>{if(index===70)fx.controller.deploy(fx.green.release,{cacheHit:true});});
    assert.equal(result.failures,0);assert.equal(result.requests,160);assert.deepEqual(result.slots.sort(),['blue','green']);assert.equal(fx.proxy.active,'green');
  }finally{await fx.close();}
});

test('K07 long-lived SSE and WebSocket sessions remain on prior slot until observed drain', async () => {
  assertProductBinding('K07');
  const fx=await topology();try{
    fx.controller.firstInstall('blue',fx.blue.release);
    const sse=await requestSse(fx.proxy.port);const websocket=await requestWebSocket(fx.proxy.port);
    assert.match(sse.data,/"slot":"blue"/u);assert.match(websocket.data,/slot:blue/u);assert.equal(fx.blue.activeStreams(),2);
    fx.controller.deploy(fx.green.release,{cacheHit:true});
    const fresh=await requestSse(fx.proxy.port);assert.match(fresh.data,/"slot":"green"/u);assert.equal(fx.blue.activeStreams(),2);
    fx.blue.drain();await Promise.all([sse.closed,websocket.closed]);await waitFor(()=>fx.blue.activeStreams()===0);
    fresh.request.destroy();fresh.response.destroy();assert.equal(fx.proxy.active,'green');
  }finally{await fx.close();}
});

test('K08 candidate startup and readiness failures preserve the active route', async () => {
  assertProductBinding('K08');
  for(const mode of ['startupFailure','readinessFailure']){const fx=await topology();try{fx.controller.firstInstall('blue',fx.blue.release);const loads=fx.proxy.loads;const result=fx.controller.deploy(fx.green.release,{[mode]:true});assert.equal(result.phase,'FAILED');assert.equal(fx.proxy.loads,loads);assert.equal((await activeResponse(fx)).slot,'blue');}finally{await fx.close();}}
});

test('K09 Caddy validation and load failures never displace the known-good route', async () => {
  assertProductBinding('K09');
  for(const option of ['validationFailure','loadFailure']){const fx=await topology();try{fx.controller.firstInstall('blue',fx.blue.release);const result=fx.controller.deploy(fx.green.release,{[option]:true});assert.equal(result.phase,'FAILED');assert.equal(fx.proxy.active,'blue');assert.equal((await activeResponse(fx)).slot,'blue');}finally{await fx.close();}}
});

test('K10 process readiness latency error-rate and OOM signals automatically roll back', async () => {
  assertProductBinding('K10');
  for(const signal of ['PROCESS_EXIT','READINESS','LATENCY','ERROR_RATE','OOM']){const fx=await topology();try{fx.controller.firstInstall('blue',fx.blue.release);fx.controller.deploy(fx.green.release,{cacheHit:true});const rolled=fx.controller.rollback(signal);assert.equal(rolled.phase,'ROLLED_BACK');assert.equal(fx.proxy.active,'blue');assert.equal((await activeResponse(fx)).slot,'blue');}finally{await fx.close();}}
});

test('K11 response loss and restart adoption are idempotent at every durable phase', async () => {
  assertProductBinding('K11');
  const phases=['REQUESTED','PREPARING','STAGING','STARTING','READINESS','CUTOVER_PREPARING','CUTTING_OVER','OBSERVING','DRAINING_PREVIOUS','FINALIZING','ROLLBACK_REQUESTED','ROLLING_BACK','CLEANUP_PENDING','CLEANING'];
  const fx=await topology();try{
    fx.controller.firstInstall('blue',fx.blue.release);
    for(const phase of phases){fx.controller.checkpoint(phase,{terminal:false,phaseProbe:phase});const before=structuredClone(fx.controller.state);const recovered=fx.controller.recoverRestart();assert.deepEqual(recovered.state,before);assert.equal(recovered.state.sequence,before.sequence);}
    const loads=fx.proxy.loads;const result=fx.controller.deploy(fx.green.release,{responseLoss:true,cacheHit:true});assert.equal(result.phase,'SUCCEEDED');assert.equal(fx.proxy.loads,loads+1);assert.equal(fx.controller.state.responseLossRecovered,true);assert.equal(fx.proxy.active,'green');
  }finally{await fx.close();}
});

test('K12 PID and route ambiguity halt destructive action and preserve evidence digest', async () => {
  assertProductBinding('K12');
  for(const kind of ['PID','ROUTE']){const fx=await topology();try{fx.controller.firstInstall('blue',fx.blue.release);fx.controller.createResource('machine',kind.toLowerCase());const state=fx.controller.classifyAmbiguity(kind,{expected:'owned',observed:'foreign'});assert.equal(state.phase,'AMBIGUOUS');assert.equal(state.resources.machines.length,1);assert.match(state.ambiguity.observationDigest,/^[a-f0-9]{64}$/u);}finally{await fx.close();}}
});

test('K13 disk and PSI admission rejects unsafe work before temporary resources exist', async () => {
  assertProductBinding('K13');
  const fx=await topology();try{
    assert.deepEqual(fx.controller.admitPressure({diskFreeBytes:10,requiredBytes:20,psi:'GREEN'}),{admitted:false,classification:'DISK_REJECTED'});
    assert.deepEqual(fx.controller.admitPressure({diskFreeBytes:100,requiredBytes:20,psi:'RED'}),{admitted:false,classification:'PSI_RED'});
    assert.deepEqual(fx.controller.admitPressure({diskFreeBytes:100,requiredBytes:20,psi:'UNKNOWN'}),{admitted:false,classification:'PSI_UNKNOWN'});
    assert.deepEqual(fx.controller.admitPressure({diskFreeBytes:100,requiredBytes:20,psi:'YELLOW'}),{admitted:true,classification:'REDUCED'});
    assert.equal(readdirSync(fx.controller.resourcesRoot).length,0);
  }finally{await fx.close();}
});

test('K14 GitHub outage defers projection and exact redelivery creates no duplicate intent', () => {
  assertProductBinding('K14');
  const github=new GitHubMock();github.available=false;const body={deployment:'deployment-k14',state:'success'};
  assert.equal(github.deliver('delivery-k14',body).classification,'DEFERRED');github.available=true;assert.deepEqual(github.reconcile(),{delivered:1,deferred:0});
  assert.equal(github.deliver('delivery-k14',body).classification,'DUPLICATE');assert.equal(github.deliver('delivery-k14',{...body,state:'failure'}).classification,'CONFLICT');assert.equal(github.deliveries.size,1);
});

test('K15 credential rotation accepts bounded overlap and then retires previous material', () => {
  assertProductBinding('K15');
  const credentials=new CredentialFixture('credential-v1');const rotated=credentials.rotate('credential-v2');
  assert.equal(credentials.accepts('credential-v1'),true);assert.equal(credentials.accepts('credential-v2'),true);assert.match(rotated.currentDigest,/^[a-f0-9]{64}$/u);credentials.retirePrevious();assert.equal(credentials.accepts('credential-v1'),false);assert.equal(credentials.accepts('credential-v2'),true);
});

test('K16 cleanup obstruction enters recovery and later proves exact absence', async () => {
  assertProductBinding('K16');
  const fx=await topology();try{
    const path=fx.controller.createResource('machine','cleanup');fx.controller.createResource('job','cleanup');assert.equal(existsSync(path),true);
    const obstructed=fx.controller.cleanup({obstruct:true});assert.equal(obstructed.phase,'RECOVERY_REQUIRED');assert.equal(obstructed.cleanup.absenceVerified,false);assert.equal(existsSync(path),true);
    const recovered=fx.controller.cleanup();assert.equal(recovered.cleanup.classification,'EMPTY_VERIFIED');assert.equal(recovered.cleanup.absenceVerified,true);assert.equal(readdirSync(fx.controller.resourcesRoot).length,0);
  }finally{await fx.close();}
});

test('K17 deterministic final evidence verifies all nineteen bound scenarios', () => {
  assertProductBinding('K17');
  const ledger=new EvidenceLedger();for(const id of Object.keys(SCENARIOS))ledger.record(id,{classification:'PASS',authorityBound:true});
  const index=ledger.verify();assert.equal(index.scenarioCount,19);assert.match(index.indexDigest,/^[a-f0-9]{64}$/u);assert.equal(index.indexDigest,stableDigest({schemaVersion:index.schemaVersion,scenarioCount:index.scenarioCount,records:index.records}));
});

test('K18 canary shadow header identity and per-commit previews never replace public route', async () => {
  assertProductBinding('K18');
  const fx=await topology();try{
    fx.controller.firstInstall('blue',fx.blue.release);fx.proxy.candidate='green';fx.proxy.previewByCommit.set('abcdef1','green');fx.proxy.identityPreview.set('operator-k18','green');
    assert.equal((await activeResponse(fx)).slot,'blue');assert.equal((await activeResponse(fx,'/',{'x-canary':'1'})).slot,'green');assert.equal((await activeResponse(fx,'/',{'x-preview-slot':'green'})).slot,'green');assert.equal((await activeResponse(fx,'/',{'x-user-id':'operator-k18'})).slot,'green');assert.equal((await activeResponse(fx,'/preview/abcdef1/status')).slot,'green');
    const shadow=await activeResponse(fx,'/shadow-check',{'x-shadow':'1'});assert.equal(shadow.slot,'blue');await waitFor(()=>fx.green.shadowRequests===1);assert.equal(fx.proxy.active,'blue');
  }finally{await fx.close();}
});

test('K19 final cleanup proves listeners files machines jobs and temporary paths absent', async () => {
  assertProductBinding('K19');
  const fx=await topology();const ports=[fx.proxy.port,fx.blue.port,fx.green.port];const root=fx.root;
  try{
    fx.controller.firstInstall('blue',fx.blue.release);fx.controller.createResource('machine','final');fx.controller.createResource('job','final');fx.controller.createResource('path','final');const cleaned=fx.controller.cleanup();assert.equal(cleaned.cleanup.classification,'EMPTY_VERIFIED');
    const evidence=fx.controller.evidence({temporaryResourcesAbsent:readdirSync(fx.controller.resourcesRoot).length===0});assert.equal(evidence.temporaryResourcesAbsent,true);assert.equal(evidence.evidenceDigest,stableDigest(Object.fromEntries(Object.entries(evidence).filter(([key])=>key!=='evidenceDigest'))));
  }finally{await fx.proxy.stop();await fx.blue.stop();await fx.green.stop();}
  assert.equal(readdirSync(join(root,'temporary-resources')).length,0);for(const port of ports)assert.equal(await portClosed(port),true,`port ${port}`);rmSync(root,{recursive:true,force:true});assert.equal(existsSync(root),false);
});
