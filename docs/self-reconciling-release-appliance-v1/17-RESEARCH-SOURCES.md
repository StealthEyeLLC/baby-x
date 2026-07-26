# Research Sources and Evidence Basis

## 1. Source policy

1. Primary vendor/project documentation is preferred.
2. Online documentation describes current upstream behavior, but installed-version verification remains mandatory because the target currently runs Caddy 2.6.2, systemd 255, and OpenZFS 2.2.2.
3. Live host observations outrank generic documentation for current version, capacity, filesystem, entitlement, and pressure facts.
4. VPS commercial-plan claims shown by the owner are recorded separately from host-observed facts.
5. No web source is treated as permission to mutate production.

## 2. Live host evidence

Read-only inventory was executed through the authenticated Baby authority on 2026-07-26. It observed:

1. Ubuntu 24.04 LTS.
2. kernel `6.8.0-136-generic`.
3. x86_64 KVM/QEMU guest with 6 online CPUs.
4. approximately 11 GiB usable memory and no swap.
5. approximately 96 GiB ext4 root with approximately 17 GiB available and 83 percent used at observation.
6. systemd 255.4 Ubuntu build.
7. `systemctl soft-reboot`, `systemctl kexec`, and `systemd-creds` available.
8. Caddy 2.6.2.
9. OpenZFS 2.2.2.
10. `babycert` pool online, approximately 11.5 GiB total and 11.1 GiB free at observation.
11. Ubuntu Pro client installed but machine not attached; Livepatch inactive.
12. no reboot required at observation.
13. Linux PSI interfaces present for CPU, memory, and I/O.

These values must be re-observed before implementation and production cutover.

## 3. Owner-supplied VPS plan evidence

The supplied plan image identifies:

1. plan label VPS-3.
2. 6 vCores.
3. 12 GB RAM.
4. 100 GB SSD NVMe.
5. daily backup of the previous 24 hours.
6. unlimited traffic.
7. 2 Gbps public bandwidth.
8. displayed starting price of $12.32 per month.

The hardware quantities align with the live inventory closely enough for design. Backup, traffic, bandwidth, and price are provider-plan claims and are not runtime-observed API facts.

## 4. Caddy primary sources

### 4.1 Reverse proxy

- URL: `https://caddyserver.com/docs/caddyfile/directives/reverse_proxy`
- Design consequences:
  1. static upstreams support loopback and Unix sockets.
  2. active and passive health-check controls exist.
  3. WebSocket proxying is supported.
  4. `stream_close_delay` can delay stream closure on config reload.
  5. low-latency/stream flushing behavior is configurable and SSE is recognized.
  6. header/cookie/hash policies can support controlled sticky canary behavior.

### 4.2 Admin API

- URL: `https://caddyserver.com/docs/api`
- Design consequences:
  1. configuration is managed through the local admin API.
  2. complete configuration can be loaded through `/load`.
  3. an invalid new config is rejected while the previous config remains active.
  4. configuration changes are persisted/autosaved for resume behavior.
  5. local Unix-socket administration is supported upstream, but installed-version behavior must be verified before adoption.

### 4.3 Command line and reload

- URL: `https://caddyserver.com/docs/command-line#caddy-reload`
- Design consequence: graceful reload is the correct production update model; stopping/restarting Caddy is not the release cutover path.

### 4.4 Getting started and API quick start

- URLs:
  - `https://caddyserver.com/docs/getting-started`
  - `https://caddyserver.com/docs/quick-starts/api`
- Design consequence: adapt/validate/load workflows can be rehearsed before live route mutation.

## 5. GitHub primary sources

### 5.1 GitHub App installation tokens

- URL: `https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app`
- Design consequences:
  1. installation tokens are minted from an App identity as needed.
  2. installation access tokens expire after one hour.
  3. repository and permission scope can be narrowed.

### 5.2 Token format changes

- URL: `https://github.blog/changelog/2025-05-08-updated-format-for-authentication-tokens-available-for-opt-in/`
- Design consequence: do not validate credentials by a fixed length or legacy prefix; treat tokens as opaque and expiring.

### 5.3 Webhook validation

- URL: `https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries`
- Design consequences:
  1. verify the raw payload with HMAC-SHA256.
  2. use `X-Hub-Signature-256`.
  3. use constant-time comparison.
  4. do not parse or act before verification.

### 5.4 Webhook headers

- URL: `https://docs.github.com/en/webhooks/webhook-events-and-payloads`
- Design consequence: persist `X-GitHub-Delivery`, event type, action, repository, installation, and body digest for de-duplication and audit.

### 5.5 Deployment status API

- URL: `https://docs.github.com/en/rest/deployments/statuses`
- Design consequences:
  1. status values include queued, pending, in progress, success, failure, error, and inactive.
  2. local deployment state can be projected into GitHub without making GitHub authoritative.
  3. log/environment URLs must be safe and must never contain credentials.

## 6. systemd primary sources

### 6.1 Execution environment and credentials

- URL: `https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html`
- Design consequences:
  1. `LoadCredential=` and `LoadCredentialEncrypted=` provide service-scoped credentials.
  2. runtime/state/cache/log directories can be systemd-managed.
  3. filesystem and process hardening directives can constrain services.

### 6.2 Resource control

- URL: `https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html`
- Design consequences:
  1. cgroup v2 CPU and I/O weights provide production-first relative scheduling.
  2. `MemoryHigh`, `MemoryMax`, and task limits bound background work.
  3. values must be read back and tested on systemd 255.

### 6.3 Service readiness and watchdog

- URL: `https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html`
- Design consequence: native notify readiness/watchdog can be used when the application supports it; compatibility probing remains available otherwise.

### 6.4 Soft reboot

- URLs:
  - `https://www.freedesktop.org/software/systemd/man/latest/systemd-soft-reboot.service.html`
  - `https://www.freedesktop.org/software/systemd/man/latest/systemd-halt.service.html`
- Design consequence: soft reboot restarts OS userspace while leaving the kernel, firmware, and hardware in place; it cannot satisfy a true kernel reboot requirement.

### 6.5 Credentials tooling

- URL: `https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html`
- Design consequence: encrypted credential creation and inspection must be capability-tested and handled without plaintext persistence in the release records.

## 7. OpenZFS primary sources

### 7.1 Quotas and reservations

- URL: `https://openzfs.github.io/openzfs-docs/Basic%20Concepts/Datasets/Quotas%20and%20Reservations.html`
- Design consequence: release/build datasets can use quota/refquota/reservation controls, subject to installed-version verification.

### 7.2 ZFS properties

- URL: `https://openzfs.github.io/openzfs-docs/man/master/7/zfsprops.7.html`
- Design consequences:
  1. dataset and snapshot-count limits can bound object growth where supported.
  2. compression, quota, reservation, and ownership metadata are readback-verifiable.
  3. upstream `master` documentation must not replace OpenZFS 2.2.2 capability checks.

### 7.3 Deliberate non-use of block deduplication

The decision not to enable ZFS block deduplication is an engineering constraint derived from this host's approximately 12 GB memory class, the availability of content-addressed logical reuse, and the operational cost of DDT memory and recovery complexity. This is not a claim that ZFS lacks deduplication; it is a host-specific decision to avoid friction and risk.

## 8. Ubuntu primary sources

### 8.1 Automatic updates

- URL: `https://ubuntu.com/server/docs/how-to/software/automatic-updates/`
- Design consequences:
  1. `unattended-upgrades` supports security-update automation.
  2. package blacklists and dry-run/debug paths exist.
  3. automatic reboot is configurable and should remain disabled by default for this single-node host.
  4. high-impact packages must be routed into the separate Maintenance Authority.

### 8.2 Package management and phased updates

- URLs:
  - `https://ubuntu.com/server/docs/explanation/software/about-apt-upgrade-and-phased-updates/`
  - `https://ubuntu.com/server/docs/how-to/software/package-management/`
- Design consequence: package origin, candidate version, phased state, simulation, and changed-service impact must be recorded before application.

### 8.3 Ubuntu Pro attachment and Livepatch

- URLs:
  - `https://documentation.ubuntu.com/pro/pro-client/how_to_attach/`
  - `https://documentation.ubuntu.com/pro/livepatch/how-to/enable_livepatch/`
- Design consequences:
  1. Livepatch requires an attached entitled Ubuntu Pro configuration.
  2. the current host is not attached, so v1 reports capability without pretending patches are active.
  3. attaching or purchasing a subscription is not a zero-friction automatic change.

### 8.4 Snapshot service

- URL: `https://documentation.ubuntu.com/server/explanation/software/snapshot-service/`
- Design consequence: staged/reproducible package sources can improve future update verification, but host adoption must be separately capability-tested and is not silently required.

## 9. Linux kernel pressure source

- URL: `https://docs.kernel.org/accounting/psi.html`
- Design consequence: CPU, memory, and I/O pressure stall information can drive bounded admission and concurrency reduction; policy must use sustained windows rather than one instantaneous sample.

## 10. Repository evidence basis

The design also derives from the certified Baby-X God Mode v1 implementation and its established invariants:

1. one dynamic gateway catalog.
2. durable jobs with exact process identity and lost-job reconciliation.
3. disposable-machine authority with ZFS/nspawn ownership and positive cleanup.
4. artifact and signed proof authorities.
5. certification and candidate execution boundaries.
6. no fabricated success.
7. strict schemas, idempotency, sequence checks, and ambiguity handling.

The new release appliance branch must verify these contracts directly against its frozen base rather than assuming this document is sufficient evidence.

## 11. Research conclusions that materially shaped the design

1. Caddy can provide graceful config replacement and private Unix-socket upstreams, so a second proxy is unnecessary.
2. Caddy reload can close WebSockets by default, so stream-close delay and explicit drain tests are mandatory.
3. GitHub App tokens are short-lived and format-variable, so token minting and opaque handling are mandatory.
4. Webhooks are redelivered and untrusted until HMAC verification, so a durable de-duplicated inbox is mandatory.
5. systemd already provides process supervision, readiness integration, cgroups, runtime directories, and credentials, so a second process supervisor is unnecessary.
6. Soft reboot is not a kernel reboot, so maintenance reporting must distinguish them.
7. The root filesystem is ext4, so host-wide ZFS snapshots are impossible without a disruptive future storage migration.
8. Root disk is already 83 percent used, so capacity reservations and hard floors are first-order release requirements.
9. The separate ZFS pool is small but mostly free, so disposable clone quotas and independent pool admission are mandatory.
10. No swap exists, so memory pressure must throttle before OOM rather than rely on swap recovery.
11. One VPS can provide application-level zero-downtime deployment but cannot provide host-level high availability.
