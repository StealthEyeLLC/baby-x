# GitHub, Secrets, and Access

## 1. GitHub role

GitHub is permitted to:

1. identify repositories and exact commits.
2. deliver push, tag, release, deployment, or approval events.
3. host source and optional immutable release artifacts.
4. display deployment and check status.
5. link to local evidence through an authenticated URL or compact reference.

GitHub is not permitted to:

1. hold local release-authority state.
2. directly call Caddy or systemd.
3. activate production merely because a workflow or status succeeded.
4. bypass Baby owner policy.
5. become the only location of deployment evidence.
6. provide a mutable branch name as final release identity.

## 2. GitHub App identity

1. Use a GitHub App rather than a long-lived broad personal token.
2. Store App ID, installation ID, and repository allowlist as non-secret configuration.
3. Store the App private key as a service credential, never in Git, `.env`, command line, or release artifact.
4. Generate a signed JWT only when obtaining an installation token.
5. Mint installation access tokens only when needed.
6. Treat installation tokens as short-lived; GitHub documents a one-hour expiration.
7. Do not assume fixed token length or prefix because token formats can change.
8. Request the minimum repository permissions required for contents/read, metadata/read, deployments/status, checks/status, and optional release access.
9. Do not grant administration, members, secrets, actions, or broad write permissions unless a separately reviewed requirement exists.
10. Keep tokens in memory or a protected temporary credential file with bounded lifetime.
11. Never include a token in URLs, logs, artifacts, events, or receipts.

## 3. Inbound webhook path

### 3.1 Exposure

1. The webhook receiver is a narrow endpoint behind Caddy.
2. It does not create a new public port.
3. It accepts only the configured path and methods.
4. Request body size, header size, and rate are bounded.
5. The receiver cannot perform release side effects directly.
6. It may only verify, normalize, and persist an inbox record.

### 3.2 Verification

1. Read the raw request body without transformation.
2. require `X-Hub-Signature-256`.
3. calculate HMAC-SHA256 with the webhook secret.
4. compare in constant time.
5. require and validate `X-GitHub-Event`.
6. require `X-GitHub-Delivery` as the delivery GUID.
7. record repository and installation identity from the verified payload.
8. reject unsupported repositories, events, actions, and oversized payloads.
9. parse JSON only after signature verification.
10. do not log the raw payload when it may contain sensitive metadata.

### 3.3 De-duplication

`GitHubInboxRecordV1` contains:

1. delivery GUID.
2. event type and action.
3. repository ID and full name.
4. installation ID.
5. raw-body digest.
6. normalized-event digest.
7. received time.
8. signature verification result.
9. processing state.
10. resulting deployment ID or exclusion reason.

A repeated GUID with identical digest is a replay no-op. A repeated GUID with different bytes is a conflict and security event.

## 4. Supported event normalization

### 4.1 Push

1. Resolve the exact `after` commit.
2. apply repository and branch policy.
3. ignore deletion and unapproved refs.
4. enqueue build/certification automatically when configured.
5. promotion still follows approval/automation policy.

### 4.2 Tag

1. Resolve tag object and peeled commit.
2. enforce tag-pattern policy.
3. optionally require annotated/signed tag policy.
4. create an exact source request.

### 4.3 Release

1. accept configured actions such as `published`.
2. bind release metadata to exact tag/commit.
3. verify any supplied artifact digest and manifest before reuse.
4. GitHub release publication alone cannot certify or promote bytes.

### 4.4 Deployment or explicit approval

1. Match repository, environment, service, commit, and owner policy.
2. normalize to a local approval record.
3. reject stale approvals when the candidate identity changed.
4. one approval may authorize one exact request digest, never a moving ref.

### 4.5 Check/status events

Inbound check/status events are informational unless a policy explicitly binds an exact external certification provider and evidence contract. They do not automatically become local truth.

## 5. Polling fallback

1. Poll configured repositories when webhooks are unavailable or intentionally disabled.
2. Use ETags or last-seen immutable identities where supported.
3. Normalize poll observations through the same inbox schema.
4. Generate deterministic synthetic delivery IDs from repository, ref, commit, and poll policy.
5. Polling cannot bypass approval policy.
6. Backoff and rate limits are bounded.
7. Webhook and polling observations for the same commit converge on one deployment request.

## 6. Outbound GitHub reporting

### 6.1 Durable outbox

`GitHubOutboxRecordV1` contains:

1. outbox ID.
2. parent deployment ID.
3. repository and installation identity.
4. target API operation.
5. normalized request body digest.
6. attempt count.
7. next attempt time.
8. last status/error, redacted.
9. delivered response identity.
10. terminal delivery state.

Local deployment progress never waits synchronously for GitHub availability beyond a small bounded attempt.

### 6.2 Deployment status mapping

Suggested mapping:

1. local `REQUESTED` -> GitHub `queued`.
2. build/stage/start/readiness/cutover -> `in_progress`.
3. awaiting owner approval -> `pending`.
4. local `SUCCEEDED` -> `success`.
5. deterministic deployment failure -> `failure`.
6. infrastructure or provider failure -> `error`.
7. prior deployment superseded or rolled back -> `inactive` plus a new status describing rollback.

Use `log_url` and `environment_url` only when the target is safe and authenticated as needed. Never embed secrets in URLs.

### 6.3 Checks and commit status

1. A summary check may report build, certification, staging, cutover, observation, and cleanup phases.
2. An exact commit receives the state, never a branch without commit binding.
3. GitHub reporting contains local evidence digests and compact IDs.
4. GitHub status is a projection; the local `babyx.release.live` operation is authoritative.

## 7. Approval policy

Supported modes:

1. `OWNER_REQUIRED`: stage and certify automatically, wait for one exact owner approval.
2. `SCHEDULED_OWNER_REQUIRED`: approval plus allowed promotion window.
3. `LOW_RISK_AUTOMATIC`: automatic promotion only when all declared risk rules pass.
4. `MANUAL_ONLY`: no event-triggered preparation or promotion.
5. `DISABLED`: service cannot deploy.

An approval record binds:

1. approver principal.
2. deployment ID.
3. request digest.
4. source commit/tree.
5. artifact digest.
6. certification ID.
7. intended environment.
8. approval time and expiry.
9. optional scheduled window.

## 8. Secret storage

### 8.1 Prohibited secret locations

1. Git repository.
2. release artifact.
3. source archive.
4. `.env` inside a release.
5. durable deployment records.
6. event bodies.
7. artifact metadata.
8. command arguments.
9. Caddy configuration.
10. GitHub deployment descriptions.
11. shell history.
12. unrestricted process environment dumps.

### 8.2 systemd credentials

1. Prefer `LoadCredentialEncrypted=` for encrypted at-rest blobs supported by systemd 255.
2. Use `LoadCredential=` only for already protected root-owned sources under a reviewed policy.
3. systemd presents credentials in a service-private credential directory.
4. Service manifests declare credential names, not values or host paths.
5. Credential-set digest covers names, versions, and encrypted-object digests without revealing plaintext.
6. Each slot can bind a different credential set during rotation.
7. Credentials are available only to the target service and helpers explicitly authorized by the unit.
8. Temporary plaintext files must exist only in systemd-managed protected runtime storage and be removed automatically.

### 8.3 Legacy compatibility

If an application only reads environment variables:

1. use a small audited launcher.
2. launcher reads declared credential files.
3. launcher sets only the required variables immediately before `execve`.
4. values never enter the systemd unit file or Release Authority record.
5. launcher does not print values.
6. long-term migration to direct credential-file consumption is recommended but not required for baseline deployment.

## 9. Secret rotation

1. Create a new credential-set reference.
2. bind it only to the inactive slot.
3. start candidate privately.
4. execute credential-aware readiness and smoke tests.
5. cut over with the release or as a credential-only slot promotion.
6. observe.
7. retain prior credentials through rollback window when policy permits.
8. revoke old credentials only after the new slot is proven and rollback implications are accepted.
9. preserve digest-only evidence.

## 10. Baby and operator access

1. Deployment control stays behind the existing authenticated Baby/operator authority.
2. No raw release API is internet-accessible.
3. Peer identity and principal are included in signed receipts.
4. Owner-scoped reads hide other principals where multi-owner operation exists.
5. Mutations require owner principal, idempotency key, and expected sequence.
6. Raw God Mode operations remain separate and auditable; normal deployment never requires manual raw calls.
7. Phone-friendly operations use the same authority and evidence as automated GitHub requests.

## 11. Access-loss behavior

1. Loss of GitHub connectivity pauses event ingestion/reporting but does not stop local reconciliation.
2. Loss of Baby UI does not lose durable state.
3. Loss of one controller process triggers restart recovery.
4. Loss of credential authority prevents a new slot from starting but leaves the active slot unchanged.
5. Expired GitHub tokens are reminted, not persisted indefinitely.
6. Webhook secret rotation supports an overlap window with two credential references when policy requires it.

## 12. Security tests

1. invalid webhook signature rejected.
2. body mutation after signature rejected.
3. duplicate delivery converges.
4. GUID conflict alerts.
5. unsupported repo/event rejected.
6. token never appears in logs or records.
7. token-length changes do not break validation.
8. GitHub outage leaves local deployment truth intact.
9. outbox retries without duplicate semantic update.
10. stale approval rejected.
11. approval for one digest cannot authorize another.
12. credential bytes absent from source, artifact, evidence, environment export, and process arguments.
13. inactive-slot secret rotation succeeds before cutover.
14. wrong credential set fails readiness without affecting active production.
