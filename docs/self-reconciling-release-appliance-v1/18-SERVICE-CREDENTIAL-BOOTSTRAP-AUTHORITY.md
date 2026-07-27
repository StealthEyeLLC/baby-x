# Service Credential Bootstrap Authority — Checkpoint K.5

Checkpoint K.5 extends the existing Credential Authority. It does not create a second vault, scheduler, worker, artifact store, receipt authority, or release authority.

## Certified profile

The initial profile is `baby-x.production-controller.v1`. It issues two independent Ed25519 private keys encoded as PKCS#8 PEM and one proof public key encoded as SPKI PEM. Private values remain in protected credential objects and never enter operation arguments, results, records, events, receipts, logs, artifacts, or Git. Public results contain opaque references, SHA-256 object digests, and public-key fingerprints only.

The profile binds the exact `fix-mcp` service principal to UID `997`. Forward and reverse account lookup run through the existing durable Job Authority using `getent passwd fix-mcp` and `getent passwd 997`. Name absence, UID mismatch, reverse-lookup mismatch, UID reuse, ambiguous output, and malformed passwd data fail closed.

## Lifecycle and recovery

Durable intent precedes generation. The transaction lifecycle covers planning, generation, reference persistence, identity binding, public materialization, verification, readiness, rotation, rollback, cleanup, failure, recovery-required, ambiguity, and revocation. Idempotent replay adopts the existing generation. Conflicting idempotency identities fail. Rotation preserves the prior active generation until the successor is fully verified. Rollback switches to a prior verified generation and never regenerates it. Revocation preserves evidence.

Activation uses the authoritative `ServiceCredentialProfileStateV1` record as the atomic source of truth. Response loss is recovered by record and filesystem readback. Derived indexes are rebuildable from authoritative records; corrupt records are isolated by the existing release store.

## Materialization contract

The authority produces an immutable materialization plan. Installation requires the exact verified generation identifier, compatibility digest, verification digest, `fix-mcp` UID binding, proof public material, and systemd credential drop-ins. The installer never mints credentials. It refuses missing, inactive, revoked, incompatible, mismatched, unsafe, or incompletely materialized generations.

Private values reach the controller and gateway only through systemd `LoadCredential=` runtime files. The controller receives `BABY_X_PROOF_PRIVATE_KEY=%d/baby-x-proof-private`. The gateway receives `BABY_X_GATEWAY_PRIVATE_KEY=%d/baby-x-gateway-authority-private`, `BABY_X_PROOF_PUBLIC_KEY=/etc/baby-x/proof-public.pem`, and `BABY_X_GATEWAY_UID=997`. Private bytes are not placed directly in environment variables.

Checkpoint K.5 authorizes repository implementation and disposable certification only. It does not authorize creating `/etc/baby-x`, installing `/opt/baby-x`, generating production credentials, restarting production units, staging a release candidate, arming rollback, changing Caddy, or cutting over traffic.

## Canonical documentation digest

The canonical procedure is implemented by `scripts/documentation-digest.mjs`:

1. Root is the repository root.
2. Included files are tracked `docs/*.md` and `docs/**/*.md` files.
3. Paths are repository-relative POSIX paths encoded as UTF-8.
4. Paths are sorted by unsigned byte value, equivalent to `LC_ALL=C` ordering.
5. Each file is framed as `uint64be(path byte length) || path bytes || uint64be(content byte length) || raw file bytes`.
6. Sizes and path bytes are included.
7. File content is used raw; line endings are not normalized.
8. Filesystem metadata is excluded.
9. SHA-256 is computed over the concatenated frames.

The Checkpoint L preflight value `1de04475a6a957f66d4ecb6ba1d08f748e0e8f564c2846c4dc8180f392bfbd1e` is exactly reproducible as SHA-256 over bytewise-sorted `sha256sum` lines for the 44 pre-K.5 Markdown files. The earlier A–K report value `1de04475812712b553ae0d40afac00420aac501cb818256e6e7a1a81137500e0` is not reproduced by the documented file set or plausible path/content aggregation and is classified as a reporting transcription error. Documentation content is not claimed to have changed without a Git content diff.

## Checkpoint L restart condition

Checkpoint L may restart only from the final certified K.5 commit after remote readback, disposable nspawn certification, immutable evidence artifact creation and readback, positive resource absence, unchanged protected snapshot, unchanged production service/release/Caddy anchors, and continued absence of production Baby-X paths and credentials.
