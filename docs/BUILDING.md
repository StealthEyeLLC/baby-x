# Building

Baby-X requires Node.js 24.18.0 and locked npm dependencies.

```bash
npm ci
npm run build
npm test
npm run lint
bash -n scripts/*.sh
```

The build compiles TypeScript, builds the peer-credential addon, the native mediation supervisor, and the static shell-free microVM guest agent, and attempts the Rust seccomp supervisor when Cargo is available. Missing optional toolchains are reported; they are not misrepresented as completed native builds. Firecracker, the matching guest kernel, and the ext4 base image are provisioned separately with `scripts/provision-microvm-assets.sh`; downloaded binaries and images are digest-verified and are not committed to Git.

Provider acceptance requiring packages absent from the host should run in disposable nspawn machines.
