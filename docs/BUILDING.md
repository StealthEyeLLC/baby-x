# Building

Baby-X requires Node.js 24.18.0 and locked npm dependencies.

```bash
npm ci
npm run build
npm test
npm run lint
bash -n scripts/*.sh
```

The build compiles TypeScript, builds the peer-credential addon, and attempts the Rust seccomp supervisor when Cargo is available. Missing optional toolchains are reported; they are not misrepresented as completed native builds.

Provider acceptance requiring packages absent from the host should run in disposable nspawn machines.
