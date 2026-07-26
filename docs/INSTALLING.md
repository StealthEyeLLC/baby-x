# Installing

This branch is not deployed.

Local installation packages an immutable release under `/opt/baby-x/releases/<id>`, updates `previous` and `current` atomically, installs the verified credential compatibility launcher at `/usr/libexec/babyx-credential-launcher` with root ownership and mode `0755`, installs systemd units, reloads the manager, starts the socket/runtime/gateway, and performs health readback.

Rollback swaps the current and previous pointers, restarts services, and reads back the exact active release.

Do not run installation scripts against production without separate deployment authorization.
