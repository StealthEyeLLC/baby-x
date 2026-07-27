# Baby-X Constitution v1

Status: **Locked architectural direction**

Baby-X is governed by one mandate:

> Maximum capability, minimum permanent machinery, near-zero user ceremony.

## Constitutional rules

1. Keep the permanent core tiny.
2. Build maximum capability through composition.
3. Keep ordinary user interaction nearly ceremony-free.
4. Providers are small adapters, never independent platforms.
5. Providers do not own scheduling, persistence, durable recovery, or alternate authority.
6. Skills are the primary mechanism for capability growth and orchestration.
7. Use the simplest execution path that can reasonably succeed.
8. Escalate automatically only when task complexity or consequence warrants it.
9. Learn by adding skills, knowledge, fixtures, templates, and providers rather than bloating the kernel.
10. Prefer native operating-system primitives, files, SQLite, and Unix sockets until scale proves otherwise.
11. Load capabilities lazily so capability breadth does not create context or schema bloat.
12. Keep advanced verification optional for ordinary work and available at meaningful boundaries.
13. Preserve a direct-execution path even after autonomous routing and event-driven operation exist.
14. Every addition must increase useful power more than architectural complexity.
15. The core should be boring; the compositions may be extreme.


## Authority interpretation

The direct-execution principle does not authorize bypassing a specialized durable authority. Once Baby-X owns a durable concern, every public lifecycle operation for that concern must route through the owning service.

- Disposable machine lifecycle belongs only to `DisposableMachineService`.
- Durable process lifecycle belongs only to `JobManager`.
- Artifact lifecycle belongs only to `ArtifactManager`.
- Certification and racing coordinate existing authorities; they do not replace them.
- The gateway authenticates and forwards; it is never an executor or persistence authority.

Raw provider access is permitted only where no specialized durable authority is bypassed and only through the finite authenticated public catalog.

## Minimal permanent concepts

The target kernel should express the system through five concepts:

- Resource
- Action
- Job
- Event
- Skill

Machines, repositories, processes, terminals, browsers, previews, snapshots, networks, formal verification, sandbox races, self-healing, bounty work, and future Aegis behavior must be composed from these concepts rather than added as separate kernels.

## User-experience requirement

A normal request should remain outcome-oriented:

> Finish and validate this correctly.

The user should not be forced to manually select providers, worker counts, evidence modes, lifecycle operations, or cleanup steps. Internal complexity must reduce user friction rather than expose itself as ceremony.
