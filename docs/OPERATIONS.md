# Operation Model

The public gateway exposes one tool, `call_x`. It forwards dynamically described `babyx.*` operations through QRT1.

Operation definitions contain only name, family, version, description, mutation truth, and input/output contracts. Risk tiers, confirmation digests, release-state fields, and mandatory evidence metadata are intentionally absent.

Raw escape hatches remain available for systemd, machines, tracing, debugging, checkpointing, packet tools, syscall supervision, specifications, and adversaries. Raw calls reject malformed transport data such as embedded NUL bytes but do not inspect or narrow valid powerful arguments.

Large or sensitive results belong in durable streams or artifacts rather than inline model context.
