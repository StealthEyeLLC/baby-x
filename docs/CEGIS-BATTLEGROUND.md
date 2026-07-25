# CEGIS Battleground

The deterministic loop is candidate -> clean machine -> build and launch -> baseline verification -> adversaries -> counterexample or bounded pass.

A bounded pass is not mathematical proof unless an actual formal verifier established it.

Adversaries include tests, fuzz commands, mutation, process and service failure, machine reboot, network faults, dependency outage, disk and permission failures, resource pressure, clock shifts, seccomp errno/delay, invalid provider responses, and arbitrary commands.

A counterexample is a replay asset containing only produced material: source identity, candidate, specification, machine definition, trigger, expected property, observed result, streams, journals, traces, captures, backtraces, core/checkpoint references, artifacts, and replay instructions.

Replay returns reproduced, not reproduced, incompatible, or unknown and cleans disposable resources unless preservation was requested.
