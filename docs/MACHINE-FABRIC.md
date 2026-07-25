# Nspawn-First Machine Fabric

Machine classes are descriptive: persistent workspace, clean build, disposable experiment, adversarial arena, failure replay, production rehearsal, and custom.

Baby-X supports directory images, raw images where available, booted systemd machines, nonboot command mode, bind mounts, environment, capabilities, resource properties, and private or bridged networking.

Clone selection is capability driven: native snapshot, reflink, thin-volume snapshot, then recursive copy. No filesystem vendor is hard-coded.

A destructive experiment should run in a clone. Host execution remains available whenever the task targets the host or cannot be performed correctly in a machine.

Lifecycle truth must distinguish creating, running, degraded, stopped, failed, lost, unavailable, and unknown. Cleanup verifies machine, process, mount, network, and transient-unit removal.
