// SPDX-License-Identifier: GPL-2.0
// Baby-X BPF LSM observation-only provider. It never denies execution.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} mediation_counters SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(babyx_observe_exec, struct linux_binprm *bprm, int ret)
{
    __u32 event_key = 0;
    __u64 *events = bpf_map_lookup_elem(&mediation_counters, &event_key);
    if (events)
        __sync_fetch_and_add(events, 1);
    return ret;
}

char LICENSE[] SEC("license") = "GPL";
