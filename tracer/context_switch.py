#!/usr/bin/python3
#
# trace context switch

from __future__ import print_function

import time

from bcc import BPF
from bcc.utils import printb

# load BPF program
b = BPF(text="""
TRACEPOINT_PROBE(sched, sched_switch) {
    //cat /sys/kernel/debug/tracing/events/sched/sched_switch/format
    bpf_trace_printk("%d\\n", args->prev_prio);
    return 0;
}
""")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "TASK", "PID", "CPU"))
# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()  # (task, pid, cpu, flags, ts, msg)
        if "python" in task:
            print("{} {} {} {}".format(ts,cpu,pid,task)
    except KeyboardInterrupt:
        exit()
