# Mach host I/O SDK spelling compatibility

New SDK mach_host.defs uses host_get_io_main and old spelling host_get_io_master for the same routine, message 205. Add a Darling-only typed forwarding wrapper in the full libsystem_kernel source build. Preserve MIG transport, error results and ownership; no fixed return value or dummy port.

Native Linux x86_64/Darling checks verify new entry absent in baseline (12), both names return the same results across 16 real Mach exchanges, invalid-host send fails MACH_SEND_INVALID_DEST, and wrong expected check count rejects (15). Positive mode has 70 assertions and returns 0. All prior kernel exports remain; host.c is the only changed existing translation unit since the paired audit-session build.

Current backend returns KERN_SUCCESS and MACH_PORT_NULL for both names. This is retained and explicitly recorded; the wrapper does not establish a working I/O master service or original resource-tool compilation. Real port ownership branch is included but not exercised with the absent backend.
