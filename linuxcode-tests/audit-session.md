# Audit session RPC backend

getaudit_addr/setaudit_addr now use checked server process memory and actual
server-owned audit context instead of a process-local static auditinfo_addr.
The Intel wire layout is checked at compile time. The original syscall-length
copy behavior is preserved. State survives fork/exec; setters require the actual
caller UID and reject unsupported headless attributes.

Paired server implementation and the 537-check native lifecycle fixture:
https://github.com/kxn/darlingserver/commit/0df62be9b9e422ef545c9d55897965713db8c75e

The source commit also carries forward the previously built parent kernel's
fcntl/xattr compatibility changes, whose source hashes match the selected
stable-boottime-kernel-v1 build. Rebuilding just the audit file on a fork lacking
those prior fixes would not reproduce the tested complete kernel.

Complete kernel build: 879 units, all 1,364 selected parent exports retained.
Audit-session Mach ports and auditon queries for other sessions remain unfinished.
Full Unity/UE App builds and signing have not been verified yet.
