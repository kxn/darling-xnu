#include <darling/emulation/xnu_syscall/bsd/impl/stat/rmdir.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/unlinkat.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/conversion/common_at.h>
long sys_rmdir(const char *path)
{
    return sys_unlinkat(get_perthread_wd(), path, BSD_AT_REMOVEDIR);
}
