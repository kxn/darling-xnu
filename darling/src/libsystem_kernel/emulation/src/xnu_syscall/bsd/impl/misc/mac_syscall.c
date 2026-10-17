#include <darling/emulation/xnu_syscall/bsd/impl/misc/mac_syscall.h>
#include <darling/emulation/conversion/errno.h>
#include <darlingserver/rpc.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/quarantine.h>

long sys_mac_syscall(const char* policy, int call, void* arguments)
{
    int ready = quarantine_kernel_ready();
    if (ready) return ready;
    int32_t bsd_error = 0;
    int result = dserver_rpc_mac_syscall(policy, call, arguments, &bsd_error);
    return result ? errno_linux_to_bsd(result) : -bsd_error;
}
