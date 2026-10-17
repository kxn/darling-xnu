#include <darling/emulation/xnu_syscall/bsd/helper/misc/fsevents.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darlingserver/rpc.h>
#include <sys/errno.h>
#include <stdint.h>
#include <stddef.h>

// Identify the open-file description by its kernel-owned Unix peer address.
// FD-number reuse, dup, SCM_RIGHTS, fork and exec need no userspace FD table.
static int is_device(int fd) {
    struct {uint16_t family;char path[108];} address;
    unsigned length=sizeof address;
    long result=LINUX_SYSCALL(__NR_getpeername,fd,&address,&length);
    static const char name[]="darling.fsevents.v1.";
    if (result<0 || address.family!=1 || length<2+1+sizeof(name)-1 || address.path[0]) return 0;
    for (size_t i=0;i<sizeof(name)-1;i++) if (address.path[1+i]!=name[i]) return 0;
    return 1;
}
static int copy_self(void* destination,const void* source,size_t size,int writing) {
    struct {void* base;size_t length;} local={(void*)(writing?source:destination),size},
        remote={(void*)(writing?destination:source),size};
    long pid=LINUX_SYSCALL(__NR_getpid);
    long result=writing?LINUX_SYSCALL(__NR_process_vm_writev,pid,&local,1,&remote,1,0):
        LINUX_SYSCALL(__NR_process_vm_readv,pid,&local,1,&remote,1,0);
    return result==(long)size?0:-EFAULT;
}
int fsevents_device_open(int linux_flags) {
#ifdef VARIANT_DYLD
    return -ENOTSUP;
#else
    int fd=-1;
    int result=dserver_rpc_fsevents_open(linux_flags,&fd);
    if (result) return errno_linux_to_bsd(result);
    if (fd<0) return -EIO;
    // SCM_RIGHTS receives an FD with its own descriptor flags.
    result=LINUX_SYSCALL(__NR_fcntl,fd,2,(linux_flags&0x80000)?1:0);
    if (result<0) {LINUX_SYSCALL(__NR_close,fd);return errno_linux_to_bsd(result);}
    return fd;
#endif
}
int fsevents_device_ioctl(int fd,unsigned command,void* argument,int* result) {
    if (!is_device(fd)) return 0;
#ifdef VARIANT_DYLD
    *result=-ENOTSUP;
#else
    struct {uint64_t actions;int32_t count,depth;uint64_t output;} args;
    int output=-1;
    if (command==0x80187301 && copy_self(&args,argument,sizeof args,0)<0) {*result=-EFAULT;return 1;}
    *result=dserver_rpc_fsevents_ioctl(fd,command,(uintptr_t)argument,&output);
    if (*result) {*result=errno_linux_to_bsd(*result);return 1;}
    if (command==0x80187301) {
        if (output<0) *result=-EIO;
        else {
            *result=copy_self((void*)(uintptr_t)args.output,&output,sizeof output,1);
            if (*result) LINUX_SYSCALL(__NR_close,output);
        }
    }
#endif
    return 1;
}
int fsevents_device_read(int fd,void* buffer,int length,int* result) {
    if (!is_device(fd)) return 0;
    if (length<0) {*result=-EINVAL;return 1;}
    if (!length) {*result=0;return 1;}
    // A short read may not truncate and consume a sequenced packet. XNU leaves
    // the first full event queued and returns zero when it cannot fit.
    char byte;
    long size=LINUX_SYSCALL(__NR_recvfrom,fd,&byte,1,0x2|0x20,0,0); // PEEK|TRUNC
    if (size<0) *result=errno_linux_to_bsd(size);
    else if (size>length) *result=0;
    else {
        long n=LINUX_SYSCALL(__NR_read,fd,buffer,length);
        *result=n<0?errno_linux_to_bsd(n):n;
    }
    return 1;
}
