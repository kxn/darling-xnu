#include <darling/emulation/xnu_syscall/bsd/helper/misc/sandbox_fs.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darlingserver/rpc.h>
#include <sys/errno.h>
#include <stdint.h>

int sandbox_fs_copy_path(char *out, size_t capacity, const char *input) {
    if (!input) return -EFAULT;
    int pid=LINUX_SYSCALL(__NR_getpid);
    for (size_t at=0;at<capacity;) {
        uintptr_t address=(uintptr_t)input+at;
        if (address<(uintptr_t)input) return -EFAULT;
        size_t count=4096-(address&4095);
        if (count>32) count=32;
        if (count>capacity-at) count=capacity-at;
        struct {void *base;size_t length;} local={out+at,count},remote={(void *)address,count};
        long n=LINUX_SYSCALL(__NR_process_vm_readv,pid,&local,1,&remote,1,0);
        if (n<=0) return -EFAULT;
        for (long i=0;i<n;i++) if (!out[at+i]) return 0;
        at+=n;
    }
    return -ENAMETOOLONG;
}

void sandbox_fs_close(struct sandbox_fs_path *path) {
    if (path->directory>=0) LINUX_SYSCALL(__NR_close,path->directory);
    path->directory=-1;
}

int sandbox_fs_prepare(const struct vchroot_expand_args *expanded, struct sandbox_fs_path *out) {
    out->directory=-1;
    size_t length=0;
    while (length<sizeof expanded->path && expanded->path[length]) length++;
    if (length==sizeof expanded->path) return -ENAMETOOLONG;
    if (!length) return -ENOENT;
    size_t end=length;
    while (end>1 && expanded->path[end-1]=='/') end--;
    size_t slash=end;
    while (slash && expanded->path[slash-1]!='/') slash--;
    char parent[4096];
    size_t parent_length=slash?slash:1;
    if (slash) for (size_t i=0;i<slash;i++) parent[i]=expanded->path[i];
    else parent[0]='.';
    parent[parent_length]=0;
    out->leaf=expanded->path+slash;
    /* Preserve the Linux root spelling instead of turning it into an empty
     * relative name. Expanded guest-root paths normally are below this root. */
    if (slash==length && length==1) out->leaf=".";
    long fd=LINUX_SYSCALL(__NR_openat,expanded->dfd,parent,0x200000|0x10000|0x80000,0);
    if (fd<0) return errno_linux_to_bsd(fd);
    out->directory=fd;
    char descriptor[64];__simple_snprintf(descriptor,sizeof descriptor,"/proc/self/fd/%d",(int)fd);
    long n=LINUX_SYSCALL(__NR_readlink,descriptor,out->name.path,sizeof out->name.path-1);
    if (n<0) {sandbox_fs_close(out);return errno_linux_to_bsd(n);}
    size_t at=n;
    if (!at || out->name.path[at-1]!='/') out->name.path[at++]='/';
    for (const char *p=out->leaf;;p++) {
        if (at>=sizeof out->name.path) {sandbox_fs_close(out);return -ENAMETOOLONG;}
        out->name.path[at++]=*p;
        if (!*p) break;
    }
    int status=vchroot_unexpand(&out->name);
    if (status<0) {sandbox_fs_close(out);return errno_linux_to_bsd(status);}
    return 0;
}

int sandbox_fs_authorize(const char *operation,const struct sandbox_fs_path *path) {
#ifdef VARIANT_DYLD
    return -ENOTSUP;
#else
    uint64_t decision=0,arguments[20]={0};
    arguments[0]=(uintptr_t)&decision;
    arguments[2]=(uintptr_t)operation;
    arguments[3]=1; /* native path filter; current process */
    arguments[4]=(uintptr_t)path->name.path;
    arguments[5]=2; /* caller supplied an expanded canonical guest path */
    int32_t error=0;
    int result=dserver_rpc_mac_syscall("Sandbox",2,arguments,&error);
    if (result) return errno_linux_to_bsd(result);
    if (error) return -error;
    return decision?-EPERM:0;
#endif
}
