#include <darling/emulation/xnu_syscall/bsd/impl/stat/quotactl.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <sys/errno.h>
#include <sys/quota.h>
#include <stdint.h>
#include <stddef.h>

/* Linux UAPI if_dqblk: limits use 1024-byte units; Darwin uses bytes. */
struct linux_dqblk {
    uint64_t hard, soft, bytes, ihard, isoft, inodes, btime, itime;
    uint32_t valid;
};
static long copy_memory(void *destination, const void *source, size_t size, int writing) {
    struct {void *base;size_t size;} local={writing?(void*)source:destination,size},remote={writing?destination:(void*)source,size};
    long copied=LINUX_SYSCALL(writing?__NR_process_vm_writev:__NR_process_vm_readv,
        LINUX_SYSCALL(__NR_getpid),&local,1,&remote,1,0);
    return copied==(long)size?0:-EFAULT;
}
static long quota_error(long result) {
    /* A filesystem without quota operations is EOPNOTSUPP in Darwin. */
    if(result==-LINUX_ENOSYS||result==-LINUX_EOPNOTSUPP)return -EOPNOTSUPP;
    return result<0?errno_linux_to_bsd(result):result;
}
long sys_quotactl(const char *path,int command,int id,void *data) {
#ifndef __x86_64__
    return -ENOTSUP;
#else
    struct vchroot_expand_args vc;vc.flags=VCHROOT_FOLLOW;vc.dfd=get_perthread_wd();
    if(!path)return -EFAULT;
    size_t i;
    for(i=0;i<sizeof(vc.path);i++){
        if(copy_memory(vc.path+i,path+i,1,0))return -EFAULT;
        if(!vc.path[i])break;
    }
    if(i==sizeof(vc.path))return -ENAMETOOLONG;
    long result=vchroot_expand(&vc);if(result<0)return errno_linux_to_bsd(result);
    /* quotactl_fd uses fdget_raw, so O_PATH retains pathname lookup semantics
     * without requiring read permission or exposing a host block device. */
    int fd=LINUX_SYSCALL(__NR_openat,vc.dfd,vc.path,0x200000|0x80000,0);
    if(fd<0)return errno_linux_to_bsd(fd);
    unsigned type=(unsigned)command&0xff,operation=(unsigned)command>>8;
    if(type>1){result=-EINVAL;goto out;}
    if(operation==Q_GETQUOTA){
        struct linux_dqblk linux_data={0};
        result=quota_error(LINUX_SYSCALL(443,fd,(0x800007u<<8)|type,(unsigned)id,&linux_data));
        if(result)goto out;
        if(linux_data.hard>UINT64_MAX/1024||linux_data.soft>UINT64_MAX/1024||
            linux_data.ihard>UINT32_MAX||linux_data.isoft>UINT32_MAX||linux_data.inodes>UINT32_MAX||
            linux_data.btime>UINT32_MAX||linux_data.itime>UINT32_MAX){result=-EOVERFLOW;goto out;}
        struct dqblk output={0};output.dqb_bhardlimit=linux_data.hard*1024;output.dqb_bsoftlimit=linux_data.soft*1024;
        output.dqb_curbytes=linux_data.bytes;output.dqb_ihardlimit=linux_data.ihard;output.dqb_isoftlimit=linux_data.isoft;
        output.dqb_curinodes=linux_data.inodes;output.dqb_btime=linux_data.btime;output.dqb_itime=linux_data.itime;output.dqb_id=id;
        result=copy_memory(data,&output,sizeof(output),1);
    }else if(operation==Q_QUOTASTAT){
        uint32_t format=0;long native=LINUX_SYSCALL(443,fd,(0x800004u<<8)|type,0,&format);
        if(native&&native!=-LINUX_ESRCH){result=quota_error(native);goto out;}
        int enabled=native==0;result=copy_memory(data,&enabled,sizeof(enabled),1);
    }else if(operation==Q_SYNC){
        result=quota_error(LINUX_SYSCALL(443,fd,(0x800001u<<8)|type,0,0));
    }else result=-ENOTSUP; // quota file formats and quota-changing commands need separate translation
out:
    LINUX_SYSCALL(__NR_close,fd);return result;
#endif
}
