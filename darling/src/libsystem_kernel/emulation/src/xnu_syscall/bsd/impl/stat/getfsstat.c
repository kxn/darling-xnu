#include <darling/emulation/xnu_syscall/bsd/impl/stat/getfsstat.h>
#include <stddef.h>
#include <sys/errno.h>
#include <darling/emulation/xnu_syscall/bsd/helper/stat/mounts.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
extern void *memset(void *, int, __SIZE_TYPE__);
extern __SIZE_TYPE__ strlcpy(char *, const char *, __SIZE_TYPE__);
extern char *strtok_r(char *, const char *, char **);

long sys_getfsstat(struct bsd_statfs *buf, int size, int flags)
{
#ifdef __x86_64__
    return sys_getfsstat64((struct bsd_statfs64 *)buf, size, flags);
#else
    return -ENOTSUP;
#endif
}
long sys_getfsstat64(struct bsd_statfs64 *buf, int size, int flags)
{
    if (size < 0) return -EINVAL;
    struct darling_mount_reader reader;
    long opened=darling_mount_open(&reader);
    if(opened<0)return errno_linux_to_bsd(opened);
    /* Linux bind mounts are aliases of a filesystem, not additional Darwin
     * volumes. Return each actual filesystem identity once, for both the count
     * query and the fill query. Native CF's volume cache requires this.
     * The limit is explicit; exceeding it never produces a fabricated count. */
    unsigned long long seen[4096];
    unsigned count = 0;
    struct darling_mount_entry mount;
    long rd, result=0;
    while((rd=darling_mount_next(&reader,&mount))>0) {
            const char *source=mount.source,*target=mount.target,*type=mount.type;
            struct linux_statfs64 linux_fs;
            if (LINUX_SYSCALL(__NR_statfs, target, &linux_fs) < 0) continue;
            struct linux_stat identity;
            if (LINUX_SYSCALL(__NR_newfstatat, -100, target, &identity, 0) < 0) continue;
            unsigned long long fsid = darling_statfs_fsid(identity.st_dev, linux_fs.f_type);
            unsigned j;
            for (j = 0; j < count && seen[j] != fsid; j++);
            if (j < count) continue;
            if (count == sizeof(seen)/sizeof(seen[0])) { result = -EOVERFLOW; goto out; }
            seen[count] = fsid;
            if (buf && count < (unsigned)size/sizeof(*buf)) {
                struct bsd_statfs64 *entry = &buf[count];
                memset(entry, 0, sizeof(*entry));
                statfs_linux_to_bsd64(&linux_fs, entry);
                entry->f_fsid = fsid;
                entry->f_iosize = linux_fs.f_bsize;
                result=darling_mount_guest_name(entry->f_mntonname,sizeof(entry->f_mntonname),target);
                if(result<0){result=errno_linux_to_bsd(result);goto out;}
                if(entry->f_mntonname[0]=='/' && !entry->f_mntonname[1])entry->f_flags|=0x00004000; /* MNT_ROOTFS */
                if(source[0]=='/')result=darling_mount_guest_name(entry->f_mntfromname,sizeof(entry->f_mntfromname),source);
                else if(strlcpy(entry->f_mntfromname,source,sizeof(entry->f_mntfromname))>=sizeof(entry->f_mntfromname))result=-36;
                if(result<0){result=errno_linux_to_bsd(result);goto out;}
                strlcpy(entry->f_fstypename, type, sizeof(entry->f_fstypename));
            }
            count++;
    }
    if (rd < 0) result = errno_linux_to_bsd(rd);
    else result = buf && count > (unsigned)size/sizeof(*buf) ? (unsigned)size/sizeof(*buf) : count;
out:
    LINUX_SYSCALL(__NR_close, reader.fd);
    return result;
}
