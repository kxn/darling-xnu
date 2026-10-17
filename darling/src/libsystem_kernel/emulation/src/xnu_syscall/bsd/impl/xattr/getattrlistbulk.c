#include <darling/emulation/xnu_syscall/bsd/impl/xattr/getattrlistbulk.h>
#include <darling/emulation/xnu_syscall/bsd/impl/xattr/getattrlistat.h>
#include <darling/emulation/xnu_syscall/bsd/impl/xattr/fgetattrlist.h>
#include <sys/attr.h>
#include <sys/errno.h>
#include <stdint.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/conversion/dirent/getdirentries.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
extern void *memcpy(void *, const void *, __SIZE_TYPE__);
extern void *memset(void *, int, __SIZE_TYPE__);
extern size_t strlen(const char *);
/* Linux fallback for XNU's readdirattr path. Individual attribute blocks reuse
 * the same packing implementation as getattrlistat/fgetattrlist. Only complete
 * records are published. A pending record's directory cookie is restored when
 * it cannot fit, so a small-buffer retry does not skip that entry.
 * Concurrent reads/seeks on one shared open description still require a server
 * offset lock; this fallback currently provides sequential cursor semantics. */
long sys_getattrlistbulk(int fd, struct xnu_attrlist *alist, void *out, size_t size, unsigned long options)
{
    if (!alist || !out) return -EFAULT;
    if (!size || alist->bitmapcount != 5 || alist->reserved || alist->volattr ||
        (alist->commonattr & ATTR_BULK_REQUIRED) != ATTR_BULK_REQUIRED) return -EINVAL;
    if (options & ~(FSOPT_NOFOLLOW|FSOPT_NOINMEMUPDATE|FSOPT_REPORT_FULLSIZE|FSOPT_PACK_INVAL_ATTRS|FSOPT_ATTR_CMN_EXTENDED|FSOPT_NOFIRMLINKPATH|FSOPT_RETURN_REALDEV)) return -ENOTSUP;
    struct linux_stat identity;
    long rv = LINUX_SYSCALL(__NR_fstat, fd, &identity);
    if (rv < 0) return errno_linux_to_bsd(rv);
    if ((identity.st_mode & 0170000) != 0040000) return -ENOTDIR;
    char entries[4096]; unsigned char record[16384];
    options |= FSOPT_ATTR_CMN_EXTENDED | FSOPT_NOFOLLOW | FSOPT_REPORT_FULLSIZE;
    /* Validate all attribute masks even for an empty directory. */
    rv = sys_fgetattrlist(fd, alist, record, sizeof(record), options);
    if (rv < 0) return rv;
    long cookie = LINUX_SYSCALL(__NR_lseek, fd, 0, 1);
    if (cookie < 0) return errno_linux_to_bsd(cookie);
    size_t used = 0; long count = 0;
    while ((rv = LINUX_SYSCALL(__NR_getdents64, fd, entries, sizeof(entries))) > 0) {
        for (long at = 0; at < rv;) {
            struct linux_dirent64 *entry = (void *)(entries + at);
            size_t room = rv - at;
            if (room < 20 || entry->d_reclen < 20 || entry->d_reclen > room) { rv = -5; goto linux_error; }
            char *name = entry->d_name;
            size_t name_room = entry->d_reclen - 19, n = 0;
            while (n < name_room && name[n]) n++;
            if (n == name_room) { rv = -5; goto linux_error; }
            at += entry->d_reclen;
            if (!entry->d_ino || !n || (n == 1 && name[0] == '.') || (n == 2 && name[0] == '.' && name[1] == '.')) {
                cookie = entry->d_off; continue;
            }
            long status = sys_getattrlistat(fd, name, alist, record, sizeof(record), options);
            if (status == -ENOENT) { cookie = entry->d_off; continue; } /* raced deletion, as XNU namei fallback */
            if (status < 0) {
                if (options & FSOPT_PACK_INVAL_ATTRS) {
                    /* Do not emit a success or invent a type-dependent invalid
                     * layout for an object whose metadata could not be read. */
                    LINUX_SYSCALL(__NR_lseek, fd, cookie, 0); return count ? count : status;
                }
                unsigned error_requested = !!(alist->commonattr & ATTR_CMN_ERROR);
                uint32_t length = 32 + error_requested*4 + ((n+4)&~3UL);
                memset(record, 0, length);
                uint32_t mask = ATTR_BULK_REQUIRED | (error_requested ? ATTR_CMN_ERROR : 0);
                memcpy(record+4, &mask, 4);
                unsigned position = 24;
                if (error_requested) { uint32_t error = -status; memcpy(record+position,&error,4); position+=4; }
                int32_t offset = 8;uint32_t name_size = n+1;
                memcpy(record+position,&offset,4);memcpy(record+position+4,&name_size,4);
                memcpy(record+position+8,name,name_size);memcpy(record,&length,4);
            }
            uint32_t length;memcpy(&length, record, 4);
            if (!length || length > sizeof(record)) { LINUX_SYSCALL(__NR_lseek,fd,cookie,0);return count?count:-EOVERFLOW; }
            if (length > size-used) { LINUX_SYSCALL(__NR_lseek,fd,cookie,0);return count?count:-ERANGE; }
            /* XNU uses eight-byte alignment when the available space permits;
             * an otherwise fitting unpadded final record is still returned. */
            uint32_t aligned = (length+7)&~7U;
            if (aligned <= sizeof(record) && aligned <= size-used) {
                memset(record+length,0,aligned-length);length=aligned;memcpy(record,&length,4);
            }
            memcpy((char *)out+used,record,length);used+=length;count++;cookie=entry->d_off;
            if (used == size) { LINUX_SYSCALL(__NR_lseek,fd,cookie,0);return count; }
        }
    }
    if (rv < 0) goto linux_error;
    return count;
linux_error:
    LINUX_SYSCALL(__NR_lseek,fd,cookie,0);
    return count ? count : errno_linux_to_bsd(rv);
}
