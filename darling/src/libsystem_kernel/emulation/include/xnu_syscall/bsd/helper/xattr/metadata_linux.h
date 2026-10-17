/* Linux statx UAPI, fixed-width fields through 0x90 plus reserved tail.
 * Layout reference: Linux include/uapi/linux/stat.h. */
#ifndef DARLING_METADATA_LINUX_H
#define DARLING_METADATA_LINUX_H
#include <stdint.h>
struct metadata_linux_time { int64_t sec; uint32_t nsec; int32_t reserved; };
struct metadata_linux_statx {
    uint32_t mask, blksize;
    uint64_t attributes;
    uint32_t nlink, uid, gid;
    uint16_t mode, spare;
    uint64_t ino, size, blocks, attributes_mask;
    struct metadata_linux_time atime, btime, ctime, mtime;
    uint32_t rdev_major, rdev_minor, dev_major, dev_minor;
    uint64_t reserved[14];
};
_Static_assert(sizeof(struct metadata_linux_statx) == 256, "Linux statx ABI");
#endif
