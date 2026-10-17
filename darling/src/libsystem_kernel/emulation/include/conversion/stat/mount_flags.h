#ifndef DARLING_CONVERSION_STAT_MOUNT_FLAGS_H
#define DARLING_CONVERSION_STAT_MOUNT_FLAGS_H
/* Linux statfs ST_* values and Darwin MNT_* values occupy different bit
 * positions. ST_VALID is an ABI marker, not Darwin's MNT_UNION; Linux relatime
 * is likewise not Darwin MNT_LOCAL. Map only semantically corresponding bits.
 */
static inline unsigned int darling_mount_flags_to_bsd(unsigned long flags, unsigned long type)
{
    unsigned int result = 0;
    if (flags & 0x001) result |= 0x00000001; /* ST_RDONLY -> MNT_RDONLY */
    if (flags & 0x002) result |= 0x00000008; /* ST_NOSUID -> MNT_NOSUID */
    if (flags & 0x004) result |= 0x00000010; /* ST_NODEV -> MNT_NODEV */
    if (flags & 0x008) result |= 0x00000004; /* ST_NOEXEC -> MNT_NOEXEC */
    if (flags & 0x010) result |= 0x00000002; /* ST_SYNCHRONOUS -> MNT_SYNCHRONOUS */
    if (flags & 0x400) result |= 0x10000000; /* ST_NOATIME -> MNT_NOATIME */
    switch (type) {
    case 0x9123683e: /* btrfs */
    case 0xef53:     /* ext2/3/4 */
    case 0x58465342: /* XFS */
    case 0xf2f52010: /* F2FS */
    case 0x01021994: /* tmpfs */
    case 0x858458f6: /* ramfs */
    case 0x794c7630: /* overlayfs */
    case 0x9660:     /* ISO 9660 */
    case 0x15013346: /* UDF */
    case 0x4d44:     /* FAT */
    case 0x2011bab0: /* exFAT */
    case 0x5346544e: /* NTFS */
        result |= 0x00001000; /* MNT_LOCAL */
        break;
    case 0x9fa0:     /* procfs */
    case 0x62656572: /* sysfs */
    case 0x1cd1:     /* devpts */
    case 0x27e0eb:   /* cgroup */
    case 0x63677270: /* cgroup2 */
    case 0x64626720: /* debugfs */
    case 0x74726163: /* tracefs */
    case 0x73636673: /* securityfs */
    case 0x19800202: /* mqueue */
    case 0x42494e4d: /* binfmt_misc */
        result |= 0x00101000; /* local kernel interface, MNT_DONTBROWSE */
        break;
    default:
        /* Network and unclassified filesystem types do not acquire MNT_LOCAL. */
        break;
    }
    return result;
}
#endif
