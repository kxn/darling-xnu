/* Apple xnu f6217f891ac0bb64f3d375211650a4c1ff8ca1ea private header
 * definitions required by its unchanged statfs_ext wrapper. The older Darling
 * getattrlist backend correctly rejects these newer volume bits with EINVAL;
 * Apple's wrapper then follows its documented statfs/fstatfs fallback. */
#ifndef DARLING_STATFS_EXT_COMPAT_H
#define DARLING_STATFS_EXT_COMPAT_H
#ifndef STATFS_EXT_NOBLOCK
#define STATFS_EXT_NOBLOCK 0x0001
#endif
#ifndef ATTR_VOL_MOUNTEXTFLAGS
#define ATTR_VOL_MOUNTEXTFLAGS 0x00080000
#define ATTR_VOL_FSTYPENAME    0x00100000
#define ATTR_VOL_FSSUBTYPE     0x00200000
#define ATTR_VOL_OWNER        0x00400000
#endif
#endif
