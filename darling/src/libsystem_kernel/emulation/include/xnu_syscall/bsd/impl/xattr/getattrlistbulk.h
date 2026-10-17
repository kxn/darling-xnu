#ifndef LINUX_GETATTRLISTBULK_H
#define LINUX_GETATTRLISTBULK_H
#include <darling/emulation/conversion/xattr/getattrlist.h>
#include <stddef.h>
long sys_getattrlistbulk(int, struct xnu_attrlist *, void *, size_t, unsigned long);
#endif
