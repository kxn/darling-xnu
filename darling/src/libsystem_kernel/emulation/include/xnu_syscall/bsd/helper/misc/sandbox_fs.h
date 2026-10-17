#ifndef DARLING_SANDBOX_FS_H
#define DARLING_SANDBOX_FS_H
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <stddef.h>
struct sandbox_fs_path {
    int directory;
    const char *leaf; /* borrowed from the expanded path until close */
    struct vchroot_unexpand_args name;
};
/* Functions return zero or a negative Darwin errno. */
int sandbox_fs_copy_path(char *destination, size_t capacity, const char *source);
int sandbox_fs_prepare(const struct vchroot_expand_args *expanded, struct sandbox_fs_path *result);
int sandbox_fs_authorize(const char *operation, const struct sandbox_fs_path *path);
void sandbox_fs_close(struct sandbox_fs_path *path);
#endif
