#ifndef _VCHROOT_EXPAND_H
#define _VCHROOT_EXPAND_H

#define VCHROOT_FOLLOW	1
struct vchroot_expand_args
{
	char path[4096]; // contains evaluated path on return
	unsigned int flags;
	int dfd; // base directory when path is relative
};

struct vchroot_fdpath_args
{
	int fd;
	char* path;
	unsigned int maxlen;
};

struct vchroot_unexpand_args
{
	char path[4096];
};

int vchroot_expand(struct vchroot_expand_args* args);
// Copy a Darwin user pathname before expansion; returns Linux negative errno.
int vchroot_copy_path(struct vchroot_expand_args* args,const char* path);
int vchroot_unexpand(struct vchroot_unexpand_args* args);
int vchroot_fdpath(struct vchroot_fdpath_args* args);

#endif // _VCHROOT_EXPAND_H
