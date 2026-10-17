#include <darling/emulation/xnu_syscall/bsd/impl/unistd/renameat.h>

#include <sys/errno.h>

#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/quarantine.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/sandbox_fs.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/conversion/common_at.h>

extern char* strcpy(char* dst, const char* src);

long sys_renameat(int oldfd, const char* oldpath, int newfd, const char* newpath)
{
	int ret;
	struct vchroot_expand_args vc, vc2;

	vc.flags = 0;
	vc.dfd = atfd(oldfd);
	
	ret = sandbox_fs_copy_path(vc.path, sizeof vc.path, oldpath);
	if (ret < 0) return ret;

	vc2.flags = 0;
	vc2.dfd = atfd(newfd);

	ret = sandbox_fs_copy_path(vc2.path, sizeof vc2.path, newpath);
	if (ret < 0) return ret;

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	ret = vchroot_expand(&vc2);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	struct sandbox_fs_path source, target;
	ret = sandbox_fs_prepare(&vc, &source);
	if (ret < 0) return ret;
	ret = sandbox_fs_prepare(&vc2, &target);
	if (ret < 0) { sandbox_fs_close(&source); return ret; }
	struct linux_stat info;
	long exists = LINUX_SYSCALL(__NR_newfstatat, target.directory, target.leaf, &info, LINUX_AT_SYMLINK_NOFOLLOW);
	if (exists < 0 && exists != -2) ret = errno_linux_to_bsd(exists);
	if (!ret) ret = sandbox_fs_authorize("file-write-unlink", &source);
	if (!ret) ret = sandbox_fs_authorize("file-write-create", &target);
	if (!ret && !exists) ret = sandbox_fs_authorize("file-write-unlink", &target);
	if (!ret) {
		ret = LINUX_SYSCALL(__NR_renameat, source.directory, source.leaf, target.directory, target.leaf);
		if (ret < 0) ret = errno_linux_to_bsd(ret);
		else quarantine_changed_path(target.directory, target.leaf, 1, 2);
	}
	sandbox_fs_close(&source);
	sandbox_fs_close(&target);
	return ret;
}
