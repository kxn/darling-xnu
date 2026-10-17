#include <darling/emulation/xnu_syscall/bsd/impl/stat/mkdirat.h>

#include <sys/errno.h>

#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/quarantine.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/sandbox_fs.h>

extern char* strcpy(char* dst, const char* src);

long sys_mkdirat(int fd, const char* path, unsigned int mode)
{
	int ret;
	struct vchroot_expand_args vc;

	if (!path)
		return -EFAULT;

	vc.flags = 0;
	vc.dfd = atfd(fd);
	
	ret = sandbox_fs_copy_path(vc.path, sizeof vc.path, path);
	if (ret < 0) return ret;

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	struct sandbox_fs_path target;
	ret = sandbox_fs_prepare(&vc, &target);
	if (ret < 0) return ret;
	ret = sandbox_fs_authorize("file-write-create", &target);
	if (!ret) {
		ret = LINUX_SYSCALL(__NR_mkdirat, target.directory, target.leaf, mode);
		if (ret < 0) ret = errno_linux_to_bsd(ret);
		else quarantine_created_path(target.directory, target.leaf, 1);
	}
	sandbox_fs_close(&target);
	return ret;
}
