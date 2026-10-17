#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/openat.h>

#include <sys/fcntl.h>

#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>

#include <darlingserver/rpc.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/quarantine.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/fsevents.h>

#ifndef O_NOFOLLOW
#	define O_NOFOLLOW 0x0100
#endif
#ifndef O_CLOEXEC
#	define O_CLOEXEC 0x1000000
#endif
#ifndef O_DIRECTORY
#	define O_DIRECTORY 0x100000
#endif

extern int strcmp(const char *s1, const char *s2);
extern char* strcpy(char* dst, const char* src);

long sys_openat(int fd, const char* filename, int flags, unsigned int mode)
{
	CANCELATION_POINT();
	return sys_openat_nocancel(fd, filename, flags, mode);
}

long sys_openat_nocancel(int fd, const char* filename, int flags, unsigned int mode)
{
	int ret, linux_flags;
	if (!filename)
		return -EFAULT;

	linux_flags = oflags_bsd_to_linux(flags);

	if (sizeof(void*) == 4)
	{
		linux_flags |= LINUX_O_LARGEFILE;
	}

	// XNU /dev/random behaves like Linux /dev/urandom
	if (strcmp(filename, "/dev/fsevents") == 0)
		return fsevents_device_open(linux_flags);
	else if (strcmp(filename, "/dev/random") == 0)
		filename = "/dev/urandom";
	// Expected by launchd and CF
	else if (strcmp(filename, "/dev/autofs_nowait") == 0)
		filename = "/dev/null";
	else if (strcmp(filename, "/dev/console") == 0) {
		// redirect console output to darlingserver
		int err = dserver_rpc_console_open(&ret);
		if (err < 0) {
			__simple_printf("dserver_rpc_console_open failed internally: %d", err);
			__simple_abort();
		}
		if (err > 0) {
			ret = errno_linux_to_bsd(-err);
		}
		return ret;
	}

	struct vchroot_expand_args vc;
	vc.flags = (flags & BSD_O_SYMLINK || flags & BSD_O_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = atfd(fd);

	strcpy(vc.path, filename);
	ret = vchroot_expand(&vc);
	if (ret < 0) {
		return errno_linux_to_bsd(ret);
	}

	// when we're given O_SYMLINK, `oflags_bsd_to_linux` translates it into
	// O_NOFOLLOW and O_PATH
	// this is the only way to open the symlink itself on Linux
	// unfortunately, this presents additional challenges
	// only a select few Linux syscalls support O_PATH descriptors, which means
	// that for other syscalls, we either have to check for this and use an
	// `l` variant (e.g. `llistxattr` instead of `listxatrr`) or we're screwed

	int active = 0, created = 0;
	if (flags & BSD_O_CREAT) {
		active = quarantine_process_active();
		if (active < 0) return active;
	}
	if (active && (flags & BSD_O_CREAT) && !(linux_flags & LINUX_O_EXCL)) {
		// Distinguish an actual new inode without an access/stat race. The
		// second open must not create a replacement inode behind our back.
		for (unsigned attempt=0; attempt<8; ++attempt) {
			ret = LINUX_SYSCALL(__NR_openat, vc.dfd, vc.path, linux_flags|LINUX_O_EXCL, mode);
			if (ret >= 0) { created=1; break; }
			if (ret != -17) break;
			ret = LINUX_SYSCALL(__NR_openat, vc.dfd, vc.path, linux_flags&~LINUX_O_CREAT, mode);
			if (ret != -2) break;
			if (attempt==7) ret=-11;
		}
	} else {
		ret = LINUX_SYSCALL(__NR_openat, vc.dfd, vc.path, linux_flags, mode);
		created = active && (flags & BSD_O_CREAT) && (linux_flags & LINUX_O_EXCL) && ret>=0;
	}
	if (created) quarantine_created_fd(ret);
	else if (ret>=0 && ((flags&3) || (flags&BSD_O_TRUNC))) quarantine_changed_fd(ret,1);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
