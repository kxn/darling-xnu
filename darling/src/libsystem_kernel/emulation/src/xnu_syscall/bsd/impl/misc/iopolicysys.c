#include <darling/emulation/xnu_syscall/bsd/impl/misc/iopolicysys.h>

#include <sys/errno.h>
#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/common/tsd.h>

struct darling_iopol_param {
	int scope;
	int type;
	int policy;
};

long sys_iopolicysys(int cmd, void* arg)
{
	if (!arg) return -EFAULT;
	struct darling_iopol_param* param = arg;
	if (cmd != 1 && cmd != 2) return -EINVAL;
	if (param->type < 0 || param->type > 8) return -EINVAL;
	// Scheduling, atime and permission policies need their own Linux backend.
	// Do not report that those policies have been applied.
	if (param->type != 3) return -ENOTSUP;
	if (param->scope != 0 && param->scope != 1) return -EINVAL;
	// Process policy must survive exec; it cannot be a library-local variable.
	if (param->scope == 0) return -ENOTSUP;
	if (cmd == 2) {
		if (param->policy < 0 || param->policy > 2) return -EINVAL;
		_pthread_setspecific_direct(__PTK_DARLING_MATERIALIZE_POLICY, param->policy);
	} else {
		param->policy = _pthread_getspecific_direct(__PTK_DARLING_MATERIALIZE_POLICY);
	}
	// This is the caller's per-thread permission state. Darling currently
	// exposes no dataless file/provider implementation; setting ON does not
	// claim to fetch data or materialize a file.
	return 0;
}
