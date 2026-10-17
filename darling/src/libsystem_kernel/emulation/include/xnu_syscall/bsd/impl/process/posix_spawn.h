#ifndef LINUX_POSIX_SPAWN_H
#define LINUX_POSIX_SPAWN_H

#include <darling/emulation/conversion/process/posix_spawn.h>

struct xnu_spawn_mac_extension {
	char policyname[128];
	uint64_t data;
	uint64_t datalen;
};

struct xnu_spawn_mac_extensions {
	int alloc;
	int count;
	struct xnu_spawn_mac_extension extensions[];
};

// See [xnu]/libsyscall/wrappers/spawn/posix_spawn.c
struct _posix_spawn_args_desc
{
	unsigned long attr_size;
	const xnu_posix_spawnattr_t attrp;
	unsigned long fact_size;
	const xnu_posix_spawn_file_actions_t factp;
	unsigned long port_actions_size;
	void* pactp;
	unsigned long mac_extensions_size;
	const struct xnu_spawn_mac_extensions* mac_extensions;
};

long sys_posix_spawn(int* pid, const char* path, const struct _posix_spawn_args_desc* desc,
		char** argvp, char** envp);

#endif // LINUX_POSIX_SPAWN_H
