#ifndef LINUX_EXECVE_H
#define LINUX_EXECVE_H

long sys_execve(const char* fname, const char** argvp, const char** envp);
long sys_execve_disclaim(const char* fname, const char** argvp, const char** envp);

#endif // LINUX_EXECVE_H
