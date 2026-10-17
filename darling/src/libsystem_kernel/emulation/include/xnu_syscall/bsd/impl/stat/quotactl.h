#ifndef DARLING_SYS_QUOTACTL_H
#define DARLING_SYS_QUOTACTL_H
long sys_quotactl(const char *path, int command, int id, void *data);
#endif
