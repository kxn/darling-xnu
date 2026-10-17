#ifndef DARLING_EMULATION_FSEVENTS_H
#define DARLING_EMULATION_FSEVENTS_H
int fsevents_device_open(int linux_flags);
int fsevents_device_ioctl(int fd,unsigned command,void* argument,int* result);
int fsevents_device_read(int fd,void* buffer,int length,int* result);
#endif
