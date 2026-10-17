/* Shared path/FD implementation. Darwin field order and four-byte packing
 * follow XNU bsd/vfs/vfs_attrlist.c. Unavailable metadata is never advertised
 * in ATTR_CMN_RETURNED_ATTRS. No CoreTypes-specific paths or values. */
#include <stddef.h>
#include <stdint.h>
#include <sys/errno.h>
#include <sys/attr.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/conversion/dirent/getdirentries.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/xattr/metadata_linux.h>
extern void *memcpy(void *, const void *, __SIZE_TYPE__);
extern void *memset(void *, int, __SIZE_TYPE__);
extern __SIZE_TYPE__ strlen(const char *);
extern __SIZE_TYPE__ strlcpy(char *, const char *, __SIZE_TYPE__);
struct metadata_field {
    uint32_t bit; unsigned group, size, valid;
    unsigned char data[40]; const char *string;
};
static unsigned metadata_type(unsigned mode) {
    switch (mode & 0170000) {
        case 0100000:return 1; case 0040000:return 2; case 0060000:return 3;
        case 0020000:return 4; case 0120000:return 5; case 0140000:return 6;
        case 0010000:return 7; default:return 0;
    }
}
static uint32_t metadata_dev(unsigned major,unsigned minor) {return (minor&255)|(major<<8)|((minor&~255U)<<12);}
static void metadata_u32(struct metadata_field *f,uint32_t v) {memcpy(f->data,&v,4);f->valid=1;}
static void metadata_u64(struct metadata_field *f,uint64_t v) {memcpy(f->data,&v,8);f->valid=1;}
static void metadata_time(struct metadata_field *f,const struct metadata_linux_time *t) {
#ifdef __LP64__
    int64_t v[2]={t->sec,t->nsec};memcpy(f->data,v,16);
#else
    int32_t v[2]={t->sec,t->nsec};memcpy(f->data,v,8);
#endif
    f->valid=1;
}
static long metadata_children(int fd) {
    /* dup shares the directory offset; openat creates an independent cursor. */
    int directory=LINUX_SYSCALL(__NR_openat,fd,".",LINUX_O_RDONLY|LINUX_O_DIRECTORY|LINUX_O_CLOEXEC,0);
    if(directory<0)return directory;
    char buffer[4096];long result=0,count=0;
    while((result=LINUX_SYSCALL(__NR_getdents64,directory,buffer,sizeof(buffer)))>0) {
        for(long at=0;at<result;) {
            struct linux_dirent64 *e=(void*)(buffer+at);
            if(result-at<20||e->d_reclen<20||e->d_reclen>result-at) {result=-5;goto out;}
            const char *n=e->d_name;
            if(!(n[0]=='.'&&(n[1]==0||(e->d_reclen>=22&&n[1]=='.'&&n[2]==0))))count++;
            at+=e->d_reclen;
        }
    }
out:
    LINUX_SYSCALL(__NR_close,directory);return result<0?result:count;
}
long FUNC_NAME(int fd,
#if HAS_PATH
    const char *path,
#endif
    struct xnu_attrlist *alist,void *attributeBuffer,__SIZE_TYPE__ bufferSize,unsigned long options)
{
    if(!alist)return -EFAULT;
    if(!bufferSize||alist->bitmapcount!=5||alist->reserved)return -EINVAL;
    if(!attributeBuffer)return -EFAULT;
    if(options&~(FSOPT_NOFOLLOW|FSOPT_NOINMEMUPDATE|FSOPT_REPORT_FULLSIZE|FSOPT_PACK_INVAL_ATTRS|FSOPT_ATTR_CMN_EXTENDED|FSOPT_NOFIRMLINKPATH|FSOPT_RETURN_REALDEV))return -EINVAL;
    int returned=!!(alist->commonattr&ATTR_CMN_RETURNED_ATTRS),invalid=!!(options&FSOPT_PACK_INVAL_ATTRS);
    if(invalid&&!returned)return -EINVAL;
    if(alist->volattr&~ATTR_VOL_VALIDMASK)return -EINVAL;
    if(alist->volattr&&(alist->dirattr||alist->fileattr||alist->forkattr))return -EINVAL;
    if(alist->volattr&~(ATTR_VOL_INFO|ATTR_VOL_CAPABILITIES|ATTR_VOL_ATTRIBUTES))return -ENOTSUP;
    if((alist->dirattr&~ATTR_DIR_VALIDMASK)||(alist->fileattr&~ATTR_FILE_VALIDMASK))return -EINVAL;
    if(alist->forkattr&&(!(options&FSOPT_ATTR_CMN_EXTENDED)||(alist->forkattr&~ATTR_CMNEXT_VALIDMASK)))return -EINVAL;
    if((alist->commonattr&(ATTR_CMN_GEN_COUNT|ATTR_CMN_DOCUMENT_ID))&&!(options&FSOPT_ATTR_CMN_EXTENDED))return -EINVAL;
    struct metadata_linux_statx sx;
    int statfd,statflags,objectfd=-1;const char *linux_path;
#if HAS_PATH
    if(!path)return -EFAULT;
    struct vchroot_expand_args vc;
    vc.flags=(options&FSOPT_NOFOLLOW)?0:VCHROOT_FOLLOW;vc.dfd=atfd(fd);
    if(strlcpy(vc.path,path,sizeof(vc.path))>=sizeof(vc.path))return -ENAMETOOLONG;
    int expanded=vchroot_expand(&vc);if(expanded<0)return errno_linux_to_bsd(expanded);
    statfd=vc.dfd;linux_path=vc.path;statflags=(options&FSOPT_NOFOLLOW)?LINUX_AT_SYMLINK_NOFOLLOW:0;
#else
    statfd=fd;linux_path="";statflags=LINUX_AT_EMPTY_PATH;
#endif
    long rv=LINUX_SYSCALL(__NR_statx,statfd,linux_path,statflags,0xfff,&sx);
    if(rv<0)return errno_linux_to_bsd(rv);
    unsigned type=metadata_type(sx.mode),isdir=type==2;
    char fullpath[4096]={0};int fullpath_valid=0;
    struct linux_statfs64 fs={0};int fs_valid=0;
    uint64_t parent_ino=0;int parent_valid=0;
    uint32_t device=metadata_dev(sx.dev_major,sx.dev_minor);
    int device_valid=sx.dev_major<=4095&&sx.dev_minor<=0xfffff;
    uint32_t need_path=ATTR_CMN_NAME|ATTR_CMN_FULLPATH|ATTR_CMN_PARENTID|ATTR_CMN_PAROBJID;
    if((alist->commonattr&(need_path|ATTR_CMN_FSID|ATTR_CMN_OBJTAG))||(alist->forkattr&(ATTR_CMNEXT_NOFIRMLINKPATH|ATTR_CMNEXT_REALFSID))||(isdir&&(alist->dirattr&ATTR_DIR_ENTRYCOUNT))) {
#if HAS_PATH
        /* Linux O_PATH adds no file-read permission requirement. */
        objectfd=LINUX_SYSCALL(__NR_openat,statfd,linux_path,0x200000|LINUX_O_CLOEXEC|((options&FSOPT_NOFOLLOW)?LINUX_O_NOFOLLOW:0),0);
        if(objectfd<0)return errno_linux_to_bsd(objectfd);
#else
        objectfd=fd;
#endif
        fs_valid=LINUX_SYSCALL(__NR_fstatfs,objectfd,&fs)==0&&device_valid;
        if(fs_valid)fs.f_fsid=darling_statfs_fsid(device,fs.f_type);
        struct vchroot_fdpath_args fp={.fd=objectfd,.path=fullpath,.maxlen=sizeof(fullpath)};
        fullpath_valid=sx.nlink&&vchroot_fdpath(&fp)==0;
        if(fullpath_valid&&(alist->commonattr&(ATTR_CMN_PARENTID|ATTR_CMN_PAROBJID))) {
            struct vchroot_expand_args parent;strlcpy(parent.path,fullpath,sizeof(parent.path));
            size_t n=strlen(parent.path);while(n>1&&parent.path[n-1]!='/')n--;parent.path[n>1?n-1:1]=0;
            parent.flags=VCHROOT_FOLLOW;parent.dfd=LINUX_AT_FDCWD;
            struct metadata_linux_statx ps;
            if(vchroot_expand(&parent)==0&&LINUX_SYSCALL(__NR_statx,parent.dfd,parent.path,0,0x100,&ps)==0&&(ps.mask&0x100)){parent_ino=ps.ino;parent_valid=1;}
        }
    }
    char *name=fullpath;
    if(fullpath_valid){size_t n=strlen(fullpath);while(n>1&&fullpath[n-1]!='/')n--;if(fullpath[n])name=fullpath+n;}
    unsigned char finder[32]={0};int finder_valid=0;
    long resource_length=-1;
    if(alist->commonattr&ATTR_CMN_FNDRINFO) {
#if HAS_PATH
        rv=(options&FSOPT_NOFOLLOW)?LINUX_SYSCALL(__NR_lgetxattr,linux_path,"user.com.apple.FinderInfo",finder,32):LINUX_SYSCALL(__NR_getxattr,linux_path,"user.com.apple.FinderInfo",finder,32);
#else
        rv=LINUX_SYSCALL(__NR_fgetxattr,fd,"user.com.apple.FinderInfo",finder,32);
#endif
        finder_valid=rv==32;
        /* XNU compatible requests default absent FinderInfo to zero. */
        if(!returned&&(rv==-61||rv==-95||rv==-1))finder_valid=1;
    }
    if(!isdir&&(alist->fileattr&(ATTR_FILE_RSRCLENGTH|ATTR_FILE_TOTALSIZE|ATTR_FILE_ALLOCSIZE))) {
#if HAS_PATH
        resource_length=(options&FSOPT_NOFOLLOW)?LINUX_SYSCALL(__NR_lgetxattr,linux_path,"user.com.apple.ResourceFork",NULL,0):LINUX_SYSCALL(__NR_getxattr,linux_path,"user.com.apple.ResourceFork",NULL,0);
#else
        resource_length=LINUX_SYSCALL(__NR_fgetxattr,fd,"user.com.apple.ResourceFork",NULL,0);
#endif
        if(resource_length==-61)resource_length=0;
    }
    long children=-1;
    if(isdir&&(alist->dirattr&ATTR_DIR_ENTRYCOUNT))children=metadata_children(objectfd);
#if HAS_PATH
    if(objectfd>=0)LINUX_SYSCALL(__NR_close,objectfd);
#endif
    static const unsigned char common_size[31]={8,4,8,4,4,8,8,8,4,16,16,16,16,16,32,4,4,4,4,4,4,4,8,16,16,8,8,8,16,4,4};
    static const unsigned char dir_size[6]={4,4,4,8,4,8};
    static const unsigned char file_size[14]={4,8,8,4,4,4,4,4,8,8,8,0,8,8};
    static const unsigned char ext_size[11]={0,0,8,8,8,8,4,8,8,8,8};
    uint32_t requested[5]={alist->commonattr,alist->volattr&~ATTR_VOL_INFO,isdir?alist->dirattr:0,isdir?0:alist->fileattr,alist->forkattr};
    struct metadata_field fields[64];unsigned count=0;
    for(unsigned group=0;group<5;group++)for(unsigned bit=0;bit<32;bit++) {
        uint32_t flag=(uint32_t)1<<bit;
        if(!(requested[group]&flag)||(group==0&&bit==31))continue;
        struct metadata_field *f=&fields[count++];memset(f,0,sizeof(*f));f->group=group;f->bit=flag;
        if(group==0) {
            f->size=common_size[bit];
#ifndef __LP64__
            if((bit>=9&&bit<=13)||bit==28)f->size=8;
#endif
            switch(bit) {
                case 0:f->string=name;f->valid=fullpath_valid;break;
                case 1:metadata_u32(f,device);f->valid=device_valid;break;
                case 2:memcpy(f->data,&fs.f_fsid,8);f->valid=fs_valid;break;
                case 3:metadata_u32(f,type);f->valid=!!(sx.mask&1);break;
                case 4:metadata_u32(f,24);break; /* VT_OTHER, not HFS/APFS. */
                case 5:case 6:metadata_u32(f,sx.ino);f->valid=!!(sx.mask&0x100);break;
                case 7:metadata_u32(f,parent_ino);f->valid=parent_valid;break;
                case 9:metadata_time(f,&sx.btime);f->valid=!!(sx.mask&0x800);break;
                case 10:metadata_time(f,&sx.mtime);f->valid=!!(sx.mask&0x40);break;
                case 11:metadata_time(f,&sx.ctime);f->valid=!!(sx.mask&0x80);break;
                case 12:metadata_time(f,&sx.atime);f->valid=!!(sx.mask&0x20);break;
                case 14:memcpy(f->data,finder,32);f->valid=finder_valid;break;
                case 15:metadata_u32(f,sx.uid);f->valid=!!(sx.mask&8);break;
                case 16:metadata_u32(f,sx.gid);f->valid=!!(sx.mask&16);break;
                case 17:metadata_u32(f,sx.mode);f->valid=!!(sx.mask&2);break;
                case 18:{uint64_t a=sx.attributes&sx.attributes_mask;metadata_u32(f,((a&0x10)?2:0)|((a&0x20)?4:0)|((a&0x40)?1:0));break;}
                case 25:metadata_u64(f,sx.ino);f->valid=!!(sx.mask&0x100);break;
                case 26:metadata_u64(f,parent_ino);f->valid=parent_valid;break;
                case 27:f->string=fullpath;f->valid=fullpath_valid;break;
                case 29:f->valid=!returned||invalid;break;
            }
        } else if(group==1) {
            if(flag==ATTR_VOL_CAPABILITIES) {
                vol_capabilities_attr_t caps={0};
                /* The attrlist interface is provided here. Readdirattr is
                 * absent. Other filesystem features remain unknown, rather
                 * than being guessed from a Linux filesystem magic number. */
                caps.capabilities[VOL_CAPABILITIES_INTERFACES]=VOL_CAP_INT_ATTRLIST;
                caps.valid[VOL_CAPABILITIES_INTERFACES]=VOL_CAP_INT_ATTRLIST|VOL_CAP_INT_READDIRATTR;
                memcpy(f->data,&caps,sizeof(caps));f->size=sizeof(caps);f->valid=1;
            } else if(flag==ATTR_VOL_ATTRIBUTES) {
                vol_attributes_attr_t supported={0};
                supported.validattr.commonattr=ATTR_CMN_NAME|ATTR_CMN_DEVID|ATTR_CMN_FSID|ATTR_CMN_OBJTYPE|ATTR_CMN_OBJTAG|ATTR_CMN_OBJID|ATTR_CMN_OBJPERMANENTID|ATTR_CMN_PAROBJID|ATTR_CMN_MODTIME|ATTR_CMN_CHGTIME|ATTR_CMN_ACCTIME|ATTR_CMN_FNDRINFO|ATTR_CMN_OWNERID|ATTR_CMN_GRPID|ATTR_CMN_ACCESSMASK|ATTR_CMN_FLAGS|ATTR_CMN_FILEID|ATTR_CMN_PARENTID|ATTR_CMN_FULLPATH|ATTR_CMN_ERROR|ATTR_CMN_RETURNED_ATTRS;
                if(sx.mask&0x800)supported.validattr.commonattr|=ATTR_CMN_CRTIME;
                supported.validattr.volattr=ATTR_VOL_INFO|ATTR_VOL_CAPABILITIES|ATTR_VOL_ATTRIBUTES;
                supported.validattr.dirattr=ATTR_DIR_LINKCOUNT|ATTR_DIR_ENTRYCOUNT|ATTR_DIR_ALLOCSIZE|ATTR_DIR_IOBLOCKSIZE|ATTR_DIR_DATALENGTH;
                if(sx.attributes_mask&0x2000)supported.validattr.dirattr|=ATTR_DIR_MOUNTSTATUS;
                supported.validattr.fileattr=ATTR_FILE_LINKCOUNT|ATTR_FILE_TOTALSIZE|ATTR_FILE_IOBLOCKSIZE|ATTR_FILE_DEVTYPE|ATTR_FILE_DATALENGTH|ATTR_FILE_DATAALLOCSIZE|ATTR_FILE_RSRCLENGTH;
                /* Native fields are precisely the Linux statx-backed subset;
                 * FinderInfo, directory counts and pathname reconstruction
                 * are supplied by the compatibility implementation. */
                supported.nativeattr.commonattr=supported.validattr.commonattr&~(ATTR_CMN_NAME|ATTR_CMN_FSID|ATTR_CMN_OBJTAG|ATTR_CMN_FNDRINFO|ATTR_CMN_PARENTID|ATTR_CMN_PAROBJID|ATTR_CMN_FULLPATH|ATTR_CMN_ERROR|ATTR_CMN_RETURNED_ATTRS);
                supported.nativeattr.dirattr=supported.validattr.dirattr&~ATTR_DIR_ENTRYCOUNT;
                supported.nativeattr.fileattr=ATTR_FILE_LINKCOUNT|ATTR_FILE_IOBLOCKSIZE|ATTR_FILE_DEVTYPE|ATTR_FILE_DATALENGTH|ATTR_FILE_DATAALLOCSIZE;
                memcpy(f->data,&supported,sizeof(supported));f->size=sizeof(supported);f->valid=1;
            }
        } else if(group==2) {
            f->size=dir_size[bit];
            if(bit==0){metadata_u32(f,sx.nlink);f->valid=!!(sx.mask&4);}
            if(bit==1&&children>=0)metadata_u32(f,children);
            if(bit==2&&(sx.attributes_mask&0x2000))metadata_u32(f,!!(sx.attributes&0x2000));
            if(bit==3){metadata_u64(f,sx.blocks*512);f->valid=!!(sx.mask&0x400);}
            if(bit==4)metadata_u32(f,sx.blksize);
            if(bit==5){metadata_u64(f,sx.size);f->valid=!!(sx.mask&0x200);}
        } else if(group==3) {
            f->size=file_size[bit];
            if(bit==0){metadata_u32(f,sx.nlink);f->valid=!!(sx.mask&4);}
            if(bit==1&&resource_length>=0){metadata_u64(f,sx.size+resource_length);f->valid=!!(sx.mask&0x200);}
            if(bit==2&&resource_length==0){metadata_u64(f,sx.blocks*512);f->valid=!!(sx.mask&0x400);}
            if(bit==3)metadata_u32(f,sx.blksize);
            if(bit==5){metadata_u32(f,metadata_dev(sx.rdev_major,sx.rdev_minor));f->valid=sx.rdev_major<=4095&&sx.rdev_minor<=0xfffff;}
            if(bit==9){metadata_u64(f,sx.size);f->valid=!!(sx.mask&0x200);}
            if(bit==10){metadata_u64(f,sx.blocks*512);f->valid=!!(sx.mask&0x400);}
            if(bit==12&&resource_length>=0)metadata_u64(f,resource_length);
        } else if(group==4) {
            f->size=ext_size[bit];
            if(bit==4){metadata_u64(f,sx.ino);f->valid=!!(sx.mask&0x100);}
            if(bit==5){f->string=fullpath;f->valid=fullpath_valid;}
            if(bit==6){metadata_u32(f,device);f->valid=device_valid;}
            if(bit==7){memcpy(f->data,&fs.f_fsid,8);f->valid=fs_valid;}
        }
        if(!f->size)return -EINVAL;
        if(!f->valid&&!returned)return -EINVAL;
    }
    /* XNU packs ERROR immediately after the optional returned-attribute set. */
    for(unsigned i=0;i<count;i++)if(fields[i].group==0&&fields[i].bit==ATTR_CMN_ERROR) {
        struct metadata_field e=fields[i];for(unsigned j=i;j;j--)fields[j]=fields[j-1];fields[0]=e;break;
    }
    uint32_t actual[5]={returned?ATTR_CMN_RETURNED_ATTRS:0,alist->volattr&ATTR_VOL_INFO,0,0,0};
    size_t fixed=4+(returned?20:0),variable=0;
    for(unsigned i=0;i<count;i++) {
        struct metadata_field *f=&fields[i];if(f->valid)actual[f->group]|=f->bit;
        if(f->valid||invalid){fixed+=f->size;if(f->string&&f->valid)variable+=(strlen(f->string)+4)&~(size_t)3;}
    }
    unsigned char buffer[16384];size_t needed=fixed+variable;
    if(needed>sizeof(buffer))return -EOVERFLOW;
    memset(buffer,0,needed);
    uint32_t length=(options&FSOPT_REPORT_FULLSIZE)?needed:(bufferSize<needed?bufferSize:needed);
    memcpy(buffer,&length,4);if(returned)memcpy(buffer+4,actual,20);
    size_t at=4+(returned?20:0),tail=fixed;
    for(unsigned i=0;i<count;i++) {
        struct metadata_field *f=&fields[i];if(!f->valid&&!invalid)continue;
        if(f->valid) {
            if(f->string){int32_t offset=tail-at;uint32_t size=strlen(f->string)+1;memcpy(buffer+at,&offset,4);memcpy(buffer+at+4,&size,4);memcpy(buffer+tail,f->string,size);tail+=(size+3)&~(size_t)3;}
            else memcpy(buffer+at,f->data,f->size);
        }
        at+=f->size;
    }
    memcpy(attributeBuffer,buffer,bufferSize<needed?bufferSize:needed);
    return 0;
}
