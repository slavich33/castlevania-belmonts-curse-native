#pragma once
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Every current diagnostic uses a fresh 0700 run directory. No default cwd,
 * user-data, TOTK environment or shared preferences folder is accepted. */
static inline void castlevania_private_dir(const char *path) {
    struct stat st;
    if(!path || lstat(path,&st) || !S_ISDIR(st.st_mode) ||
       st.st_uid!=getuid() || (st.st_mode&0777)!=0700)
        runtime_fail("Castlevania requires an owned 0700 run directory");
}
static inline const char *castlevania_run_root(void) {
    const char *root=getenv("CASTLEVANIA_RUN_ROOT");char resolved[PATH_MAX];
    if(!root || root[0]!='/' || !realpath(root,resolved) || strcmp(root,resolved))
        runtime_fail("Castlevania run root must be an absolute canonical directory");
    castlevania_private_dir(root);return root;
}
static inline const char *castlevania_run_directory(const char *key,const char *name) {
    const char *root=castlevania_run_root(),*value=getenv(key);char expected[PATH_MAX],actual[PATH_MAX];
    if(snprintf(expected,sizeof expected,"%s/%s",root,name)>=(int)sizeof expected ||
       !value || strcmp(value,expected) || !realpath(value,actual) || strcmp(value,actual))
        runtime_fail("Castlevania path is outside its isolated run directory");
    castlevania_private_dir(value);return value;
}
static inline const char *castlevania_profile_directory(void) {
    return castlevania_run_directory("CASTLEVANIA_PROFILE_DIR","profile");
}
static inline void castlevania_check_scratch(const char *marker_name,const char *log_name,int check_stderr) {
    const char *root=castlevania_run_root(),*token=getenv("CASTLEVANIA_RUN_TOKEN");char cwd[PATH_MAX];
    if(!getcwd(cwd,sizeof cwd) || strcmp(cwd,root))runtime_fail("diagnostic cwd must equal its isolated run root");
    if(!token || strlen(token)!=32)runtime_fail("loader run token missing");
    for(unsigned i=0;i<32;i++)if(!((token[i]>='0'&&token[i]<='9')||(token[i]>='a'&&token[i]<='f')))
        runtime_fail("loader run token malformed");
    char marker[PATH_MAX],expected[80],actual[80]={0};struct stat st;
    if(snprintf(marker,sizeof marker,"%s/%s",root,marker_name)>=(int)sizeof marker)
        runtime_fail("loader marker path too long");
    int fd=open(marker,O_RDONLY|O_NOFOLLOW);
    if(fd<0 || fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid!=getuid() || (st.st_mode&0777)!=0600)
        runtime_fail("loader owned marker missing");
    int n=snprintf(expected,sizeof expected,"%s %s\n",CASTLEVANIA_TITLE_ID_TEXT,token);
    ssize_t got=read(fd,actual,sizeof actual);close(fd);
    if(n<0 || got!=n || memcmp(actual,expected,(size_t)n))runtime_fail("loader marker mismatch");
    castlevania_run_directory("HOME","home");castlevania_run_directory("TMPDIR","tmp");
    castlevania_run_directory("XDG_CONFIG_HOME","config");castlevania_run_directory("XDG_CACHE_HOME","cache");
    castlevania_profile_directory();castlevania_run_directory("CASTLEVANIA_SAVE_DIR","saves");
    const char *logs=castlevania_run_directory("CASTLEVANIA_LOG_DIR","logs"),*log=getenv("CASTLEVANIA_LOG_FILE");
    char log_path[PATH_MAX];
    if(snprintf(log_path,sizeof log_path,"%s/%s",logs,log_name)>=(int)sizeof log_path || !log || strcmp(log,log_path))
        runtime_fail("Castlevania log path is outside its isolated run directory");
    if(check_stderr) {
        struct stat ls,err;
        if(lstat(log,&ls) || !S_ISREG(ls.st_mode) || ls.st_uid!=getuid() || (ls.st_mode&0777)!=0600 ||
           fstat(STDERR_FILENO,&err) || ls.st_dev!=err.st_dev || ls.st_ino!=err.st_ino)
            runtime_fail("host stderr must be the owned 0600 native-host.log");
    }
}
static inline void castlevania_check_loader_scratch(void) {
    castlevania_check_scratch(".castlevania-loader-run","native-loader.log",0);
}
static inline void castlevania_check_host_scratch(void) {
    if(!CASTLEVANIA_DIAGNOSTIC_BOOT)runtime_fail("diagnostic boot is disabled at compile time");
    castlevania_check_scratch(".castlevania-host-run","native-host.log",1);
}
