/* One diagnostic host at a time. The runner selects an explicit machine-wide
 * owned state directory; no source-tree fallback, donor queue or preemption. */
#include "runtime.h"
#include "castlevania_policy.h"
#include "castlevania_paths.h"
#include <errno.h>
#include <sys/file.h>

void runtime_game_slot_acquire(const char *mode) {
    static int held_fd=-1;
    if(held_fd>=0)return;
    castlevania_check_host_scratch();
    if(!mode||strcmp(mode,"boot"))runtime_fail("Castlevania slot is only for diagnostic boot");
    const char *dir=getenv("CASTLEVANIA_GAME_SLOT_DIR");char canonical[PATH_MAX],path[PATH_MAX];
    if(!dir||dir[0]!='/'||!realpath(dir,canonical)||strcmp(dir,canonical))
        runtime_fail("explicit canonical CASTLEVANIA_GAME_SLOT_DIR is required");
    castlevania_private_dir(dir);
    /* A per-run lock would let two hosts run together. Retain machine state
       outside the scratch/data/source views, chosen explicitly by the runner. */
    const char *run=castlevania_run_root();size_t n=strlen(run);
    if(!strncmp(dir,run,n)&&(dir[n]=='/'||dir[n]==0))
        runtime_fail("machine game slot must be outside the individual run directory");
    if(snprintf(path,sizeof path,"%s/lock",dir)>=(int)sizeof path)runtime_fail("game slot path too long");
    int fd=open(path,O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);struct stat st;
    if(fd<0||fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=getuid()||(st.st_mode&0777)!=0600)
        runtime_fail("machine game slot requires an owned regular 0600 lock");
    if(flock(fd,LOCK_EX|LOCK_NB)) {
        int cause=errno;
        close(fd);
        if(cause==EWOULDBLOCK)runtime_fail("machine game slot is held; diagnostic host not started");
        runtime_fail("cannot acquire machine game slot");
    }
    held_fd=fd; /* Kernel releases the flock on process exit; never stop a holder. */
    fprintf(stderr,"[castlevania] acquired explicit machine game slot\n");
}
