/* Bounded native loader probe derived from Ori loader.c at f5a03fead9c40.
 * This executable has no path that calls guest instructions, HLE services,
 * constructors, nnMain, graphics, audio, profiles or save files. */
#if !defined(GAME_CASTLEVANIA) || !defined(__aarch64__)
#error "This target requires GAME_CASTLEVANIA on native ARM64"
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libkern/OSCacheControl.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach/mach.h>
#include "mach_vm_compat.h"
#include "runtime.h"
#include "castlevania_policy.h"
#include "castlevania_paths.h"
#include "runtime_tables.h"
#define NM (sizeof(modules)/sizeof(modules[0]))
static pthread_key_t keys[8];
static unsigned checked_relocations, checked_permissions, missing_weak_kinds;
static const char *missing_weak[3];

_Noreturn void runtime_fail(const char *message) {
    fprintf(stderr,"[castlevania-loader] FAIL: %s\n",message);
    exit(1);
}
static void need(bool ok,const char *message) { if(!ok)runtime_fail(message); }
static size_t page_up(size_t n) { return (n+0x3fff)&~(size_t)0x3fff; }
static uint64_t image_end(const Module *m) { return page_up(m->file_size-m->pre); }
static unsigned hash_name(const char *s) {
    unsigned h=2166136261u;
    for(;*s;s++)h=(h^(uint8_t)*s)*16777619u;
    return h;
}
static void make_hash(Module *m) {
    unsigned cap=16;
    while(cap<m->nsym*2)cap<<=1;
    m->hash=calloc(cap,sizeof(unsigned));need(m->hash!=NULL,"symbol hash allocation");m->hash_mask=cap-1;
    for(unsigned i=1;i<m->nsym;i++)if(m->symbols[i].defined) {
        unsigned p=hash_name(m->symbols[i].name)&m->hash_mask;
        while(m->hash[p]&&strcmp(m->symbols[m->hash[p]].name,m->symbols[i].name))p=(p+1)&m->hash_mask;
        if(!m->hash[p])m->hash[p]=i;
    }
}
static void *module_symbol(Module *m,const char *name) {
    unsigned p=hash_name(name)&m->hash_mask;
    while(m->hash[p]) {
        const Symbol *s=&m->symbols[m->hash[p]];
        if(!strcmp(name,s->name))return s->value<m->key_off?m->base+s->value:NULL;
        p=(p+1)&m->hash_mask;
    }
    return NULL;
}
void *runtime_symbol(const char *name) {
    for(unsigned i=0;i<NM;i++) {void *p=module_symbol(&modules[i],name);if(p)return p;}
    return NULL;
}
static void map_module(Module *m,const char *directory) {
    char path[4096];need(snprintf(path,sizeof(path),"%s/%s.patched.bin",directory,m->name)<(int)sizeof(path),"module path");
    FILE *f=fopen(path,"rb");need(f!=NULL,"open completed AOT module read-only");
    struct stat st;need(fstat(fileno(f),&st)==0&&(size_t)st.st_size==m->file_size,"AOT module size");
    need(m->pre%0x4000==0&&m->pre<m->file_size,"PRE layout");
    m->size=image_end(m); /* No extra title-specific writable patch/data page. */
    uint8_t *lo=mmap(NULL,m->pre+m->size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    need(lo!=MAP_FAILED,"map private module");need(fread(lo,1,m->file_size,f)==m->file_size,"read AOT module");need(fclose(f)==0,"close AOT module");
    m->base=lo+m->pre;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];char hex[65];
    CC_SHA256(lo,(CC_LONG)m->file_size,digest);
    for(unsigned i=0;i<sizeof(digest);i++)snprintf(hex+i*2,3,"%02x",digest[i]);
    need(!strcmp(hex,m->digest),"AOT SHA256 differs from exact verified rewrite");
    need(m->key_off%0x4000==0&&m->key_off+0x4000<=image_end(m),"key page bounds");
    need(m->pre?m->patch_off==-m->pre:m->key_off+0x4000<=m->patch_off&&m->patch_off<m->size,"patch area bounds");
    uint64_t *key=(void *)(m->base+m->key_off);
    for(unsigned i=0;i<8;i++)key[i]=keys[i]*8;
    make_hash(m);
}
static void note_missing_weak(const char *name) {
    static const char *allowed[]={"_ZTH15gDeferredAction","nnProfilerInitialize","nnProfilerRecordHeartbeat"};
    bool known=false;
    for(unsigned i=0;i<3;i++)if(!strcmp(name,allowed[i]))known=true;
    need(known,"unmeasured unresolved weak import");
    for(unsigned i=0;i<missing_weak_kinds;i++)if(!strcmp(name,missing_weak[i]))return;
    need(missing_weak_kinds<3,"weak import count");missing_weak[missing_weak_kinds++]=name;
}
static uintptr_t relocation_value(Module *m,const Reloc *r,bool count) {
    need(r->where>=m->data_off&&r->where+8<=m->key_off&&r->symbol<m->nsym,"relocation bounds");
    if(r->kind==1027) {
        need(r->addend>=0&&(uint64_t)r->addend<m->key_off,"relative relocation addend");
        if(count)m->relative++;
        return (uintptr_t)m->base+r->addend;
    }
    need(r->kind==257||r->kind==1025||r->kind==1026,"relocation kind");
    const Symbol *s=&m->symbols[r->symbol];void *address=NULL;
    /* Shared rtld semantics: locals bind in their module; globals/weak symbols
     * bind to the first definition in measured Horizon load order. No HLE or
     * observer address is injected in this bounded probe. */
    if(castlevania_symbol_binds_locally(s->defined,s->binding))address=s->value<m->key_off?m->base+s->value:NULL;
    if(!address)address=runtime_symbol(s->name);
    if(!address&&s->binding!=2) {fprintf(stderr,"%s unresolved %s\n",m->name,s->name);runtime_fail("strong import unresolved");}
    if(!address)note_missing_weak(s->name);
    if(count) {m->symbolic++;if(!address)m->weak++;if(address&&!s->defined)m->cross++;}
    return (uintptr_t)address+(r->kind==1026?0:r->addend);
}
static void relocate_and_readback(Module *m) {
    for(unsigned i=0;i<m->nreloc;i++) {
        const Reloc *r=&m->relocs[i];uintptr_t value=relocation_value(m,r,true);
        memcpy(m->base+r->where,&value,8);
    }
    for(unsigned i=0;i<m->nreloc;i++) {
        const Reloc *r=&m->relocs[i];uintptr_t actual;
        memcpy(&actual,m->base+r->where,8);
        need(actual==relocation_value(m,r,false),"relocated pointer independent readback");checked_relocations++;
    }
}
static void verify_nnmain_identity(void) {
    void *original=runtime_symbol("nnMain");need(original!=NULL,"measured nnMain definition");unsigned checked=0;
    for(unsigned i=0;i<NM;i++)for(unsigned j=0;j<modules[i].nreloc;j++) {
        Module *m=&modules[i];const Reloc *r=&m->relocs[j];
        if(r->kind==1027||r->kind==1026||strcmp(m->symbols[r->symbol].name,"nnMain"))continue;
        uintptr_t actual;memcpy(&actual,m->base+r->where,8);
        need(actual==(uintptr_t)original,"nnMain identity binding");checked++;
    }
    need(checked>0,"nnMain identity relocation absent");
}
static void seal_and_query(Module *m) {
    size_t rx=page_up(m->text_end),ro_end=m->data_off&~(size_t)0x3fff;
    need(rx<=ro_end,"text/data overlap");
    need(mprotect(m->base,rx,PROT_READ|PROT_EXEC)==0,"text RX");
    if(ro_end>rx)need(mprotect(m->base+rx,ro_end-rx,PROT_READ)==0,"rodata R");
    need(mprotect(m->base+m->key_off,0x4000,PROT_READ)==0,"key page R");
    uint8_t *patch=m->pre?m->base-m->pre:m->base+m->patch_off;
    size_t patch_size=m->pre?m->pre:image_end(m)-m->patch_off;
    need(mprotect(patch,patch_size,PROT_READ|PROT_EXEC)==0,"patch RX");
    sys_icache_invalidate(m->base,rx);sys_icache_invalidate(patch,patch_size);
    mach_vm_address_t a=(uintptr_t)m->base-m->pre,end=(uintptr_t)m->base+m->size;
    while(a<end) {
        mach_vm_size_t size=0;vm_region_basic_info_data_64_t info;mach_msg_type_number_t count=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t object=0;
        mach_vm_address_t requested=a;
        need(mach_vm_region(mach_task_self(),&a,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&count,&object)==KERN_SUCCESS&&a==requested&&size>0,"mapped region query");
        if(object)mach_port_deallocate(mach_task_self(),object);
        uint64_t off=a-(uintptr_t)m->base;
        vm_prot_t expected=a<(uintptr_t)m->base?VM_PROT_READ|VM_PROT_EXECUTE:
            (off<rx||(!m->pre&&off>=m->patch_off))?VM_PROT_READ|VM_PROT_EXECUTE:
            ((off>=rx&&off<ro_end)||off==m->key_off)?VM_PROT_READ:VM_PROT_READ|VM_PROT_WRITE;
        need(info.protection==expected,"mapped permission mismatch");a+=size;checked_permissions++;
    }
}
int main(int argc,char **argv) {
    castlevania_check_loader_scratch();
    need(argc==2,"usage: castlevania-loader-probe completed-AOT-directory");
    need(sysconf(_SC_PAGESIZE)==0x4000,"16KB Apple pages required");
    need(NM==3&&!strcmp(modules[0].name,"main")&&!strcmp(modules[1].name,"subsdk0")&&!strcmp(modules[2].name,"sdk"),"Castlevania measured load order");
    for(unsigned i=0;i<8;i++)need(pthread_key_create(&keys[i],NULL)==0&&keys[i]!=0,"allocate real Darwin TLS key index");
    for(unsigned i=0;i<NM;i++)map_module(&modules[i],argv[1]);
    for(unsigned i=0;i<NM;i++)relocate_and_readback(&modules[i]);
    verify_nnmain_identity();need(missing_weak_kinds==3,"expected three measured unresolved weak symbols");
    for(unsigned i=0;i<NM;i++)seal_and_query(&modules[i]);
    printf("{\"status\":\"pass\",\"phase\":\"native_loader_mapping_only\",\"title_id\":\"0100BA4026E94000\",\"version\":\"1.1.0\",\"modules\":[");
    for(unsigned i=0;i<NM;i++) {Module *m=&modules[i];printf("%s{\"name\":\"%s\",\"sha256\":\"%s\",\"relative\":%u,\"symbolic\":%u,\"cross\":%u,\"weak_zero_relocations\":%u}",i?",":"",m->name,m->digest,m->relative,m->symbolic,m->cross,m->weak);}
    printf("],\"relocations_readback\":%u,\"permission_regions_checked\":%u,\"unresolved_weak_symbols\":%u,\"guest_instructions_executed\":false,\"constructors_executed\":false,\"nnMain_executed\":false,\"GPU_used\":false,\"HLE_overrides_injected\":false,\"profiles_or_saves_opened\":false,\"scope\":\"actual SHA-verified native mappings, ELF bindings, relocation bytes, identity and page permissions; no service or gameplay compatibility claim\"}\n",checked_relocations,checked_permissions,missing_weak_kinds);
    for(unsigned i=0;i<NM;i++) {need(munmap(modules[i].base-modules[i].pre,modules[i].pre+modules[i].size)==0,"release private mapping");free(modules[i].hash);}
    for(unsigned i=0;i<8;i++)need(pthread_key_delete(keys[i])==0,"release Darwin key");
    return 0;
}
