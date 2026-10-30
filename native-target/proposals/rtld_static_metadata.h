#pragma once
/* Candidate only: no loader integration. A metadata-only port of the measured
 * RTLD static RoModule population, not its relocation/binding/init routines.
 * The caller supplies modules in authenticated original RTLD lookup order and
 * an already host-stack-wrapped LookupGlobalAuto callback. See provenance. */
#include "runtime.h"
#include <stdlib.h>
#include <string.h>

#define RTLD_STATIC_MAX_MODULES 16u
typedef struct {
    /* Physical +0 goes backward: head+0 is the last inserted module and
     * RTLD's DT_INIT walk follows +0 in reverse load order. Physical +8 goes
     * forward: head+8 is the first module and lookup/binding follows +8.
     * prev/next here use conventional names; only offsets define this ABI. */
    uint64_t prev,next,jmprel,relocations,opaque20,base,dynamic,pltrelsz;
    uint64_t init,fini,buckets,chains,strings,symbols,strsz,pltgot;
    uint64_t relasz,relsz,relcount,relacount,nchain,nbucket,soname,image_size;
    uint8_t state_c0,zero_c1,zero_c2,flags_c3;
    uint32_t zero_c4;
    uint64_t lazy_c8;
} RtldStaticRoModule;
_Static_assert(sizeof(RtldStaticRoModule)==0xd0,"measured RoModule size");
_Static_assert(offsetof(RtldStaticRoModule,prev)==0,"reverse/DT_INIT link offset");
_Static_assert(offsetof(RtldStaticRoModule,next)==8,"forward/lookup link offset");
_Static_assert(offsetof(RtldStaticRoModule,base)==0x28,"RoModule base");
_Static_assert(offsetof(RtldStaticRoModule,symbols)==0x68,"RoModule symbols");
_Static_assert(offsetof(RtldStaticRoModule,flags_c3)==0xc3,"RoModule flags");
typedef struct {uint64_t prev,next;} RtldStaticList;
typedef struct {
    RtldStaticList automatic,manual;
    uintptr_t manual_lookup_address;
    uint8_t debug_flag;
    unsigned prepared,module_count;
    RtldStaticRoModule *descriptors[RTLD_STATIC_MAX_MODULES];
} RtldStaticMetadata;

static const char *const rtld_static_alias_names[5]={
    "_ZN2nn2ro6detail36g_pLookupGlobalManualFunctionPointerE",
    "_ZN2nn2ro6detail17g_pManualLoadListE",
    "_ZN2nn2ro6detail14g_pRoDebugFlagE",
    "_ZN2nn2ro6detail34g_pLookupGlobalAutoFunctionPointerE",
    "_ZN2nn2ro6detail15g_pAutoLoadListE"
};
static inline uint32_t rtld_static_u32(const void *p){uint32_t x;memcpy(&x,p,4);return x;}
static inline uint64_t rtld_static_u64(const void *p){uint64_t x;memcpy(&x,p,8);return x;}
static inline int rtld_static_range(uint64_t off,uint64_t len,uint64_t lo,uint64_t hi){
    return lo<=off&&off<=hi&&len<=hi-off;
}
static inline int rtld_static_zero(const void *p,size_t n){
    const uint8_t *b=p;for(size_t i=0;i<n;i++)if(b[i])return 0;return 1;
}
typedef struct {
    RtldStaticRoModule value,*destination;
    uint64_t aliases[5];unsigned alias_mask;
} RtldStaticPlan;
typedef struct {
    const uint8_t *base;
    const char *digest;
    uint64_t file_size,lazy_offset,jump_slots;
    unsigned captured;
} RtldStaticBindingSource;

/* Read initialized image metadata only. All source offsets are relative to the
 * actual mapped module; no title-specific address or module name is required. */
static inline const char *rtld_static_plan(const Module *m,RtldStaticPlan *p){
    if(!m->base||(uintptr_t)m->base%8||m->ro_off<8||m->text_end>m->ro_off||
       m->ro_off>m->data_off||m->data_off>m->key_off||m->key_off>m->size||
       m->key_off>UINTPTR_MAX-(uintptr_t)m->base||!m->symbols||!m->nsym)
        return "RTLD static module bounds/metadata";
    uint64_t mod=rtld_static_u32(m->base+4);
    if(!rtld_static_range(mod,28,m->ro_off,m->data_off)||rtld_static_u32(m->base+mod)!=0x30444f4d)
        return "RTLD static MOD0 header";
    uint64_t fields[6];
    for(unsigned i=0;i<6;i++){
        int64_t off=(int64_t)mod+(int32_t)rtld_static_u32(m->base+mod+4+i*4);
        if(off<0)return "RTLD static MOD0 signed offset";
        fields[i]=(uint64_t)off;
    }
    uint64_t dyn=fields[0],bss=fields[1],end=fields[2],descriptor=fields[5];
    if(bss<m->data_off||bss>end||end>m->key_off||descriptor%8||
       !rtld_static_range(descriptor,sizeof p->value,bss,end)||
       !rtld_static_range(dyn,16,m->data_off,bss)||end>UINT64_MAX-4095)
        return "RTLD static MOD0 BSS/dynamic/descriptor range";
    p->destination=(void *)(m->base+descriptor);
    if(!rtld_static_zero(p->destination,sizeof p->value))return "RTLD static descriptor not fresh BSS";
    uint64_t tags[38]={0},seen=0,flags1=0,relacount=0,relcount=0;
    int stopped=0,have_flags1=0,have_relacount=0,have_relcount=0;
    for(unsigned i=0;i<4096;i++){
        uint64_t pos=dyn+(uint64_t)i*16;
        if(!rtld_static_range(pos,16,m->data_off,bss))return "RTLD static unterminated dynamic table";
        uint64_t tag=rtld_static_u64(m->base+pos),v=rtld_static_u64(m->base+pos+8);
        if(!tag){if(v)return "RTLD static DT_NULL value";stopped=1;break;}
        if(tag==1)continue; /* DT_NEEDED does not mutate the original RTLD descriptor. */
        if(tag==0x6ffffef5)continue; /* GNU hash: this RTLD's lookup uses SysV. */
        if(tag==0x6ffffffb){if(have_flags1++)return "RTLD static duplicate FLAGS_1";flags1=v;continue;}
        if(tag==0x6ffffff9){if(have_relacount++)return "RTLD static duplicate RELACOUNT";relacount=v;continue;}
        if(tag==0x6ffffffa){if(have_relcount++)return "RTLD static duplicate RELCOUNT";relcount=v;continue;}
        if(tag>=38||!(tag==2||tag==3||tag==4||tag==5||tag==6||tag==7||tag==8||tag==9||
           tag==10||tag==11||tag==12||tag==13||tag==14||tag==17||tag==18||tag==19||
           tag==20||tag==21||tag==23||tag==24||tag==25||tag==26||tag==27||tag==28||
           tag==30||tag==35||tag==36||tag==37))return "RTLD static unsupported dynamic tag";
        if(seen&(UINT64_C(1)<<tag))return "RTLD static duplicate dynamic tag";
        seen|=UINT64_C(1)<<tag;tags[tag]=v;
    }
    if(!stopped)return "RTLD static dynamic table limit";
    if(!(seen&(UINT64_C(1)<<4))||!tags[4]||!tags[5]||!tags[6]||!tags[10]||tags[11]!=24||
       (tags[30]&~UINT64_C(8))||(flags1&~UINT64_C(0x8000001)))
        return "RTLD static unsupported ELF metadata/flags";
    if(!rtld_static_range(tags[4],8,m->ro_off,m->data_off)||
       !rtld_static_range(tags[5],tags[10],m->ro_off,m->data_off))return "RTLD static hash/string bounds";
    uint64_t nb=rtld_static_u32(m->base+tags[4]),nc=rtld_static_u32(m->base+tags[4]+4);
    if(!nb||nc!=m->nsym||!rtld_static_range(tags[4]+8,(nb+nc)*4,m->ro_off,m->data_off)||
       !rtld_static_range(tags[6],nc*24,m->ro_off,m->data_off))return "RTLD static SysV/symbol bounds";
    for(uint64_t i=0;i<nb+nc;i++)if(rtld_static_u32(m->base+tags[4]+8+i*4)>=nc)
        return "RTLD static SysV index";
    uint8_t *colors=calloc((size_t)nc,1);if(!colors)return "RTLD static SysV validation allocation";
    const uint8_t *chains=m->base+tags[4]+8+nb*4;
    for(uint64_t i=1;i<nc;i++){
        uint32_t cursor=(uint32_t)i;
        while(cursor&&!colors[cursor]){colors[cursor]=1;cursor=rtld_static_u32(chains+(uint64_t)cursor*4);}
        if(cursor&&colors[cursor]==1){free(colors);return "RTLD static cyclic SysV chain";}
        cursor=(uint32_t)i;
        while(cursor&&colors[cursor]==1){colors[cursor]=2;cursor=rtld_static_u32(chains+(uint64_t)cursor*4);}
    }
    free(colors);
    for(unsigned i=0;i<m->nsym;i++){
        const uint8_t *e=m->base+tags[6]+(uint64_t)i*24;const Symbol *s=&m->symbols[i];
        uint32_t name=rtld_static_u32(e);uint16_t section;memcpy(&section,e+6,2);
        if(name>=tags[10]||!memchr(m->base+tags[5]+name,0,(size_t)(tags[10]-name))||!s->name||
           strcmp(s->name,(const char *)m->base+tags[5]+name)||s->value!=rtld_static_u64(e+8)||
           s->size!=rtld_static_u64(e+16)||s->binding!=(unsigned)(e[4]>>4)||s->type!=(e[4]&15)||
           s->defined!=(unsigned)(section!=0))return "RTLD static generated/raw symbol disagreement";
        if((e[4]>>4)>2||(e[4]&15)>4||e[5]>3||section>=0xff00)
            return "RTLD static unsupported symbol kind/binding/section";
        if(section&&!rtld_static_range(s->value,s->size,0,end))return "RTLD static defined symbol bounds";
        for(unsigned a=0;a<5;a++)if(section&&!strcmp(s->name,rtld_static_alias_names[a])){
            if(p->alias_mask&(1u<<a))return "RTLD static duplicate alias definition";
            if((s->binding!=1&&s->binding!=2)||s->type!=1||s->size!=8||s->value%8||
               !rtld_static_range(s->value,8,m->data_off,end)||
               (s->value<descriptor+sizeof p->value&&descriptor<s->value+8)||
               !rtld_static_zero(m->base+s->value,8))return "RTLD static alias storage/metadata";
            for(unsigned prior=0;prior<5;prior++)if((p->alias_mask&(1u<<prior))&&p->aliases[prior]==s->value)
                return "RTLD static overlapping aliases";
            p->aliases[a]=s->value;p->alias_mask|=1u<<a;
        }
    }
    if(tags[9]&&tags[9]!=24)return "RTLD static RELA entry size";
    if(tags[19]&&tags[19]!=16)return "RTLD static REL entry size";
    if((tags[7]&&tags[17])||tags[8]%24||tags[18]%16||relacount>tags[8]/24||relcount>tags[18]/16)
        return "RTLD static relocation table layout";
    if((tags[7]||tags[8])&&(!tags[7]||!rtld_static_range(tags[7],tags[8],m->ro_off,m->data_off)))
        return "RTLD static RELA bounds";
    if((tags[17]||tags[18])&&(!tags[17]||!rtld_static_range(tags[17],tags[18],m->ro_off,m->data_off)))
        return "RTLD static REL bounds";
    if((tags[23]||tags[2])&&(!tags[23]||(tags[20]!=7&&tags[20]!=17)||
       tags[2]%(tags[20]==7?24:16)||!rtld_static_range(tags[23],tags[2],m->ro_off,m->data_off)))
        return "RTLD static JMPREL bounds/type";
    if((tags[35]||tags[36]||tags[37])&&(!tags[36]||tags[37]!=8||tags[35]%8||
       !rtld_static_range(tags[36],tags[35],m->ro_off,m->data_off)))return "RTLD static RELR bounds";
    if(tags[3]&&(tags[3]%8||!rtld_static_range(tags[3],24,m->data_off,bss)))return "RTLD static PLTGOT bounds";
    if(tags[14]>=tags[10]||!memchr(m->base+tags[5]+tags[14],0,(size_t)(tags[10]-tags[14])))
        return "RTLD static SONAME bounds";
    if((tags[12]&&(tags[12]%4||tags[12]>=m->text_end))||
       (tags[13]&&(tags[13]%4||tags[13]>=m->text_end)))return "RTLD static init/fini bounds";
    RtldStaticRoModule *r=&p->value;
    r->base=(uintptr_t)m->base;r->dynamic=r->base+dyn;r->image_size=(end+4095)&~UINT64_C(4095);
    r->jmprel=tags[23]?r->base+tags[23]:0;r->relocations=(tags[7]||tags[17])?r->base+(tags[7]?tags[7]:tags[17]):0;
    r->pltrelsz=tags[2];r->init=tags[12]?r->base+tags[12]:0;r->fini=tags[13]?r->base+tags[13]:0;
    r->buckets=r->base+tags[4]+8;r->chains=r->buckets+nb*4;r->strings=r->base+tags[5];
    r->symbols=r->base+tags[6];r->strsz=tags[10];r->pltgot=tags[3]?r->base+tags[3]:0;
    r->relasz=tags[8];r->relsz=tags[18];r->relcount=relcount;r->relacount=relacount;
    r->nchain=nc;r->nbucket=nb;r->soname=tags[14];r->state_c0=0x13;
    r->flags_c3=(tags[20]==7?2:0)|((tags[30]&8)||(flags1&1)||(seen&(UINT64_C(1)<<24))?4:0)|(m->weak?8:0);
    return NULL;
}

/* Capture only from the already authenticated AOT mapping before relocation.
 * The common original JUMP_SLOT value is lost after native/HLE binding. Real
 * RTLD records base+this value at +C8; guessing zero is incorrect even NOW-bound
 * modules need that baseline for later RestoreFunctions/RevertReference.
 * No source file is reopened and no relocation target is modified here. */
static inline const char *rtld_static_capture_binding_source(const Module *m,RtldStaticBindingSource *out){
    if(!m||!out||!rtld_static_zero(out,sizeof *out)||!m->digest||strlen(m->digest)!=64||
       m->relative||m->symbolic||m->cross||m->weak)return "RTLD static capture requires fresh authenticated mapping";
    RtldStaticPlan plan={0};const char *error=rtld_static_plan(m,&plan);if(error)return error;
    RtldStaticBindingSource source={.base=m->base,.digest=m->digest,.file_size=m->file_size,.captured=1};
    uint64_t mod=rtld_static_u32(m->base+4);
    uint64_t initialized_end=(uint64_t)((int64_t)mod+(int32_t)rtld_static_u32(m->base+mod+8));
    uint64_t stride=(plan.value.flags_c3&2)?24:16;
    for(uint64_t off=0;off<plan.value.pltrelsz;off+=stride){
        const uint8_t *entry=(void *)(uintptr_t)(plan.value.jmprel+off);
        uint64_t target=rtld_static_u64(entry),info=rtld_static_u64(entry+8);
        if((uint32_t)info!=1026||(info>>32)>=m->nsym||target%8||
           !rtld_static_range(target,8,m->data_off,initialized_end))return "RTLD static original JUMP_SLOT metadata";
        uint64_t initial=rtld_static_u64(m->base+target);
        if(initial%4||initial>=m->text_end)return "RTLD static original lazy target outside text";
        if(source.jump_slots&&source.lazy_offset!=initial)return "RTLD static inconsistent original lazy target";
        source.lazy_offset=initial;source.jump_slots++;
    }
    *out=source;return NULL;
}

/* The callback never substitutes runtime_symbol's local-first hash. This is
 * the original RTLD SysV-chain/name lookup and its first global/weak provider
 * in the supplied static load order; no later strong-over-weak preference. */
static inline void *rtld_static_lookup_export(const RtldStaticMetadata *state,const char *name){
    if(!state||!state->prepared||!name)return NULL;
    uint32_t h=0;for(const unsigned char *s=(const void *)name;*s;s++){
        h=(h<<4)+*s;uint32_t g=h&0xf0000000;h^=g>>24;h&=~g;
    }
    for(unsigned i=0;i<state->module_count;i++){
        const RtldStaticRoModule *m=state->descriptors[i];
        uint32_t index=rtld_static_u32((void *)(uintptr_t)(m->buckets+(h%m->nbucket)*4));
        for(uint64_t steps=0;index&&steps<m->nchain;steps++){
            const uint8_t *s=(const void *)(uintptr_t)(m->symbols+(uint64_t)index*24);
            uint16_t section;memcpy(&section,s+6,2);
            if((s[4]&15)!=4&&section&&section!=0xfff2&&
               !strcmp(name,(const char *)(uintptr_t)(m->strings+rtld_static_u32(s)))){
                if((s[4]>>4)==1||(s[4]>>4)==2)return (void *)(uintptr_t)(m->base+rtld_static_u64(s+8));
                break;
            }
            index=rtld_static_u32((void *)(uintptr_t)(m->chains+(uint64_t)index*4));
        }
    }
    return NULL;
}

/* Every module and alias is validated before mutating any state/image bytes.
 * Only fresh RoModule BSS, the five named aliases and owned native storage are
 * written. Existing relocations, constructors, code and HLE slots are untouched. */
static inline const char *rtld_static_metadata_prepare(RtldStaticMetadata *state,Module *modules,
                                                       const RtldStaticBindingSource *sources,
                                                       size_t count,uintptr_t wrapped_auto_lookup){
    if(!state||!modules||!sources||!count||count>RTLD_STATIC_MAX_MODULES||!wrapped_auto_lookup||wrapped_auto_lookup%4)
        return "RTLD static prepare arguments";
    if(!rtld_static_zero(state,sizeof *state))return "RTLD static state is not fresh";
    RtldStaticPlan *plans=calloc(count,sizeof *plans);if(!plans)return "RTLD static plan allocation";
    const char *error=NULL;unsigned aliases=0;
    for(size_t i=0;i<count;i++){
        error=rtld_static_plan(&modules[i],&plans[i]);if(error)goto done;
        const RtldStaticBindingSource *source=&sources[i];
        uint64_t stride=(plans[i].value.flags_c3&2)?24:16;
        if(!source->captured||source->base!=modules[i].base||!source->digest||!modules[i].digest||
           strcmp(source->digest,modules[i].digest)||source->file_size!=modules[i].file_size||
           source->jump_slots!=plans[i].value.pltrelsz/stride||
           (source->jump_slots&&(source->lazy_offset%4||source->lazy_offset>=modules[i].text_end))||
           (!source->jump_slots&&source->lazy_offset)){
            error="RTLD static missing/mismatched original binding capture";goto done;
        }
        if(source->jump_slots)plans[i].value.lazy_c8=(uintptr_t)modules[i].base+source->lazy_offset;
        aliases|=plans[i].alias_mask;
        for(size_t j=0;j<i;j++){
            uintptr_t a=(uintptr_t)modules[i].base,b=(uintptr_t)modules[j].base;
            if(a<b+modules[j].key_off&&b<a+modules[i].key_off){error="RTLD static overlapping modules";goto done;}
        }
    }
    if(aliases!=31){error="RTLD static required aliases missing";goto done;}
    uintptr_t auto_head=(uintptr_t)&state->automatic,manual_head=(uintptr_t)&state->manual;
    uint64_t values[5]={(uintptr_t)&state->manual_lookup_address,manual_head,(uintptr_t)&state->debug_flag,
                        wrapped_auto_lookup,auto_head};
    for(size_t i=0;i<count;i++){
        plans[i].value.prev=i?(uintptr_t)plans[i-1].destination:auto_head;
        plans[i].value.next=i+1<count?(uintptr_t)plans[i+1].destination:auto_head;
        memcpy(plans[i].destination,&plans[i].value,sizeof plans[i].value);
        state->descriptors[i]=plans[i].destination;
        for(unsigned a=0;a<5;a++)if(plans[i].alias_mask&(1u<<a))memcpy(modules[i].base+plans[i].aliases[a],&values[a],8);
    }
    state->automatic.prev=(uintptr_t)plans[count-1].destination;state->automatic.next=(uintptr_t)plans[0].destination;
    state->manual.prev=state->manual.next=manual_head;state->module_count=(unsigned)count;state->prepared=1;
done:
    free(plans);return error;
}
