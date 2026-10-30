#pragma once
/* RTLD's exported RO callback-slot alias. This is loader storage, not a host
 * implementation of RO lookup or a replacement for the SDK's callback. */
#include "runtime.h"
#include <string.h>

typedef struct {
    uintptr_t manual_lookup_address;
    unsigned prepared;
} RuntimeRtldRoState;

#define RUNTIME_RO_MANUAL_SLOT_SYMBOL "_ZN2nn2ro6detail36g_pLookupGlobalManualFunctionPointerE"
_Static_assert(sizeof(uintptr_t)==8,"64-bit RTLD RO ABI");

/* Resolve every definition by name and validate the complete plan before any
 * write. Real RTLD aliases each exported definition to one process-wide slot.
 * The SDK installs its own callback later, through this alias. No callback is
 * invoked here, and no module lists or unrelated RO globals are manufactured.
 * Returns NULL on success, otherwise a diagnostic for the caller's fail gate. */
static inline const char *runtime_rtld_ro_prepare(RuntimeRtldRoState *state,
                                                Module *modules,size_t count) {
    if(!state||!modules||!count)return "RTLD RO alias arguments";
    if(state->prepared||state->manual_lookup_address)return "RTLD RO alias already initialized";
    size_t definitions=0;
    for(size_t i=0;i<count;i++){
        const Module *m=&modules[i];unsigned found=0;
        if(!m->symbols&&m->nsym)return "RTLD RO symbol table missing";
        for(unsigned j=0;j<m->nsym;j++){
            const Symbol *s=&m->symbols[j];
            if(!s->name)return "RTLD RO symbol name missing";
            if(strcmp(s->name,RUNTIME_RO_MANUAL_SLOT_SYMBOL)||!s->defined)continue;
            if(++found!=1)return "RTLD RO duplicate symbol definition";
            if(s->defined!=1||(s->binding!=1&&s->binding!=2)||s->type!=1||s->size!=8)
                return "RTLD RO unsupported symbol metadata";
            if(!m->base||m->data_off>m->key_off||m->key_off>m->size||
               s->value<m->data_off||s->value>m->key_off||m->key_off-s->value<8||
               s->value>UINTPTR_MAX-(uintptr_t)m->base||
               ((uintptr_t)m->base+s->value)%_Alignof(uintptr_t))
                return "RTLD RO symbol outside aligned writable data";
            uintptr_t previous;memcpy(&previous,m->base+s->value,sizeof previous);
            if(previous)return "RTLD RO alias is not fresh zero";
            definitions++;
        }
    }
    if(!definitions)return "RTLD RO required callback-slot symbol missing";
    uintptr_t alias=(uintptr_t)&state->manual_lookup_address;
    for(size_t i=0;i<count;i++)for(unsigned j=0;j<modules[i].nsym;j++){
        const Symbol *s=&modules[i].symbols[j];
        if(s->defined&&!strcmp(s->name,RUNTIME_RO_MANUAL_SLOT_SYMBOL))
            memcpy(modules[i].base+s->value,&alias,sizeof alias);
    }
    state->prepared=1;return NULL;
}
