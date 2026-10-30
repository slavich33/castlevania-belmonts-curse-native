#pragma once
/* Independently authored NRR fixtures signed by ephemeral in-memory test keys.
 * Only public key components leave Security handles; nothing is persisted. */
#include <Security/Security.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {SecKeyRef root,child;uint8_t root_modulus[256],child_modulus[256];} NrrFixtureKeys;
static inline void nrr_fixture_need(int ok,const char *why){if(!ok){fprintf(stderr,"fixture: %s\n",why);exit(2);}}
static inline void nrr_fixture_u32(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(i*8));}
static inline void nrr_fixture_u64(uint8_t *p,uint64_t v){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(v>>(i*8));}
static inline SecKeyRef nrr_fixture_key(uint8_t modulus[256]) {
    int bits=2048;CFNumberRef number=CFNumberCreate(NULL,kCFNumberIntType,&bits);
    const void *keys[]={kSecAttrKeyType,kSecAttrKeySizeInBits};const void *values[]={kSecAttrKeyTypeRSA,number};
    CFDictionaryRef attrs=CFDictionaryCreate(NULL,keys,values,2,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    SecKeyRef private_key=SecKeyCreateRandomKey(attrs,NULL);CFRelease(attrs);CFRelease(number);
    nrr_fixture_need(private_key!=NULL,"ephemeral RSA key generation");
    SecKeyRef public_key=SecKeyCopyPublicKey(private_key);nrr_fixture_need(public_key!=NULL,"public key");
    CFDataRef der=SecKeyCopyExternalRepresentation(public_key,NULL);CFRelease(public_key);
    nrr_fixture_need(der&&CFDataGetLength(der)==270,"test RSA public DER");
    const uint8_t *p=CFDataGetBytePtr(der);nrr_fixture_need(p[8]==0&&p[265]==2&&p[266]==3&&p[267]==1&&p[268]==0&&p[269]==1,"test RSA2048 exponent65537");
    memcpy(modulus,p+9,256);CFRelease(der);return private_key;
}
static inline NrrFixtureKeys nrr_fixture_keys(void) {
    NrrFixtureKeys k={0};k.root=nrr_fixture_key(k.root_modulus);k.child=nrr_fixture_key(k.child_modulus);return k;
}
static inline void nrr_fixture_keys_close(NrrFixtureKeys *k){CFRelease(k->root);CFRelease(k->child);memset(k,0,sizeof *k);}
static inline void nrr_fixture_sign(SecKeyRef key,const uint8_t *data,size_t size,uint8_t signature[256]) {
    CFDataRef message=CFDataCreate(NULL,data,(CFIndex)size);
    CFDataRef sig=SecKeyCreateSignature(key,kSecKeyAlgorithmRSASignatureMessagePSSSHA256,message,NULL);CFRelease(message);
    nrr_fixture_need(sig&&CFDataGetLength(sig)==256,"ephemeral RSA-PSS signature");memcpy(signature,CFDataGetBytePtr(sig),256);CFRelease(sig);
}
static inline void nrr_fixture_sign_all(NrrFixtureKeys *k,uint8_t *nrr,size_t size) {
    nrr_fixture_sign(k->root,nrr+0x10,0x120,nrr+0x130);
    nrr_fixture_sign(k->child,nrr+0x330,size-0x330,nrr+0x230);
}
static inline uint8_t *nrr_fixture_make(NrrFixtureKeys *k,uint64_t program_id) {
    void *memory=NULL;nrr_fixture_need(!posix_memalign(&memory,4096,4096),"aligned NRR allocation");
    uint8_t *b=memory;memset(b,0,4096);memcpy(b,"NRR0",4);nrr_fixture_u32(b+4,0);
    nrr_fixture_u64(b+0x10,UINT64_MAX);nrr_fixture_u64(b+0x18,program_id);memcpy(b+0x30,k->child_modulus,256);
    nrr_fixture_u64(b+0x330,program_id);nrr_fixture_u32(b+0x338,4096);nrr_fixture_u32(b+0x340,0x350);nrr_fixture_u32(b+0x344,2);
    memset(b+0x350,0x11,32);memset(b+0x370,0x22,32);nrr_fixture_sign_all(k,b,4096);return b;
}
