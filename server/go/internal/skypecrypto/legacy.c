#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* The historical source assumes a 32-bit u32 even on LP64 Unix. */
#define u32 uint32_t
#define __fastcall
int debuglog(const char *format, ...) { (void)format; return 0; }

/* Load the historical declarations first, then replace its GCC rotate macros
   with explicitly unsigned 32-bit operations. MSVC performed these as 32-bit
   machine rotates; leaving signed integer constants to GCC would invoke
   undefined shift behaviour for several IV-expansion constants. */
#include "../../../../skypeopensource2/goodsendrelay4_dll/goodsendrelay4_dll/skype/skype_rc4.h"
#undef rotl32
#undef rotr32
#define rotl32(x,r) ((uint32_t)(((uint32_t)(x) << ((r)&31)) | ((uint32_t)(x) >> ((0-(r))&31))))
#define rotr32(x,r) ((uint32_t)(((uint32_t)(x) >> ((r)&31)) | ((uint32_t)(x) << ((0-(r))&31))))
#include "../../../../skypeopensource2/goodsendrelay4_dll/goodsendrelay4_dll/skype/skype_rc4.c"
#undef u32

typedef struct os_session {
    RC4_context send;
    RC4_context recv;
    int send_ready;
    int recv_ready;
} os_session;

static void be32(unsigned char *p, uint32_t v) {
    p[0]=(unsigned char)(v>>24); p[1]=(unsigned char)(v>>16); p[2]=(unsigned char)(v>>8); p[3]=(unsigned char)v;
}
static void be16(unsigned char *p, uint16_t v) { p[0]=(unsigned char)(v>>8); p[1]=(unsigned char)v; }
static uint32_t read_be32(const unsigned char *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}

static int make_handshake(RC4_context *ctx,const unsigned char *secret,int secret_len,uint32_t iv,uint16_t seq,int garbage,unsigned char *out,int cap) {
    int n;
    if (!ctx || !secret || secret_len < 48 || !out) return -1;
    if (garbage < 4) garbage=4; else if (garbage > 48) garbage=48;
    n=garbage+16; if (cap<n) return -2;
    memset(out,0,n); be32(out,iv); be16(out+4,seq);
    out[9]=1; out[13]=3; out[14]=(unsigned char)((garbage+1)*2+1); out[15]=3;
    memset(ctx,0,sizeof(*ctx));
    Skype_RC4_Expand_IV(iv,secret,ctx,1,48);
    RC4_crypt(out+4,10,ctx,1);
    RC4_crypt(out+14,(uint32_t)(garbage+2),ctx,0);
    return n;
}

static int decrypt_handshake(RC4_context *ctx,const unsigned char *secret,int secret_len,const unsigned char *packet,int packet_len,unsigned char *out,int cap) {
    uint32_t iv; int remaining;
    if (!ctx||!secret||secret_len<48||!packet||packet_len<16||!out||cap<packet_len) return -1;
    memcpy(out,packet,packet_len); iv=read_be32(out); memset(ctx,0,sizeof(*ctx));
    Skype_RC4_Expand_IV(iv,secret,ctx,1,48);
    RC4_crypt(out+4,10,ctx,1);
    remaining=packet_len-14; if (remaining>0) RC4_crypt(out+14,(uint32_t)remaining,ctx,0);
    return packet_len;
}

void *os_session_create(void) { return calloc(1,sizeof(os_session)); }
void os_session_free(void *p) { free(p); }
int os_session_make(void *p,const unsigned char *secret,int secret_len,uint32_t iv,uint16_t seq,int garbage,unsigned char *out,int cap) {
    os_session *s=(os_session*)p; int n; if(!s)return -3;
    n=make_handshake(&s->send,secret,secret_len,iv,seq,garbage,out,cap); if(n>0)s->send_ready=1; return n;
}
int os_session_client_handshake(void *p,const unsigned char *secret,int secret_len,const unsigned char *packet,int packet_len,unsigned char *out,int cap) {
    os_session *s=(os_session*)p; int n; if(!s)return -3;
    n=decrypt_handshake(&s->recv,secret,secret_len,packet,packet_len,out,cap); if(n>0)s->recv_ready=1; return n;
}
int os_session_decrypt(void *p,const unsigned char *in,int n,unsigned char *out,int cap) {
    os_session *s=(os_session*)p; if(!s||!s->recv_ready)return -3;if(!in||n<0||!out||cap<n)return -1;
    memcpy(out,in,n); RC4_crypt(out,(uint32_t)n,&s->recv,0); return n;
}
int os_session_encrypt(void *p,const unsigned char *in,int n,unsigned char *out,int cap) {
    os_session *s=(os_session*)p; if(!s||!s->send_ready)return -3;if(!in||n<0||!out||cap<n)return -1;
    memcpy(out,in,n); RC4_crypt(out,(uint32_t)n,&s->send,0); return n;
}
int os_udp_crypt(uint32_t iv,const unsigned char *in,int n,unsigned char *out,int cap) {
    RC4_context ctx; if(!in||n<0||!out||cap<n)return -1;memcpy(out,in,n);memset(&ctx,0,sizeof(ctx));
    Skype_RC4_Expand_IV_udp(&ctx,iv,1);RC4_crypt(out,(uint32_t)n,&ctx,0);return n;
}
