/*
 * metal_backend.mm - macOS Metal GPU backend for rar3crack.
 *
 * One candidate password per GPU thread. Compiles MSL at runtime
 * (makeLibrary(source:)) — this avoids hashcat's broken cl2Metal path and
 * works on Apple Silicon. The MSL kernel is a faithful port of the RAR3
 * OraIter SHA1 KDF + AES-128 verify (validated vs hashcat m12500 vector).
 */
#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#include "backend.h"
#include "rar3.h"
#include <vector>
#include <chrono>
#include <cstring>

static const char *kMSL = R"METAL(
#include <metal_stdlib>
using namespace metal;
constant uint HR = 0x40000;
inline uint rotl(uint x, uint n){ return (x<<n)|(x>>(32-n)); }

static void sha1_block(thread uint s[5], thread uint w[16]){
    uint a=s[0],b=s[1],c=s[2],d=s[3],e=s[4];
    uint ww[80];
    for(int i=0;i<16;i++) ww[i]=w[i];
    for(int i=16;i<80;i++) ww[i]=rotl(ww[i-3]^ww[i-8]^ww[i-14]^ww[i-16],1);
    for(int i=0;i<80;i++){
        uint f,k;
        if(i<20){f=(b&(c^d))^d;k=0x5A827999u;}
        else if(i<40){f=b^c^d;k=0x6ED9EBA1u;}
        else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDCu;}
        else{f=b^c^d;k=0xCA62C1D6u;}
        uint t=rotl(a,5)+f+e+k+ww[i];
        e=d;d=c;c=rotl(b,30);b=a;a=t;
    }
    s[0]+=a;s[1]+=b;s[2]+=c;s[3]+=d;s[4]+=e;
}

typedef struct { uint state[5]; uint bufw; ulong count; uchar buf[64]; } sctx;
static void sc_init(thread sctx* c){
    c->state[0]=0x67452301u;c->state[1]=0xEFCDAB89u;c->state[2]=0x98BADCFEu;c->state[3]=0x10325476u;c->state[4]=0xC3D2E1F0u;
    c->bufw=0; c->count=0;
}
static void sc_block(thread sctx* c, thread uchar* blk){
    thread uint w[16];
    for(int i=0;i<16;i++) w[i]=((uint)blk[i*4]<<24)|((uint)blk[i*4+1]<<16)|((uint)blk[i*4+2]<<8)|((uint)blk[i*4+3]);
    sha1_block(c->state, w);
}
static void sc_process(thread sctx* c, thread const uchar* data, uint len){
    c->count += len;
    uint j = c->bufw;
    if (j+len > 63){
        uint take=64-j; for(uint i=0;i<take;i++) c->buf[j+i]=data[i];
        sc_block(c,c->buf);
        uint i=take;
        for(; i+63<len; i+=64) sc_block(c,(thread uchar*)(data+i));
        j=0; for(; i<len; i++) c->buf[j++]=data[i];
        c->bufw=j;
    } else { for(uint i=0;i<len;i++) c->buf[j+i]=data[i]; c->bufw=j+len; }
}
static void sc_process_rar29(thread sctx* c, thread uchar* data, uint len){
    c->count += len;
    uint j=c->bufw;
    if (j+len > 63){
        uint take=64-j; for(uint i=0;i<take;i++) c->buf[j+i]=data[i];
        sc_block(c,c->buf);
        uint i=take;
        for(; i+63<len; i+=64){
            sc_block(c,(thread uchar*)(data+i));
            thread uint w[16];
            for(int k=0;k<16;k++) w[k]=((uint)data[i+k*4]<<24)|((uint)data[i+k*4+1]<<16)|((uint)data[i+k*4+2]<<8)|((uint)data[i+k*4+3]);
            for(int k=0;k<16;k++){ uint v=w[k]; data[i+k*4]=v>>24;data[i+k*4+1]=v>>16;data[i+k*4+2]=v>>8;data[i+k*4+3]=v; }
        }
        j=0; for(; i<len; i++) c->buf[j++]=data[i]; c->bufw=j;
    } else { for(uint i=0;i<len;i++) c->buf[j+i]=data[i]; c->bufw=j+len; }
}
static void sc_done(thread sctx* c, thread uint dg[5]){
    ulong bitlen=c->count*8; uint j=c->bufw;
    c->buf[j++]=0x80;
    if(j!=56){ if(j>56){ while(j<64)c->buf[j++]=0; sc_block(c,c->buf); j=0;} for(uint i=j;i<56;i++)c->buf[i]=0; }
    c->buf[56]=(uchar)(bitlen>>56);c->buf[57]=(uchar)(bitlen>>48);c->buf[58]=(uchar)(bitlen>>40);c->buf[59]=(uchar)(bitlen>>32);
    c->buf[60]=(uchar)(bitlen>>24);c->buf[61]=(uchar)(bitlen>>16);c->buf[62]=(uchar)(bitlen>>8);c->buf[63]=(uchar)bitlen;
    sc_block(c,c->buf);
    for(int i=0;i<5;i++) dg[i]=c->state[i];
}

constant uchar sbox[256]={
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
constant uchar invsbox[256]={
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d};
static uchar gmul(uchar a, uchar b){ uchar p=0; for(int i=0;i<8;i++){ if(b&1)p^=a; uchar hi=a&0x80; a<<=1; if(hi)a^=0x1b; b>>=1; } return p; }
static void aes_dec(thread const uchar key[16], thread const uchar in[16], thread uchar out[16]){
    uchar rk[176]; for(int i=0;i<16;i++)rk[i]=key[i];
    int r=0;
    for(int i=16;i<176;i+=4){ uchar t[4]; for(int j=0;j<4;j++)t[j]=rk[i-4+j];
        if(i%16==0){ uchar u=t[0]; t[0]=sbox[t[1]];t[1]=sbox[t[2]];t[2]=sbox[t[3]];t[3]=sbox[u]; uchar rc=1; for(int k=0;k<r;k++)rc=gmul(rc,2); t[0]^=rc; r++; }
        for(int j=0;j<4;j++) rk[i+j]=rk[i-16+j]^t[j];
    }
    uchar s[16]; for(int i=0;i<16;i++)s[i]=in[i]^rk[160+i];
    for(int rd=9;rd>=1;rd--){ uchar t[16];
        t[0]=s[0];t[1]=s[13];t[2]=s[10];t[3]=s[7];t[4]=s[4];t[5]=s[1];t[6]=s[14];t[7]=s[11];t[8]=s[8];t[9]=s[5];t[10]=s[2];t[11]=s[15];t[12]=s[12];t[13]=s[9];t[14]=s[6];t[15]=s[3];
        for(int i=0;i<16;i++)s[i]=invsbox[t[i]];
        for(int i=0;i<16;i++)s[i]^=rk[rd*16+i];
        for(int c=0;c<4;c++){ uchar a0=s[c*4],a1=s[c*4+1],a2=s[c*4+2],a3=s[c*4+3];
            s[c*4]=gmul(a0,14)^gmul(a1,11)^gmul(a2,13)^gmul(a3,9);
            s[c*4+1]=gmul(a0,9)^gmul(a1,14)^gmul(a2,11)^gmul(a3,13);
            s[c*4+2]=gmul(a0,13)^gmul(a1,9)^gmul(a2,14)^gmul(a3,11);
            s[c*4+3]=gmul(a0,11)^gmul(a1,13)^gmul(a2,9)^gmul(a3,14);
        }
    }
    uchar t[16];
    t[0]=s[0];t[1]=s[13];t[2]=s[10];t[3]=s[7];t[4]=s[4];t[5]=s[1];t[6]=s[14];t[7]=s[11];t[8]=s[8];t[9]=s[5];t[10]=s[2];t[11]=s[15];t[12]=s[12];t[13]=s[9];t[14]=s[6];t[15]=s[3];
    for(int i=0;i<16;i++) out[i]=invsbox[t[i]]^rk[i];
}

kernel void rar3_crack(
    device const uchar* pwbuf [[buffer(0)]],
    device const uint* pwlen [[buffer(1)]],
    device const uchar* salt  [[buffer(2)]],
    device const uchar* enc   [[buffer(3)]],
    device int* result        [[buffer(4)]],
    constant uint& count      [[buffer(5)]],
    uint gid [[thread_position_in_grid]])
{
    if (gid >= count) return;
    uchar RawPsw[80]; uint m=0;
    uint L=pwlen[gid];
    for(uint i=0;i<L;i++){ RawPsw[m++]=pwbuf[gid*16+i]; RawPsw[m++]=0; } /* UTF-16LE */
    for(int i=0;i<8;i++) RawPsw[m+i]=salt[i];
    uint RawLength=m+8;

    sctx c; sc_init(&c);
    uchar AESInit[16];
    for(uint I=0;I<HR;I++){
        uchar buf[80]; for(uint i=0;i<RawLength;i++)buf[i]=RawPsw[i];
        sc_process_rar29(&c, buf, RawLength);
        uchar pn[3]={ (uchar)I,(uchar)(I>>8),(uchar)(I>>16) };
        sc_process(&c, pn, 3);
        if(I%(HR/16)==0){ sctx tc=c; uint dg[5]; sc_done(&tc,dg); AESInit[I/(HR/16)]=(uchar)dg[4]; }
    }
    uint dg[5]; sc_done(&c,dg);
    uchar AESKey[16];
    for(uint i=0;i<4;i++)for(uint j=0;j<4;j++) AESKey[i*4+j]=(uchar)(dg[i]>>(j*8));
    uchar enc_local[16]; for(int i=0;i<16;i++) enc_local[i]=enc[i];
    uchar dec[16]; aes_dec(AESKey, enc_local, dec);
    uchar sig[8]={0xc4,0x3d,0x7b,0x00,0x40,0x07,0x00,0x00};
    uchar ok=1;
    for(int i=0;i<8;i++) if((uchar)(dec[i]^AESInit[i])!=sig[i]){ ok=0; break; }
    result[gid] = ok ? 1 : 0;
}
)METAL";

namespace {
const char *backend_name = "metal";
int metal_available() { return MTLCreateSystemDefaultDevice() != nil ? 1 : 0; }

int run_batch(const rar3_target *t, const rar3_batch *b,
              uint64_t *match_index, rar3_progress_cb cb, void *user) {
    @autoreleasepool {
        id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
        if (!dev) return -1;
        NSError *err = nil;
        id<MTLLibrary> lib = [dev newLibraryWithSource:[NSString stringWithUTF8String:kMSL]
                                               options:nil error:&err];
        if (!lib) {
            fprintf(stderr, "[metal] compile error: %s\n",
                    err ? [[err localizedDescription] UTF8String] : "unknown");
            return -1;
        }
        id<MTLFunction> fn = [lib newFunctionWithName:@"rar3_crack"];
        if (!fn) { fprintf(stderr,"[metal] function not found\n"); return -1; }
        id<MTLComputePipelineState> pipe = [dev newComputePipelineStateWithFunction:fn error:&err];
        if (!pipe) { fprintf(stderr,"[metal] pipeline error\n"); return -1; }

        id<MTLCommandQueue> q = [dev newCommandQueue];
        auto t0 = std::chrono::steady_clock::now();

        uint64_t total = b->count;
        uint64_t hitidx = 0; int hit = 0;
        const uint64_t CHUNK = 200000;

        for (uint64_t base = 0; base < total && !hit; base += CHUNK) {
            uint64_t n = std::min<uint64_t>(CHUNK, total - base);
            id<MTLBuffer> pwM  = [dev newBufferWithBytes:(b->pw + base)
                                                  length:n*16 options:MTLResourceStorageModeShared];
            id<MTLBuffer> lenM = [dev newBufferWithBytes:(b->pwlen + base)
                                                  length:n options:MTLResourceStorageModeShared];
            id<MTLBuffer> saltM= [dev newBufferWithBytes:t->salt length:8 options:MTLResourceStorageModeShared];
            id<MTLBuffer> encM = [dev newBufferWithBytes:t->enc length:16 options:MTLResourceStorageModeShared];
            std::vector<int32_t> res(n, 0);
            id<MTLBuffer> resM = [dev newBufferWithBytes:res.data() length:n*4 options:MTLResourceStorageModeShared];
            uint32_t nn = (uint32_t)n;
            id<MTLBuffer> cntM = [dev newBufferWithBytes:&nn length:4 options:MTLResourceStorageModeShared];

            id<MTLCommandBuffer> cbuf = [q commandBuffer];
            id<MTLComputeCommandEncoder> ce = [cbuf computeCommandEncoder];
            [ce setComputePipelineState:pipe];
            [ce setBuffer:pwM offset:0 atIndex:0];
            [ce setBuffer:lenM offset:0 atIndex:1];
            [ce setBuffer:saltM offset:0 atIndex:2];
            [ce setBuffer:encM offset:0 atIndex:3];
            [ce setBuffer:resM offset:0 atIndex:4];
            [ce setBuffer:cntM offset:0 atIndex:5];
            NSUInteger tg = std::min<NSUInteger>(pipe.maxTotalThreadsPerThreadgroup, 256);
            [ce dispatchThreads:MTLSizeMake(n,1,1) threadsPerThreadgroup:MTLSizeMake(tg,1,1)];
            [ce endEncoding];
            [cbuf commit];
            [cbuf waitUntilCompleted];

            int32_t *rp = (int32_t*)resM.contents;
            for (uint64_t i = 0; i < n; i++) if (rp[i] == 1) { hit = 1; hitidx = base + i; break; }

            /* Release per-chunk buffers immediately so no GPU allocation lingers
             * between chunks (prevent the "GPU stays pinned at 100%" issue). */
#if __has_feature(objc_arc)
            /* ARC: scope ends each iteration, objects released automatically. */
#else
            [pwM release]; [lenM release]; [saltM release];
            [encM release]; [resM release]; [cntM release];
#endif

            if (cb) {
                double el = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                if (!cb(user, base + n, total, el)) break;
            }
        }

        /* ---- GPU drain: force a final empty submission and wait, then let the
         * driver settle. Helps the hardware/OS drop out of the max performance
         * state promptly instead of leaving the utilization gauge pinned at 100%. */
        {
            id<MTLCommandBuffer> draincb = [q commandBuffer];
            [draincb commit];
            [draincb waitUntilCompleted];
        }
#if !__has_feature(objc_arc)
        [pipe release]; [fn release]; [lib release]; [q release];
#endif
        if (hit) { *match_index = hitidx; return 1; }
        return 0;
    }
}
} // namespace

const rar3_backend *rar3_backend_metal(void) {
    static rar3_backend be = { "metal", run_batch, metal_available };
    return &be;
}
