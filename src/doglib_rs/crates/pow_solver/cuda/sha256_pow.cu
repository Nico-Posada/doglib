/*
 * sha256_pow.cu  –  SHA-256 proof-of-work brute-forcer
 *
 * Optimisations applied (guided by Hashcat inc_hash_sha256.h):
 *   - LOP3.LUT for Ch/Maj: any 3-input boolean in 1 clock on NVIDIA hardware
 *   - __funnelshift_r for ROTR: single hardware instruction
 *   - Odometer-based suffix generation: zero 64-bit division in the hot loop
 *   - Shared-memory found flag (s_found): intra-block early exit without globals
 *   - BATCH=64 inner loop: amortises global-flag check across 64 hashes/thread
 *   - #pragma unroll on all inner loops
 *
 * Kernel parameters (all passed as pointers — no __constant__ memory):
 *   base_counter     : first counter value for this launch
 *   init_state       : 8 x u32 big-endian SHA-256 initial state (IV or mid-state)
 *   tmpl             : 16 x u32 big-endian SHA block template (prefix + padding)
 *   charset          : raw charset bytes
 *   charset_len      : number of bytes in charset
 *   suffix_byte_off  : byte offset inside the 64-byte block where suffix starts
 *   suffix_len       : number of suffix bytes to brute-force
 *   bits             : required zero-bit count
 *   leading          : 1 = leading zeros, 0 = trailing zeros
 *   found            : OUT global flag (0 = not found, 1 = found)
 *   result           : OUT winning counter value
 */

typedef unsigned int       u32;
typedef unsigned long long u64;
typedef unsigned char      u8;

#define BATCH 64

/* ── hardware intrinsics ───────────────────────────────────────────────────── */

static __device__ __forceinline__ u32 rotr(u32 x, u32 n) {
    return __funnelshift_r(x, x, n);
}

/* LOP3.LUT: evaluate any 3-input boolean in a single NVIDIA clock.
   The 8-bit LUT encodes the truth table for (a,b,c) = (1,0,0)..(1,1,1).
   Ch (choose):  (x & y) ^ (~x & z)  → LUT = 0xca
   Maj (majority): (x & y) ^ (x & z) ^ (y & z) → LUT = 0xe8            */
template<int lut>
static __device__ __forceinline__ u32 lop3(u32 a, u32 b, u32 c) {
    u32 r;
    asm("lop3.b32 %0, %1, %2, %3, %4;" : "=r"(r) : "r"(a), "r"(b), "r"(c), "n"(lut));
    return r;
}

#define Ch(x,y,z)  lop3<0xca>(x,y,z)
#define Maj(x,y,z) lop3<0xe8>(x,y,z)

/* ── SHA-256 sigma functions ───────────────────────────────────────────────── */
#define S0(x)  (rotr(x,2)  ^ rotr(x,13) ^ rotr(x,22))
#define S1(x)  (rotr(x,6)  ^ rotr(x,11) ^ rotr(x,25))
#define s0(x)  (rotr(x,7)  ^ rotr(x,18) ^ ((x) >> 3))
#define s1(x)  (rotr(x,17) ^ rotr(x,19) ^ ((x) >> 10))

/* ── round macro — Hashcat style: only h and d are modified per round.
   The parameter order rotates by 1 each call, so all 8 state values stay
   live in registers without any extra move instructions.                  */
#define R(a,b,c,d,e,f,g,h,w,k) \
{ \
    (h) += (k) + (w) + S1(e) + Ch(e,f,g); \
    (d) += (h); \
    (h) += S0(a) + Maj(a,b,c); \
}

/* ── message schedule expansion ─────────────────────────────────────────────
   Each EXP() call produces one new schedule word from its four predecessors.
   Stored as w0..w15 in a rotating window (w16 aliases w0, etc.).           */
#define EXP(a,b,c,d) (s1(a) + (b) + s0(c) + (d))

/* ── SHA-256 round constants ─────────────────────────────────────────────── */
__device__ __constant__ u32 K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,
    0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,
    0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,
    0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,
    0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,
    0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u,
};

/* ── check helpers ───────────────────────────────────────────────────────── */
static __device__ __forceinline__ int check_leading(u32 h0, u32 h1, int bits) {
    if (bits <= 0)  return 1;
    if (bits <= 32) return (h0 >> (32 - bits)) == 0u;
    if (h0 != 0)    return 0;
    bits -= 32;
    if (bits <= 32) return (h1 >> (32 - bits)) == 0u;
    return 0;
}

static __device__ __forceinline__ int check_trailing(u32 h6, u32 h7, int bits) {
    /* h7 is the last word of the digest (big-endian → lowest address = MSB of h7
       is byte 28, LSB is byte 31 = last byte).                               */
    if (bits <= 0)  return 1;
    if (bits <= 32) return (h7 << (32 - bits)) == 0u;
    if (h7 != 0)    return 0;
    bits -= 32;
    if (bits <= 32) return (h6 << (32 - bits)) == 0u;
    return 0;
}

/* ── main kernel ─────────────────────────────────────────────────────────── */
extern "C" __global__ void sha256_pow(
    u64            base_counter,
    const u32* __restrict__ init_state,
    const u32* __restrict__ tmpl,
    const u8*  __restrict__ charset,
    int  charset_len,
    int  suffix_byte_off,
    int  suffix_len,
    int  bits,
    int  leading,
    u32* found,
    u64* result
) {
    __shared__ u32 s_found;
    if (threadIdx.x == 0) s_found = 0;
    __syncthreads();

    const int tid = (int)(blockIdx.x * blockDim.x + threadIdx.x);
    u64 thread_start = base_counter + (u64)tid * BATCH;

    /* Load init state into registers */
    u32 iv0 = init_state[0], iv1 = init_state[1], iv2 = init_state[2], iv3 = init_state[3];
    u32 iv4 = init_state[4], iv5 = init_state[5], iv6 = init_state[6], iv7 = init_state[7];

    /* Initialise odometer from thread_start (suffix_len divisions, done ONCE) */
    u8 idx[8];
    {
        u64 tmp = thread_start;
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            idx[i] = (i < suffix_len) ? (u8)(tmp % charset_len) : 0;
            if (i < suffix_len) tmp /= charset_len;
        }
    }

    #pragma unroll 1
    for (int b = 0; b < BATCH; b++) {
        /* Early-exit via shared flag */
        if (s_found) return;

        /* Build the 16-word message schedule from template */
        u32 w0, w1, w2, w3, w4, w5, w6, w7,
            w8, w9, w10, w11, w12, w13, w14, w15;
        w0  = tmpl[0];  w1  = tmpl[1];  w2  = tmpl[2];  w3  = tmpl[3];
        w4  = tmpl[4];  w5  = tmpl[5];  w6  = tmpl[6];  w7  = tmpl[7];
        w8  = tmpl[8];  w9  = tmpl[9];  w10 = tmpl[10]; w11 = tmpl[11];
        w12 = tmpl[12]; w13 = tmpl[13]; w14 = tmpl[14]; w15 = tmpl[15];

        /* Patch suffix bytes into the word array.
           suffix byte i lives at block byte (suffix_byte_off + i).
           In big-endian words: word index = pos/4, shift = (3 - pos%4)*8      */
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            if (i >= suffix_len) break;
            int pos   = suffix_byte_off + i;
            int widx  = pos >> 2;
            int shift = (3 - (pos & 3)) << 3;
            u32 byte  = (u32)charset[idx[i]];
            /* clear that byte in the word, then OR in the new byte */
            switch (widx) {
                case  0: w0  = (w0  & ~(0xFFu << shift)) | (byte << shift); break;
                case  1: w1  = (w1  & ~(0xFFu << shift)) | (byte << shift); break;
                case  2: w2  = (w2  & ~(0xFFu << shift)) | (byte << shift); break;
                case  3: w3  = (w3  & ~(0xFFu << shift)) | (byte << shift); break;
                case  4: w4  = (w4  & ~(0xFFu << shift)) | (byte << shift); break;
                case  5: w5  = (w5  & ~(0xFFu << shift)) | (byte << shift); break;
                case  6: w6  = (w6  & ~(0xFFu << shift)) | (byte << shift); break;
                case  7: w7  = (w7  & ~(0xFFu << shift)) | (byte << shift); break;
                case  8: w8  = (w8  & ~(0xFFu << shift)) | (byte << shift); break;
                case  9: w9  = (w9  & ~(0xFFu << shift)) | (byte << shift); break;
                case 10: w10 = (w10 & ~(0xFFu << shift)) | (byte << shift); break;
                case 11: w11 = (w11 & ~(0xFFu << shift)) | (byte << shift); break;
                case 12: w12 = (w12 & ~(0xFFu << shift)) | (byte << shift); break;
                case 13: w13 = (w13 & ~(0xFFu << shift)) | (byte << shift); break;
            }
        }

        /* SHA-256 compression */
        u32 a=iv0, b_=iv1, c=iv2, d=iv3, e=iv4, f=iv5, g=iv6, h=iv7;

        R(a,b_,c,d,e,f,g,h, w0,  K256[ 0])
        R(h,a, b_,c,d,e,f,g, w1,  K256[ 1])
        R(g,h, a, b_,c,d,e,f, w2,  K256[ 2])
        R(f,g, h, a, b_,c,d,e, w3,  K256[ 3])
        R(e,f, g, h, a, b_,c,d, w4,  K256[ 4])
        R(d,e, f, g, h, a, b_,c, w5,  K256[ 5])
        R(c,d, e, f, g, h, a, b_, w6,  K256[ 6])
        R(b_,c,d, e, f, g, h, a, w7,  K256[ 7])
        R(a,b_,c,d,e,f,g,h, w8,  K256[ 8])
        R(h,a, b_,c,d,e,f,g, w9,  K256[ 9])
        R(g,h, a, b_,c,d,e,f, w10, K256[10])
        R(f,g, h, a, b_,c,d,e, w11, K256[11])
        R(e,f, g, h, a, b_,c,d, w12, K256[12])
        R(d,e, f, g, h, a, b_,c, w13, K256[13])
        R(c,d, e, f, g, h, a, b_, w14, K256[14])
        R(b_,c,d, e, f, g, h, a, w15, K256[15])

        u32 w16 = EXP(w14,w9,w1,w0);
        R(a,b_,c,d,e,f,g,h, w16, K256[16])
        u32 w17 = EXP(w15,w10,w2,w1);
        R(h,a, b_,c,d,e,f,g, w17, K256[17])
        u32 w18 = EXP(w16,w11,w3,w2);
        R(g,h, a, b_,c,d,e,f, w18, K256[18])
        u32 w19 = EXP(w17,w12,w4,w3);
        R(f,g, h, a, b_,c,d,e, w19, K256[19])
        u32 w20 = EXP(w18,w13,w5,w4);
        R(e,f, g, h, a, b_,c,d, w20, K256[20])
        u32 w21 = EXP(w19,w14,w6,w5);
        R(d,e, f, g, h, a, b_,c, w21, K256[21])
        u32 w22 = EXP(w20,w15,w7,w6);
        R(c,d, e, f, g, h, a, b_, w22, K256[22])
        u32 w23 = EXP(w21,w16,w8,w7);
        R(b_,c,d, e, f, g, h, a, w23, K256[23])
        u32 w24 = EXP(w22,w17,w9,w8);
        R(a,b_,c,d,e,f,g,h, w24, K256[24])
        u32 w25 = EXP(w23,w18,w10,w9);
        R(h,a, b_,c,d,e,f,g, w25, K256[25])
        u32 w26 = EXP(w24,w19,w11,w10);
        R(g,h, a, b_,c,d,e,f, w26, K256[26])
        u32 w27 = EXP(w25,w20,w12,w11);
        R(f,g, h, a, b_,c,d,e, w27, K256[27])
        u32 w28 = EXP(w26,w21,w13,w12);
        R(e,f, g, h, a, b_,c,d, w28, K256[28])
        u32 w29 = EXP(w27,w22,w14,w13);
        R(d,e, f, g, h, a, b_,c, w29, K256[29])
        u32 w30 = EXP(w28,w23,w15,w14);
        R(c,d, e, f, g, h, a, b_, w30, K256[30])
        u32 w31 = EXP(w29,w24,w16,w15);
        R(b_,c,d, e, f, g, h, a, w31, K256[31])
        u32 w32 = EXP(w30,w25,w17,w16);
        R(a,b_,c,d,e,f,g,h, w32, K256[32])
        u32 w33 = EXP(w31,w26,w18,w17);
        R(h,a, b_,c,d,e,f,g, w33, K256[33])
        u32 w34 = EXP(w32,w27,w19,w18);
        R(g,h, a, b_,c,d,e,f, w34, K256[34])
        u32 w35 = EXP(w33,w28,w20,w19);
        R(f,g, h, a, b_,c,d,e, w35, K256[35])
        u32 w36 = EXP(w34,w29,w21,w20);
        R(e,f, g, h, a, b_,c,d, w36, K256[36])
        u32 w37 = EXP(w35,w30,w22,w21);
        R(d,e, f, g, h, a, b_,c, w37, K256[37])
        u32 w38 = EXP(w36,w31,w23,w22);
        R(c,d, e, f, g, h, a, b_, w38, K256[38])
        u32 w39 = EXP(w37,w32,w24,w23);
        R(b_,c,d, e, f, g, h, a, w39, K256[39])
        u32 w40 = EXP(w38,w33,w25,w24);
        R(a,b_,c,d,e,f,g,h, w40, K256[40])
        u32 w41 = EXP(w39,w34,w26,w25);
        R(h,a, b_,c,d,e,f,g, w41, K256[41])
        u32 w42 = EXP(w40,w35,w27,w26);
        R(g,h, a, b_,c,d,e,f, w42, K256[42])
        u32 w43 = EXP(w41,w36,w28,w27);
        R(f,g, h, a, b_,c,d,e, w43, K256[43])
        u32 w44 = EXP(w42,w37,w29,w28);
        R(e,f, g, h, a, b_,c,d, w44, K256[44])
        u32 w45 = EXP(w43,w38,w30,w29);
        R(d,e, f, g, h, a, b_,c, w45, K256[45])
        u32 w46 = EXP(w44,w39,w31,w30);
        R(c,d, e, f, g, h, a, b_, w46, K256[46])
        u32 w47 = EXP(w45,w40,w32,w31);
        R(b_,c,d, e, f, g, h, a, w47, K256[47])
        u32 w48 = EXP(w46,w41,w33,w32);
        R(a,b_,c,d,e,f,g,h, w48, K256[48])
        u32 w49 = EXP(w47,w42,w34,w33);
        R(h,a, b_,c,d,e,f,g, w49, K256[49])
        u32 w50 = EXP(w48,w43,w35,w34);
        R(g,h, a, b_,c,d,e,f, w50, K256[50])
        u32 w51 = EXP(w49,w44,w36,w35);
        R(f,g, h, a, b_,c,d,e, w51, K256[51])
        u32 w52 = EXP(w50,w45,w37,w36);
        R(e,f, g, h, a, b_,c,d, w52, K256[52])
        u32 w53 = EXP(w51,w46,w38,w37);
        R(d,e, f, g, h, a, b_,c, w53, K256[53])
        u32 w54 = EXP(w52,w47,w39,w38);
        R(c,d, e, f, g, h, a, b_, w54, K256[54])
        u32 w55 = EXP(w53,w48,w40,w39);
        R(b_,c,d, e, f, g, h, a, w55, K256[55])
        u32 w56 = EXP(w54,w49,w41,w40);
        R(a,b_,c,d,e,f,g,h, w56, K256[56])
        u32 w57 = EXP(w55,w50,w42,w41);
        R(h,a, b_,c,d,e,f,g, w57, K256[57])
        u32 w58 = EXP(w56,w51,w43,w42);
        R(g,h, a, b_,c,d,e,f, w58, K256[58])
        u32 w59 = EXP(w57,w52,w44,w43);
        R(f,g, h, a, b_,c,d,e, w59, K256[59])
        u32 w60 = EXP(w58,w53,w45,w44);
        R(e,f, g, h, a, b_,c,d, w60, K256[60])
        u32 w61 = EXP(w59,w54,w46,w45);
        R(d,e, f, g, h, a, b_,c, w61, K256[61])
        u32 w62 = EXP(w60,w55,w47,w46);
        R(c,d, e, f, g, h, a, b_, w62, K256[62])
        u32 w63 = EXP(w61,w56,w48,w47);
        R(b_,c,d, e, f, g, h, a, w63, K256[63])

        /* Finalise digest (add IV) */
        u32 d0 = iv0 + a;
        u32 d1 = iv1 + b_;

        int match;
        if (leading) {
            match = check_leading(d0, d1, bits);
        } else {
            u32 d6 = iv6 + g;
            u32 d7 = iv7 + h;
            match = check_trailing(d6, d7, bits);
        }

        if (match) {
            s_found = 1;
            if (atomicCAS(found, 0u, 1u) == 0u)
                *result = thread_start + (u64)b;
            return;
        }

        /* Odometer carry-increment (zero divisions) */
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            if (i >= suffix_len) break;
            idx[i]++;
            if ((int)idx[i] < charset_len) break;
            idx[i] = 0;
        }
    }
}
