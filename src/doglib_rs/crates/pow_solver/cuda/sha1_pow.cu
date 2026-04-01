/*
 * sha1_pow.cu  –  SHA-1 proof-of-work brute-forcer
 *
 * Optimisations applied (guided by Hashcat inc_hash_sha1.h):
 *   - LOP3.LUT for Ch/Maj/XOR3: any 3-input boolean in 1 clock on NVIDIA
 *   - __funnelshift_lc for ROTL: single hardware instruction
 *   - Odometer-based suffix generation: zero 64-bit division in the hot loop
 *   - Shared-memory found flag (s_found): intra-block early exit
 *   - BATCH=64 inner loop: amortises global-flag check
 *   - Fully unrolled 80 rounds
 *   - Template on SL (suffix length): fully unrolled loops, fixed-size register
 *     arrays, no dead iterations or branch overhead per candidate
 *   - Template word load hoisted outside BATCH loop: 16 global reads total per
 *     thread (was 16 × BATCH = 1024 reads)
 *   - Loop-invariant suffix-patch parameters (widx, shift, mask) precomputed
 *     once outside the BATCH loop
 *
 * SHA-1 boolean functions (80 rounds in 4 groups of 20):
 *   F0  rounds  0-19: Ch  (x & y) | (~x & z)  → LUT = 0xca  (same as SHA-256 Ch)
 *   F1  rounds 20-39: Parity  x ^ y ^ z        → LUT = 0x96
 *   F2  rounds 40-59: Maj  (x & y) | (x & z) | (y & z) → LUT = 0xe8
 *   F3  rounds 60-79: Parity  x ^ y ^ z        → LUT = 0x96
 */

typedef unsigned int       u32;
typedef unsigned long long u64;
typedef unsigned char      u8;

#define BATCH 64

/* ── hardware intrinsics ───────────────────────────────────────────────────── */

static __device__ __forceinline__ u32 rotl(u32 x, u32 n) {
    return __funnelshift_lc(x, x, n);
}

template<int lut>
static __device__ __forceinline__ u32 lop3(u32 a, u32 b, u32 c) {
    u32 r;
    asm("lop3.b32 %0, %1, %2, %3, %4;" : "=r"(r) : "r"(a), "r"(b), "r"(c), "n"(lut));
    return r;
}

#define F0(x,y,z) lop3<0xca>(x,y,z)   /* Ch      rounds  0-19 */
#define F1(x,y,z) lop3<0x96>(x,y,z)   /* Parity  rounds 20-39 */
#define F2(x,y,z) lop3<0xe8>(x,y,z)   /* Maj     rounds 40-59 */
#define F3(x,y,z) lop3<0x96>(x,y,z)   /* Parity  rounds 60-79 */

/* ── SHA-1 round constants ────────────────────────────────────────────────── */
#define K0 0x5a827999u
#define K1 0x6ed9eba1u
#define K2 0x8f1bbcdcu
#define K3 0xca62c1d6u

/* ── round macro ─────────────────────────────────────────────────────────── */
#define SHA1_STEP(F,K,a,b,c,d,e,w) \
{ \
    (e) += (K) + (w) + F(b,c,d) + rotl(a,5u); \
    (b)  = rotl(b,30u); \
}

/* ── schedule expansion ─────────────────────────────────────────────────── */
#define W_EXP(w3,w8,w14,w16) rotl((w3)^(w8)^(w14)^(w16), 1u)

/* ── check helpers ───────────────────────────────────────────────────────── */
static __device__ __forceinline__ int check_leading(u32 h0, u32 h1, int bits) {
    if (bits <= 0)  return 1;
    if (bits <= 32) return (h0 >> (32 - bits)) == 0u;
    if (h0 != 0)    return 0;
    bits -= 32;
    if (bits <= 32) return (h1 >> (32 - bits)) == 0u;
    return 0;
}

static __device__ __forceinline__ int check_trailing(u32 h3, u32 h4, int bits) {
    if (bits <= 0)  return 1;
    if (bits <= 32) return (h4 << (32 - bits)) == 0u;
    if (h4 != 0)    return 0;
    bits -= 32;
    if (bits <= 32) return (h3 << (32 - bits)) == 0u;
    return 0;
}

/* ── SHA-1 IV ────────────────────────────────────────────────────────────── */
#define SHA1_H0 0x67452301u
#define SHA1_H1 0xefcdab89u
#define SHA1_H2 0x98badcfeu
#define SHA1_H3 0x10325476u
#define SHA1_H4 0xc3d2e1f0u

/* ── template kernel implementation ─────────────────────────────────────── */
/*
 * SL:          suffix length (compile-time constant).
 * STANDARD_IV: when true, initialise from the compile-time SHA-1 IV constants
 *              instead of loading init_state[] from global memory.  For all
 *              CTF PoW cases where prefix < 56 bytes the Rust side passes the
 *              standard IV, so this eliminates 5 physical registers and raises
 *              SM occupancy from 75 % → ~94 % on Ada (sm_89).
 *
 * Callers are the extern "C" wrappers sha1_pow_1_s .. sha1_pow_8_s (standard
 * IV) and sha1_pow_1_c .. sha1_pow_8_c (custom IV / mid-state).
 */
template<int SL, bool STANDARD_IV>
static __device__ __forceinline__ void sha1_pow_impl(
    u64            base_counter,
    const u32* __restrict__ init_state,
    const u32* __restrict__ tmpl,
    const u8*  __restrict__ charset,
    int  charset_len,
    int  suffix_byte_off,
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

    /* When STANDARD_IV is a compile-time true, the compiler folds these into
       immediate constants and reclaims 5 physical registers.                 */
    u32 iv0 = STANDARD_IV ? SHA1_H0 : init_state[0];
    u32 iv1 = STANDARD_IV ? SHA1_H1 : init_state[1];
    u32 iv2 = STANDARD_IV ? SHA1_H2 : init_state[2];
    u32 iv3 = STANDARD_IV ? SHA1_H3 : init_state[3];
    u32 iv4 = STANDARD_IV ? SHA1_H4 : init_state[4];

    /* ── Load template once into base registers (hoisted from BATCH loop) ── */
    u32 b0  = tmpl[0],  b1  = tmpl[1],  b2  = tmpl[2],  b3  = tmpl[3],
        b4  = tmpl[4],  b5  = tmpl[5],  b6  = tmpl[6],  b7  = tmpl[7],
        b8  = tmpl[8],  b9  = tmpl[9],  b10 = tmpl[10], b11 = tmpl[11],
        b12 = tmpl[12], b13 = tmpl[13], b14 = tmpl[14], b15 = tmpl[15];

    /* ── Precompute suffix patch parameters once (loop-invariant) ── */
    /* SL is a compile-time constant so these arrays have fixed size → registers */
    int widx_[SL], shift_[SL];
    u32 mask_[SL];
    #pragma unroll
    for (int i = 0; i < SL; i++) {
        int pos   = suffix_byte_off + i;
        widx_[i]  = pos >> 2;
        shift_[i] = (3 - (pos & 3)) << 3;
        mask_[i]  = ~(0xFFu << shift_[i]);
    }

    /* ── Initialise odometer (SL divisions total, outside hot loop) ── */
    u8 idx[SL];
    {
        u64 tmp = thread_start;
        #pragma unroll
        for (int i = 0; i < SL; i++) {
            idx[i] = (u8)(tmp % (u64)charset_len);
            tmp /= (u64)charset_len;
        }
    }

    #pragma unroll 1
    for (int b_iter = 0; b_iter < BATCH; b_iter++) {
        if (s_found) return;

        /* Copy base template into working registers */
        u32 w0=b0,  w1=b1,  w2=b2,  w3=b3,  w4=b4,  w5=b5,  w6=b6,  w7=b7,
            w8=b8,  w9=b9,  w10=b10,w11=b11,w12=b12,w13=b13,w14=b14,w15=b15;

        /* Apply suffix patches using precomputed constants */
        #pragma unroll
        for (int i = 0; i < SL; i++) {
            u32 byte = (u32)__ldg(&charset[idx[i]]);
            u32 val  = byte << shift_[i];
            switch (widx_[i]) {
                case  0: w0  = (w0  & mask_[i]) | val; break;
                case  1: w1  = (w1  & mask_[i]) | val; break;
                case  2: w2  = (w2  & mask_[i]) | val; break;
                case  3: w3  = (w3  & mask_[i]) | val; break;
                case  4: w4  = (w4  & mask_[i]) | val; break;
                case  5: w5  = (w5  & mask_[i]) | val; break;
                case  6: w6  = (w6  & mask_[i]) | val; break;
                case  7: w7  = (w7  & mask_[i]) | val; break;
                case  8: w8  = (w8  & mask_[i]) | val; break;
                case  9: w9  = (w9  & mask_[i]) | val; break;
                case 10: w10 = (w10 & mask_[i]) | val; break;
                case 11: w11 = (w11 & mask_[i]) | val; break;
                case 12: w12 = (w12 & mask_[i]) | val; break;
                case 13: w13 = (w13 & mask_[i]) | val; break;
            }
        }

        /* SHA-1 compression — 80 rounds, fully unrolled */
        u32 a=iv0, b_=iv1, c=iv2, d=iv3, e=iv4;

        /* Rounds 0-15: raw words */
        SHA1_STEP(F0,K0, a,b_,c,d,e, w0)
        SHA1_STEP(F0,K0, e,a, b_,c,d, w1)
        SHA1_STEP(F0,K0, d,e, a, b_,c, w2)
        SHA1_STEP(F0,K0, c,d, e, a, b_, w3)
        SHA1_STEP(F0,K0, b_,c,d, e, a, w4)
        SHA1_STEP(F0,K0, a,b_,c,d,e, w5)
        SHA1_STEP(F0,K0, e,a, b_,c,d, w6)
        SHA1_STEP(F0,K0, d,e, a, b_,c, w7)
        SHA1_STEP(F0,K0, c,d, e, a, b_, w8)
        SHA1_STEP(F0,K0, b_,c,d, e, a, w9)
        SHA1_STEP(F0,K0, a,b_,c,d,e, w10)
        SHA1_STEP(F0,K0, e,a, b_,c,d, w11)
        SHA1_STEP(F0,K0, d,e, a, b_,c, w12)
        SHA1_STEP(F0,K0, c,d, e, a, b_, w13)
        SHA1_STEP(F0,K0, b_,c,d, e, a, w14)
        SHA1_STEP(F0,K0, a,b_,c,d,e, w15)

        /* Rounds 16-19: first expanded words */
        u32 w16 = W_EXP(w13,w8,w2,w0);
        SHA1_STEP(F0,K0, e,a, b_,c,d, w16)
        u32 w17 = W_EXP(w14,w9,w3,w1);
        SHA1_STEP(F0,K0, d,e, a, b_,c, w17)
        u32 w18 = W_EXP(w15,w10,w4,w2);
        SHA1_STEP(F0,K0, c,d, e, a, b_, w18)
        u32 w19 = W_EXP(w16,w11,w5,w3);
        SHA1_STEP(F0,K0, b_,c,d, e, a, w19)

        /* Rounds 20-39: F1 (parity) */
        u32 w20 = W_EXP(w17,w12,w6,w4);
        SHA1_STEP(F1,K1, a,b_,c,d,e, w20)
        u32 w21 = W_EXP(w18,w13,w7,w5);
        SHA1_STEP(F1,K1, e,a, b_,c,d, w21)
        u32 w22 = W_EXP(w19,w14,w8,w6);
        SHA1_STEP(F1,K1, d,e, a, b_,c, w22)
        u32 w23 = W_EXP(w20,w15,w9,w7);
        SHA1_STEP(F1,K1, c,d, e, a, b_, w23)
        u32 w24 = W_EXP(w21,w16,w10,w8);
        SHA1_STEP(F1,K1, b_,c,d, e, a, w24)
        u32 w25 = W_EXP(w22,w17,w11,w9);
        SHA1_STEP(F1,K1, a,b_,c,d,e, w25)
        u32 w26 = W_EXP(w23,w18,w12,w10);
        SHA1_STEP(F1,K1, e,a, b_,c,d, w26)
        u32 w27 = W_EXP(w24,w19,w13,w11);
        SHA1_STEP(F1,K1, d,e, a, b_,c, w27)
        u32 w28 = W_EXP(w25,w20,w14,w12);
        SHA1_STEP(F1,K1, c,d, e, a, b_, w28)
        u32 w29 = W_EXP(w26,w21,w15,w13);
        SHA1_STEP(F1,K1, b_,c,d, e, a, w29)
        u32 w30 = W_EXP(w27,w22,w16,w14);
        SHA1_STEP(F1,K1, a,b_,c,d,e, w30)
        u32 w31 = W_EXP(w28,w23,w17,w15);
        SHA1_STEP(F1,K1, e,a, b_,c,d, w31)
        u32 w32 = W_EXP(w29,w24,w18,w16);
        SHA1_STEP(F1,K1, d,e, a, b_,c, w32)
        u32 w33 = W_EXP(w30,w25,w19,w17);
        SHA1_STEP(F1,K1, c,d, e, a, b_, w33)
        u32 w34 = W_EXP(w31,w26,w20,w18);
        SHA1_STEP(F1,K1, b_,c,d, e, a, w34)
        u32 w35 = W_EXP(w32,w27,w21,w19);
        SHA1_STEP(F1,K1, a,b_,c,d,e, w35)
        u32 w36 = W_EXP(w33,w28,w22,w20);
        SHA1_STEP(F1,K1, e,a, b_,c,d, w36)
        u32 w37 = W_EXP(w34,w29,w23,w21);
        SHA1_STEP(F1,K1, d,e, a, b_,c, w37)
        u32 w38 = W_EXP(w35,w30,w24,w22);
        SHA1_STEP(F1,K1, c,d, e, a, b_, w38)
        u32 w39 = W_EXP(w36,w31,w25,w23);
        SHA1_STEP(F1,K1, b_,c,d, e, a, w39)

        /* Rounds 40-59: F2 (majority) */
        u32 w40 = W_EXP(w37,w32,w26,w24);
        SHA1_STEP(F2,K2, a,b_,c,d,e, w40)
        u32 w41 = W_EXP(w38,w33,w27,w25);
        SHA1_STEP(F2,K2, e,a, b_,c,d, w41)
        u32 w42 = W_EXP(w39,w34,w28,w26);
        SHA1_STEP(F2,K2, d,e, a, b_,c, w42)
        u32 w43 = W_EXP(w40,w35,w29,w27);
        SHA1_STEP(F2,K2, c,d, e, a, b_, w43)
        u32 w44 = W_EXP(w41,w36,w30,w28);
        SHA1_STEP(F2,K2, b_,c,d, e, a, w44)
        u32 w45 = W_EXP(w42,w37,w31,w29);
        SHA1_STEP(F2,K2, a,b_,c,d,e, w45)
        u32 w46 = W_EXP(w43,w38,w32,w30);
        SHA1_STEP(F2,K2, e,a, b_,c,d, w46)
        u32 w47 = W_EXP(w44,w39,w33,w31);
        SHA1_STEP(F2,K2, d,e, a, b_,c, w47)
        u32 w48 = W_EXP(w45,w40,w34,w32);
        SHA1_STEP(F2,K2, c,d, e, a, b_, w48)
        u32 w49 = W_EXP(w46,w41,w35,w33);
        SHA1_STEP(F2,K2, b_,c,d, e, a, w49)
        u32 w50 = W_EXP(w47,w42,w36,w34);
        SHA1_STEP(F2,K2, a,b_,c,d,e, w50)
        u32 w51 = W_EXP(w48,w43,w37,w35);
        SHA1_STEP(F2,K2, e,a, b_,c,d, w51)
        u32 w52 = W_EXP(w49,w44,w38,w36);
        SHA1_STEP(F2,K2, d,e, a, b_,c, w52)
        u32 w53 = W_EXP(w50,w45,w39,w37);
        SHA1_STEP(F2,K2, c,d, e, a, b_, w53)
        u32 w54 = W_EXP(w51,w46,w40,w38);
        SHA1_STEP(F2,K2, b_,c,d, e, a, w54)
        u32 w55 = W_EXP(w52,w47,w41,w39);
        SHA1_STEP(F2,K2, a,b_,c,d,e, w55)
        u32 w56 = W_EXP(w53,w48,w42,w40);
        SHA1_STEP(F2,K2, e,a, b_,c,d, w56)
        u32 w57 = W_EXP(w54,w49,w43,w41);
        SHA1_STEP(F2,K2, d,e, a, b_,c, w57)
        u32 w58 = W_EXP(w55,w50,w44,w42);
        SHA1_STEP(F2,K2, c,d, e, a, b_, w58)
        u32 w59 = W_EXP(w56,w51,w45,w43);
        SHA1_STEP(F2,K2, b_,c,d, e, a, w59)

        /* Rounds 60-79: F3 (parity) */
        u32 w60 = W_EXP(w57,w52,w46,w44);
        SHA1_STEP(F3,K3, a,b_,c,d,e, w60)
        u32 w61 = W_EXP(w58,w53,w47,w45);
        SHA1_STEP(F3,K3, e,a, b_,c,d, w61)
        u32 w62 = W_EXP(w59,w54,w48,w46);
        SHA1_STEP(F3,K3, d,e, a, b_,c, w62)
        u32 w63 = W_EXP(w60,w55,w49,w47);
        SHA1_STEP(F3,K3, c,d, e, a, b_, w63)
        u32 w64 = W_EXP(w61,w56,w50,w48);
        SHA1_STEP(F3,K3, b_,c,d, e, a, w64)
        u32 w65 = W_EXP(w62,w57,w51,w49);
        SHA1_STEP(F3,K3, a,b_,c,d,e, w65)
        u32 w66 = W_EXP(w63,w58,w52,w50);
        SHA1_STEP(F3,K3, e,a, b_,c,d, w66)
        u32 w67 = W_EXP(w64,w59,w53,w51);
        SHA1_STEP(F3,K3, d,e, a, b_,c, w67)
        u32 w68 = W_EXP(w65,w60,w54,w52);
        SHA1_STEP(F3,K3, c,d, e, a, b_, w68)
        u32 w69 = W_EXP(w66,w61,w55,w53);
        SHA1_STEP(F3,K3, b_,c,d, e, a, w69)
        u32 w70 = W_EXP(w67,w62,w56,w54);
        SHA1_STEP(F3,K3, a,b_,c,d,e, w70)
        u32 w71 = W_EXP(w68,w63,w57,w55);
        SHA1_STEP(F3,K3, e,a, b_,c,d, w71)
        u32 w72 = W_EXP(w69,w64,w58,w56);
        SHA1_STEP(F3,K3, d,e, a, b_,c, w72)
        u32 w73 = W_EXP(w70,w65,w59,w57);
        SHA1_STEP(F3,K3, c,d, e, a, b_, w73)
        u32 w74 = W_EXP(w71,w66,w60,w58);
        SHA1_STEP(F3,K3, b_,c,d, e, a, w74)
        u32 w75 = W_EXP(w72,w67,w61,w59);
        SHA1_STEP(F3,K3, a,b_,c,d,e, w75)
        u32 w76 = W_EXP(w73,w68,w62,w60);
        SHA1_STEP(F3,K3, e,a, b_,c,d, w76)
        u32 w77 = W_EXP(w74,w69,w63,w61);
        SHA1_STEP(F3,K3, d,e, a, b_,c, w77)
        u32 w78 = W_EXP(w75,w70,w64,w62);
        SHA1_STEP(F3,K3, c,d, e, a, b_, w78)
        u32 w79 = W_EXP(w76,w71,w65,w63);
        SHA1_STEP(F3,K3, b_,c,d, e, a, w79)

        /* Finalise */
        u32 d0 = iv0 + a;

        int match;
        if (leading) {
            u32 d1 = iv1 + b_;
            match = check_leading(d0, d1, bits);
        } else {
            u32 d3 = iv3 + d;
            u32 d4 = iv4 + e;
            match = check_trailing(d3, d4, bits);
        }

        if (match) {
            s_found = 1;
            if (atomicCAS(found, 0u, 1u) == 0u)
                *result = thread_start + (u64)b_iter;
            return;
        }

        /* Odometer carry-increment */
        #pragma unroll
        for (int i = 0; i < SL; i++) {
            idx[i]++;
            if ((int)idx[i] < charset_len) break;
            idx[i] = 0;
        }
    }
}

/* ── extern "C" entry points, one per suffix length ─────────────────────── */
/*
 * Each wrapper bakes SL and STANDARD_IV into the template instantiation.
 * Suffix "_s" = standard IV (prefix < 56 bytes — the common CTF case).
 * Suffix "_c" = custom IV  (prefix needed CPU mid-state compression first).
 * The Rust side picks the right variant based on the init_state it computed.
 */
#define INST_BODY(n, si) \
    u64            base_counter, \
    const u32* __restrict__ init_state, \
    const u32* __restrict__ tmpl, \
    const u8*  __restrict__ charset, \
    int  charset_len, \
    int  suffix_byte_off, \
    int  bits, \
    int  leading, \
    u32* found, \
    u64* result) \
{ sha1_pow_impl<n, si>(base_counter, init_state, tmpl, charset, charset_len, \
                       suffix_byte_off, bits, leading, found, result); }

#define INST_S(n) extern "C" __global__ void sha1_pow_##n##_s( INST_BODY(n, true)
#define INST_C(n) extern "C" __global__ void sha1_pow_##n##_c( INST_BODY(n, false)
#define INST(n) INST_S(n) INST_C(n)

#include "pow_inst.h"
