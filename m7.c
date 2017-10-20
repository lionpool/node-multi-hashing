#include <gmp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <float.h>
#include <math.h>

#include "hash/sph_sha2.h"
#include "hash/sph_keccak.h"
#include "hash/sph_haval.h"
#include "hash/sph_tiger.h"
#include "hash/sph_whirlpool.h"
#include "hash/sph_ripemd.h"

#define SWAP_UINT32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))


static void mpz_set_uint256(mpz_t r, uint8_t *u)
{
    mpz_import(r, 32 / sizeof(unsigned long), -1, sizeof(unsigned long), -1, 0, u);
}

static void mpz_get_uint256(mpz_t r, uint8_t *u)
{
    u=0;
    mpz_export(u, 0, -1, sizeof(unsigned long), -1, 0, r);
}

static void mpz_set_uint512(mpz_t r, uint8_t *u)
{
    mpz_import(r, 64 / sizeof(unsigned long), -1, sizeof(unsigned long), -1, 0, u);
}

static void set_one_if_zero(uint8_t *hash512) {
    int i;
    for (i = 0; i < 32; i++) {
        if (hash512[i] != 0) {
            return;
        }
    }
    hash512[0] = 1;
}

static uint64_t _bswap64(uint64_t a)
{
  a = ((a & 0x00000000000000FFULL) << 56) | 
      ((a & 0x000000000000FF00ULL) << 40) | 
      ((a & 0x0000000000FF0000ULL) << 24) | 
      ((a & 0x00000000FF000000ULL) <<  8) | 
      ((a & 0x000000FF00000000ULL) >>  8) | 
      ((a & 0x0000FF0000000000ULL) >> 24) | 
      ((a & 0x00FF000000000000ULL) >> 40) | 
      ((a & 0xFF00000000000000ULL) >> 56);
  return a;
}

#define M7_MIDSTATE_LEN 116
void m7_hash(const char* input, char* output)
{

    uint32_t data[32] __attribute__((aligned(128)));
    uint32_t *data_p64 = data + (M7_MIDSTATE_LEN / sizeof(data[0]));
    uint32_t hash[8] __attribute__((aligned(32)));
    uint8_t bhash[7][64] __attribute__((aligned(32)));
    uint32_t hashtest[8] __attribute__((aligned(32)));
    char data_str[245], hash_str[65], target_str[65];
    uint8_t *bdata = 0;
    mpz_t bns[7];
    int i;
    int z;

    for(i=0; i < 7; i++){
        mpz_init(bns[i]);
    }

    memcpy(data, input, 122);

    sph_sha256_context       ctx_final_sha256;

    sph_sha256_context       ctx_sha256;
    sph_sha512_context       ctx_sha512;
    sph_keccak512_context    ctx_keccak;
    sph_whirlpool_context    ctx_whirlpool;
    sph_haval256_5_context   ctx_haval;
    sph_tiger_context        ctx_tiger;
    sph_ripemd160_context    ctx_ripemd;

    sph_sha256_init(&ctx_sha256);
    sph_sha256 (&ctx_sha256, data, M7_MIDSTATE_LEN);

    sph_sha512_init(&ctx_sha512);
    sph_sha512 (&ctx_sha512, data, M7_MIDSTATE_LEN);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, data, M7_MIDSTATE_LEN);

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, data, M7_MIDSTATE_LEN);

    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5 (&ctx_haval, data, M7_MIDSTATE_LEN);

    sph_tiger_init(&ctx_tiger);
    sph_tiger (&ctx_tiger, data, M7_MIDSTATE_LEN);

    sph_ripemd160_init(&ctx_ripemd);
    sph_ripemd160 (&ctx_ripemd, data, M7_MIDSTATE_LEN);

    sph_sha256_context       ctx2_sha256;
    sph_sha512_context       ctx2_sha512;
    sph_keccak512_context    ctx2_keccak;
    sph_whirlpool_context    ctx2_whirlpool;
    sph_haval256_5_context   ctx2_haval;
    sph_tiger_context        ctx2_tiger;
    sph_ripemd160_context    ctx2_ripemd;

        memset(bhash, 0, 7 * 64);

        ctx2_sha256 = ctx_sha256;
        sph_sha256 (&ctx2_sha256, data_p64, 122 - M7_MIDSTATE_LEN);
        sph_sha256_close(&ctx2_sha256, (void*)(bhash[0]));

        ctx2_sha512 = ctx_sha512;
        sph_sha512 (&ctx2_sha512, data_p64, 122 - M7_MIDSTATE_LEN);
        sph_sha512_close(&ctx2_sha512, (void*)(bhash[1]));

        ctx2_keccak = ctx_keccak;
        sph_keccak512 (&ctx2_keccak, data_p64, 122 - M7_MIDSTATE_LEN);
        sph_keccak512_close(&ctx2_keccak, (void*)(bhash[2]));

        ctx2_whirlpool = ctx_whirlpool;
        sph_whirlpool (&ctx2_whirlpool, data_p64, 122 - M7_MIDSTATE_LEN);
        sph_whirlpool_close(&ctx2_whirlpool, (void*)(bhash[3]));

        ctx2_haval = ctx_haval;
        sph_haval256_5 (&ctx2_haval, data_p64, 122 - M7_MIDSTATE_LEN);
        sph_haval256_5_close(&ctx2_haval, (void*)(bhash[4]));

        ctx2_tiger = ctx_tiger;
        sph_tiger (&ctx2_tiger, data_p64, 122 - M7_MIDSTATE_LEN);
        sph_tiger_close(&ctx2_tiger, (void*)(bhash[5]));

        ctx2_ripemd = ctx_ripemd;
        sph_ripemd160 (&ctx2_ripemd, data_p64, 122 - M7_MIDSTATE_LEN);
        sph_ripemd160_close(&ctx2_ripemd, (void*)(bhash[6]));

        for(i=0; i < 7; i++){
            set_one_if_zero(bhash[i]);
            mpz_set_uint512(bns[i],bhash[i]);
        }

        for(i=6; i > 0; i--){
            mpz_mul(bns[i-1], bns[i-1], bns[i]);
        }

        int bytes = mpz_sizeinbase(bns[0], 256);
        bdata = (uint8_t *)realloc(bdata, bytes);
        mpz_export((void *)bdata, NULL, -1, 1, 0, 0, bns[0]);

        sph_sha256_init(&ctx_final_sha256);
        sph_sha256 (&ctx_final_sha256, bdata, bytes);
        sph_sha256_close(&ctx_final_sha256, (void*)(hash));

        

    for(i=0; i < 7; i++){
        mpz_clear(bns[i]);
    }

    free(bdata);

    hash[0] = SWAP_UINT32(hash[0]);
    hash[1] = SWAP_UINT32(hash[1]);
    hash[2] = SWAP_UINT32(hash[2]);
    hash[3] = SWAP_UINT32(hash[3]);
    hash[4] = SWAP_UINT32(hash[4]);
    hash[5] = SWAP_UINT32(hash[5]);
    hash[6] = SWAP_UINT32(hash[6]);
    hash[7] = SWAP_UINT32(hash[7]);

    memcpy(output, (void*) hash, 32);
}
