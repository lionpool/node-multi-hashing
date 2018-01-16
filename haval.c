#include "haval.h"

#include "sha3/sph_haval.h"

void haval_hash(const char* input, char* output, uint32_t len)
{
	sph_haval256_5_init(&ctx_haval);
	sph_haval256_5(&ctx_haval,(const void*) hash, dataLen);
  sph_haval256_5_close(&ctx_haval, hash);
}
