#include <miner.h>

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <sha3/sph_skein.h>
#include <sha3/sph_cubehash.h>
#include <sha3/sph_fugue.h>
#include <sha3/gost_streebog.h>
#include <sha3/sph_echo.h>
#include <sha3/sph_shavite.h>
#include <sha3/sph_luffa.h>

//#define DEBUG_ALGO

void vitaliumhash(void *output, const void *input)
{
	unsigned char _ALIGN(64) hash[64];
	
	sph_skein512_context     ctx_skein;
    sph_cubehash512_context  ctx_cubehash;
	sph_fugue512_context      ctx_fugue;
	sph_gost512_context      ctx_gost;
	sph_echo512_context      ctx_echo;
	sph_shavite512_context   ctx_shavite;
	sph_luffa512_context     ctx_luffa;

	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx_skein, input, 80);
	sph_skein512_close(&ctx_skein, hash);

	sph_cubehash512_init(&ctx_cubehash);
	sph_cubehash512(&ctx_cubehash, hash, 64);
	sph_cubehash512_close(&ctx_cubehash, hash);
	
	sph_fugue512_init(&ctx_fugue);
	sph_fugue512(&ctx_fugue, hash, 64);
	sph_fugue512_close(&ctx_fugue, hash);
	
	sph_gost512_init(&ctx_gost);
    sph_gost512 (&ctx_gost, hash, 64);
    sph_gost512_close(&ctx_gost, hash);
	
	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, hash, 64);
	sph_echo512_close(&ctx_echo, hash);
	
	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, hash, 64);
	sph_shavite512_close(&ctx_shavite, hash);
	
	sph_luffa512_init(&ctx_luffa);
	sph_luffa512(&ctx_luffa, hash, 64);
	sph_luffa512_close(&ctx_luffa, hash);
	
	sph_gost512_init(&ctx_gost);
    sph_gost512 (&ctx_gost, hash, 64);
    sph_gost512_close(&ctx_gost, hash);
	
	sph_cubehash512_init(&ctx_cubehash);
	sph_cubehash512(&ctx_cubehash, hash, 64);
	sph_cubehash512_close(&ctx_cubehash, hash);
	
	sph_fugue512_init(&ctx_fugue);
	sph_fugue512(&ctx_fugue, hash, 64);
	sph_fugue512_close(&ctx_fugue, hash);
	
	sph_gost512_init(&ctx_gost);
    sph_gost512 (&ctx_gost, hash, 64);
    sph_gost512_close(&ctx_gost, hash);
	
	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, hash, 64);
	sph_echo512_close(&ctx_echo, hash);
	
	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, hash, 64);
	sph_shavite512_close(&ctx_shavite, hash);
	
	sph_luffa512_init(&ctx_luffa);
	sph_luffa512(&ctx_luffa, hash, 64);
	sph_luffa512_close(&ctx_luffa, hash);

	memcpy(output, hash, 32);
}

int scanhash_vitalium(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	if (opt_benchmark)
		ptarget[7] = 0x0cff;

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	do {
		be32enc(&endiandata[19], nonce);
		vitaliumhash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
