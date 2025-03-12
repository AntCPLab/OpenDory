#ifndef EMP_DORY_CCRH_H__
#define EMP_DORY_CCRH_H__
// #include "emp-tool/utils/prp.h"
#include "emp-tool/emp-tool.h"
#include <stdio.h>
#include "emp-ot/dory/performance.h"
#include <cstdint>
namespace emp {

#ifdef __AVX512F__
typedef __m512i blockx4_t;
// NOTE: any use of this struct should make sure the memory allocation is 64-byte aligned, otherwise there will be
// a segmentation fault. The `alignas(64)` doesn't really guarantee this.
typedef struct alignas(64) { blockx4_t rd_key[11]; unsigned int rounds; } AES_KEYx4_t;
#endif

#ifdef __AVX512F__
/**
 * Caller should make sure `blks` is 64-byte aligned.
*/
template<int N>
static inline void ParaEnc(block *blks, const AES_KEYx4_t *keys) {
	blockx4_t* packed_blks = reinterpret_cast<blockx4_t*>(blks);
	constexpr int n_packed = N >> 2;
	for (int i = 0; i < n_packed; ++i)
      packed_blks[i] = _mm512_xor_si512(packed_blks[i], keys[i].rd_key[0]);
	
	for (unsigned int j = 1; j < 10; ++j)
		for (int i = 0; i < n_packed; ++i)
			packed_blks[i] = _mm512_aesenc_epi128(packed_blks[i], keys[i].rd_key[j]);
	for (int i = 0; i < n_packed; ++i) 
		packed_blks[i] = _mm512_aesenclast_epi128(packed_blks[i], keys[i].rd_key[10]);
}
#endif

#ifdef __AVX512F__
#define DORY_AES_BATCH_SIZE 4

// template<int N>
// static inline void AES_ecb_encrypt_blks(block *blks, const AES_KEYx4_t* key) {
// 	blockx4_t* packed_blks = reinterpret_cast<blockx4_t*>(blks);
// 	constexpr int n_packed = N >> 2;
// 	for (int i = 0; i < n_packed; ++i)
//       packed_blks[i] = _mm512_xor_si512(packed_blks[i], key->rd_key[0]);
	
// 	for (unsigned int j = 1; j < 10; ++j)
// 		for (int i = 0; i < n_packed; ++i)
// 			packed_blks[i] = _mm512_aesenc_epi128(packed_blks[i], key->rd_key[j]);
// 	for (int i = 0; i < n_packed; ++i) 
// 		packed_blks[i] = _mm512_aesenclast_epi128(packed_blks[i], key->rd_key[10]);
// }

static inline void aes_enc_4(block *blks, const AES_KEYx4_t* key) {
	blockx4_t* packed_blks = reinterpret_cast<blockx4_t*>(blks);
	*packed_blks = _mm512_xor_si512(*packed_blks, key->rd_key[0]);
	for (unsigned int j = 1; j < 10; ++j)
		*packed_blks = _mm512_aesenc_epi128(*packed_blks, key->rd_key[j]);
	*packed_blks = _mm512_aesenclast_epi128(*packed_blks, key->rd_key[10]);
}

template<int N>
static inline void AES_ecb_encrypt_blks(block *blks, const AES_KEYx4_t* key) {
	constexpr int n_packed = N >> 2;
	for (int i = 0; i < n_packed; ++i)
    	aes_enc_4(blks + i * 4, key);
}

static inline void AES_ecb_encrypt_blks(block *data, int nblocks, const AES_KEYx4_t* key) {
	assert(nblocks % DORY_AES_BATCH_SIZE == 0);
	for(int i = 0; i < nblocks/DORY_AES_BATCH_SIZE; ++i) {
		AES_ecb_encrypt_blks<DORY_AES_BATCH_SIZE>(data + i*DORY_AES_BATCH_SIZE, key);
	}
}

static inline void aes_key_to_aes_keyx4(AES_KEYx4_t* out_key, const AES_KEY* key) {
	out_key->rounds = key->rounds;
	for (int j = 0; j < 11; j++) {
		out_key->rd_key[j] = _mm512_setzero_si512();
		out_key->rd_key[j] = _mm512_inserti32x4(
			out_key->rd_key[j], key->rd_key[j], 0
		);
		out_key->rd_key[j] = _mm512_inserti32x4(
			out_key->rd_key[j], key->rd_key[j], 1
		);
		out_key->rd_key[j] = _mm512_inserti32x4(
			out_key->rd_key[j], key->rd_key[j], 2
		);
		out_key->rd_key[j] = _mm512_inserti32x4(
			out_key->rd_key[j], key->rd_key[j], 3
		);
	}
}

#endif

#define DEFAULT_EXPAND_SIZE 16

/*
 * By default, CRH use zero_block as the AES key.
 * Here we model f(x) = AES_{00..0}(x) as a random permutation (and thus in the RPM model)
 */
template<int BatchSize = 8>
class DoryCCRH { public:
#ifdef __AVX512F__
	// AES_KEYx4_t batch_keys[(BatchSize + 3)/4];
	AES_KEYx4_t *batch_keys = nullptr;
#endif
	AES_KEY scheduled_keys[BatchSize];
	block keys[BatchSize];

	DoryCCRH(block key) {
		for(int i = 0; i < BatchSize; ++i)
			keys[i] = key;
		AES_opt_key_schedule<BatchSize>(keys, scheduled_keys);
#ifdef __AVX512F__
		if ((BatchSize & 0x3) == 0) {
			batch_keys = reinterpret_cast<AES_KEYx4_t*>(aligned_alloc(64, BatchSize / 4 * sizeof(AES_KEYx4_t)));
			for (int i = 0; i < BatchSize/4; i++) {
				batch_keys[i].rounds = scheduled_keys[0].rounds;
				for (int j = 0; j < 11; j++) {
					batch_keys[i].rd_key[j] = _mm512_setzero_si512();
					batch_keys[i].rd_key[j] = _mm512_inserti32x4(
						batch_keys[i].rd_key[j], scheduled_keys[i*4].rd_key[j], 0
					);
					batch_keys[i].rd_key[j] = _mm512_inserti32x4(
						batch_keys[i].rd_key[j], scheduled_keys[i*4 + 1].rd_key[j], 1
					);
					batch_keys[i].rd_key[j] = _mm512_inserti32x4(
						batch_keys[i].rd_key[j], scheduled_keys[i*4 + 2].rd_key[j], 2
					);
					batch_keys[i].rd_key[j] = _mm512_inserti32x4(
						batch_keys[i].rd_key[j], scheduled_keys[i*4 + 3].rd_key[j], 3
					);
				}
			}
		}
#endif
	}

	~DoryCCRH() {
#ifdef __AVX512F__
	if (!batch_keys)
		free(batch_keys);
#endif
	}

	void batch_node_expand(block* left, block* right, const block* parent) {
		count_log("aes", BatchSize);
		// [TODO] Need to revisit here. Compiler might not respect the 64-byte aligned request.
		alignas(64) block tmp[BatchSize];
		for(size_t i = 0; i < BatchSize; i++) {
			tmp[i] = right[i] = parent[i];
			left[i] = tmp[i] = sigma(tmp[i]);
		}
		// acc_time_log("ParaEnc");
#ifdef __AVX512F__
		if((BatchSize & 0x3) == 0) {
		// if(batch_keys) { // This is slower than above
			// ParaEnc<BatchSize>(tmp, batch_keys);
			AES_ecb_encrypt_blks<BatchSize>(tmp, &batch_keys[0]);
		}
		else {
#endif
			ParaEnc<BatchSize, 1>(tmp, scheduled_keys);
#ifdef __AVX512F__
		}
#endif
		// acc_time_log("ParaEnc");
		for(size_t i = 0; i < BatchSize; i++) {
			left[i] ^= tmp[i];
			right[i] ^= left[i];
		}
	}

	void node_expand_4to8(block* left, block* right, const block* parent) {
		// [TODO] Need to revisit here. Compiler might not respect the 64-byte aligned request.
		alignas(64) block tmp[4];
		for(size_t i = 0; i < 4; i++) {
			tmp[i] = right[i] = parent[i];
			left[i] = tmp[i] = sigma(tmp[i]);
		}
#ifdef __AVX512F__
		if((BatchSize & 0x3) == 0) {
		// if(batch_keys) { // This is slower than above
			ParaEnc<BatchSize>(tmp, batch_keys);
			// AES_ecb_encrypt_blks<4>(tmp, &batch_keys[0]);
		}
		else {
#endif
			ParaEnc<4, 1>(tmp, scheduled_keys);
#ifdef __AVX512F__
		}
#endif
		for(size_t i = 0; i < 4; i++) {
			left[i] ^= tmp[i];
			right[i] ^= left[i];
		}
	}

	void single_node_expand(block& left, block& right, const block& parent) {
		count_log("aes", 1);
		block tmp;
		tmp = left = right = parent;
		left = tmp = sigma(tmp);
		AES_ecb_encrypt_blks<1>(&tmp, &scheduled_keys[0]);
		left = left ^ tmp;
		right = right ^ left;
	}
};


class DoryPRP { public:
#ifdef __AVX512F__
	AES_KEYx4_t* scheduled_key512;
#endif
	AES_KEY scheduled_key;
	block key;
	PRP prp;

	DoryPRP() : DoryPRP(zero_block) {}

	DoryPRP(block key) : prp(key) {
		AES_set_encrypt_key(key, &scheduled_key);
#ifdef __AVX512F__
		scheduled_key512 = reinterpret_cast<AES_KEYx4_t*>(aligned_alloc(64, sizeof(AES_KEYx4_t)));
		scheduled_key512->rounds = scheduled_key.rounds;
		for (int j = 0; j < 11; j++) {
			scheduled_key512->rd_key[j] = _mm512_setzero_si512();
			scheduled_key512->rd_key[j] = _mm512_inserti32x4(
				scheduled_key512->rd_key[j], scheduled_key.rd_key[j], 0
			);
			scheduled_key512->rd_key[j] = _mm512_inserti32x4(
				scheduled_key512->rd_key[j], scheduled_key.rd_key[j], 1
			);
			scheduled_key512->rd_key[j] = _mm512_inserti32x4(
				scheduled_key512->rd_key[j], scheduled_key.rd_key[j], 2
			);
			scheduled_key512->rd_key[j] = _mm512_inserti32x4(
				scheduled_key512->rd_key[j], scheduled_key.rd_key[j], 3
			);
		}
#endif
	}

	~DoryPRP() {
#ifdef __AVX512F__
	if (!scheduled_key512)
		free(scheduled_key512);
#endif
	}

	void permute_block(block *data, int nblocks) {
		count_log("aes", nblocks);
#ifdef __AVX512F__
		if (reinterpret_cast<uintptr_t>(data) % 64 != 0) {
			int skip = std::min(static_cast<int>(4 - reinterpret_cast<uintptr_t>(data)%64/16), nblocks);
			AES_ecb_encrypt_blks(data, skip, &scheduled_key);
			data += skip;
			nblocks -= skip;
			if (nblocks == 0)
				return;
		}
		for(int i = 0; i < nblocks/DORY_AES_BATCH_SIZE; ++i) {
			AES_ecb_encrypt_blks<DORY_AES_BATCH_SIZE>(data + i*DORY_AES_BATCH_SIZE, scheduled_key512);
		}
		int remain = nblocks % DORY_AES_BATCH_SIZE;
		AES_ecb_encrypt_blks(data + nblocks - remain, remain, &scheduled_key);
#else
		prp.permute_block(data, nblocks);
#endif 
	}
};



// /*
//  * By default, CRH use zero_block as the AES key.
//  * Here we model f(x) = AES_{00..0}(x) as a random permutation (and thus in the RPM model)
//  */
// class DoryCCRH { public:
// 	emp::AES_KEY aes_key;

// 	DoryCCRH(block key) {
// 		AES_set_encrypt_key((const block)key, &aes_key);
// 	}

// 	void node_expand_1to2(block *children, const block *parent) {
// 		block tmp;
// 		tmp = children[0] = children[1] = parent[0];
// 		children[0] = tmp = sigma(tmp);
// 		AES_ecb_encrypt_blks<1>(&tmp, &aes_key);
// 		children[0] = children[0] ^ tmp;
// 		children[1] = children[1] ^ children[0];
// 	}

// 	void node_expand(block* left, block* right, const block* parent) {
// 		block tmp;
// 		tmp = *left = *right = *parent;
// 		*left = tmp = sigma(tmp);
// 		AES_ecb_encrypt_blks<1>(&tmp, &aes_key);
// 		*left = *left ^ tmp;
// 		*right = *right ^ *left;
// 	}


// 	void node_expand_2to4(block *children, const block *parent) {
// 		block tmp[2];
// 		tmp[1] = children[2] = children[3] = parent[1];
// 		tmp[0] = children[0] = children[1] = parent[0];
// 		children[2] = tmp[1] = sigma(tmp[1]);
// 		children[0] = tmp[0] = sigma(tmp[0]);
// 		AES_ecb_encrypt_blks<2>(tmp, &aes_key);
// 		children[2] = children[2] ^ tmp[1];
// 		children[3] = children[3] ^ children[2];
// 		children[0] = children[0] ^ tmp[0];
// 		children[1] = children[1] ^ children[0];
// 	}

// 	void node_expand_4to8(block *children, const block *parent) {
// 		block tmp[4];
// 		tmp[3] = children[6] = children[7] = parent[3];
// 		tmp[2] = children[4] = children[5] = parent[2];
// 		tmp[1] = children[2] = children[3] = parent[1];
// 		tmp[0] = children[0] = children[1] = parent[0];
// 		children[6] = tmp[3] = sigma(tmp[3]);
// 		children[4] = tmp[2] = sigma(tmp[2]);
// 		children[2] = tmp[1] = sigma(tmp[1]);
// 		children[0] = tmp[0] = sigma(tmp[0]);
// 		AES_ecb_encrypt_blks<4>(tmp, &aes_key);
// 		children[6] = children[6] ^ tmp[3];
// 		children[4] = children[4] ^ tmp[2];
// 		children[2] = children[2] ^ tmp[1];
// 		children[0] = children[0] ^ tmp[0];
// 		children[7] = children[7] ^ children[6];
// 		children[5] = children[5] ^ children[4];
// 		children[3] = children[3] ^ children[2];
// 		children[1] = children[1] ^ children[0];
// 	}
// };

}//namespace
#endif// CCRH_H__
