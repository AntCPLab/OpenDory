#ifndef EMP_DORY_CCRH_H__
#define EMP_DORY_CCRH_H__
// #include "emp-tool/utils/prp.h"
#include "emp-tool/emp-tool.h"
#include <stdio.h>
namespace emp {

#ifdef __AVX512F__
typedef __m512i blockx4_t;
typedef struct { blockx4_t rd_key[11]; unsigned int rounds; } AES_KEYx4_t;
#endif

#ifdef __AVX512F__
template<int N>
inline void ParaEnc(block *blks __attribute__((aligned(64))), AES_KEYx4_t *keys) {
	blockx4_t* packed_blks = reinterpret_cast<blockx4_t*>(blks);
	int n_packed = N >> 2;
	for (int i = 0; i < n_packed; ++i)
      packed_blks[i] = _mm512_xor_si512(packed_blks[i], keys[i]->rd_key[0]);
	for (unsigned int j = 1; j < keys[0]->rounds; ++j)
		for (int i = 0; i < n_packed; ++i)
			packed_blks[i] = _mm512_aesenc_epi128(packed_blks[i], keys[i]->rd_key[j]);
	for (int i = 0; i < n_packed; ++i)
		packed_blks[i] = _mm512_aesenclast_epi128(packed_blks[i], keys[i]->rd_key[keys[i]->rounds]);
}
#else
template<int N>
inline void ParaEnc(block *blks, AES_KEY *keys) {
	ParaEnc<N, 1>(blks, keys);
}
#endif

/*
 * By default, CRH use zero_block as the AES key.
 * Here we model f(x) = AES_{00..0}(x) as a random permutation (and thus in the RPM model)
 */
template<int BatchSize = 8>
class DoryCCRH { public:
	AES_KEY scheduled_keys[BatchSize];
	block keys[BatchSize];
#ifdef __AVX512F__
	AES_KEYx4_t* batch_keys;
#endif

	DoryCCRH(block key) {
		for(int i = 0; i < BatchSize; ++i)
			keys[i] = key;
		AES_opt_key_schedule<BatchSize>(keys, scheduled_keys);
#ifdef __AVX512F__
		if (BatchSize % 4 == 0) {
			batch_keys = new AES_KEYx4_t[BatchSize / 4];
			for (int i = 0; i < BatchSize/4; i++) {
				batch_keys[i].rounds = scheduled_keys[0].rounds;
				for (int j = 0; j < 11; j++) {
					batch_keys[i].rd_key[j] = _mm512_setzero_si512();
					batch_keys[i].rd_key[j] = _mm512_inserti128_si512(
						batch_keys[i].rd_key[j], scheduled_keys[i*BatchSize].rd_key[j], 0
					);
					batch_keys[i].rd_key[j] = _mm512_inserti128_si512(
						batch_keys[i].rd_key[j], scheduled_keys[i*BatchSize + 1].rd_key[j], 1
					);
					batch_keys[i].rd_key[j] = _mm512_inserti128_si512(
						batch_keys[i].rd_key[j], scheduled_keys[i*BatchSize + 2].rd_key[j], 2
					);
					batch_keys[i].rd_key[j] = _mm512_inserti128_si512(
						batch_keys[i].rd_key[j], scheduled_keys[i*BatchSize + 3].rd_key[j], 3
					);
				}
			}
		}
#endif
	}

	~DoryCCRH() {
#ifdef __AVX512F__
	delete[] batch_keys;
#endif
	}

	void batch_node_expand(block* left, block* right, const block* parent) {
		block tmp[BatchSize];
		for(size_t i = 0; i < BatchSize; i++) {
			tmp[i] = left[i] = right[i] = parent[i];
			left[i] = tmp[i] = sigma(tmp[i]);
		}
#ifdef __AVX512F__
		ParaEnc<BatchSize>(tmp, batch_keys);
#else
		ParaEnc<BatchSize>(tmp, scheduled_keys);
#endif
		for(size_t i = 0; i < BatchSize; i++) {
			left[i] = left[i] ^ tmp[i];
			right[i] = right[i] ^ left[i];
		}
	}

	void single_node_expand(block& left, block& right, const block& parent) {
		block tmp;
		tmp = left = right = parent;
		left = tmp = sigma(tmp);
		AES_ecb_encrypt_blks<1>(&tmp, &scheduled_keys[0]);
		left = left ^ tmp;
		right = right ^ left;
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
