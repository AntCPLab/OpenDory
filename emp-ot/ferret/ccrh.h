#ifndef EMP_FERRET_CCRH_H__
#define EMP_FERRET_CCRH_H__
// #include "emp-tool/utils/prp.h"
#include "emp-tool/emp-tool.h"
#include <stdio.h>
#include "emp-ot/dory/performance.h"
namespace emp {

/*
 * By default, CRH use zero_block as the AES key.
 * Here we model f(x) = AES_{00..0}(x) as a random permutation (and thus in the RPM model)
 */
class FerretCCRH { public:
	emp::AES_KEY aes_key;

	FerretCCRH(block key) {
		AES_set_encrypt_key((const block)key, &aes_key);
	}

	void node_expand_2to4(block *children, const block *parent) {
		count_log("aes", 2);
		block tmp[2];
		tmp[1] = children[2] = children[3] = parent[1];
		tmp[0] = children[0] = children[1] = parent[0];
		children[2] = tmp[1] = sigma(tmp[1]);
		children[0] = tmp[0] = sigma(tmp[0]);
		AES_ecb_encrypt_blks<2>(tmp, &aes_key);
		children[2] = children[2] ^ tmp[1];
		children[3] = children[3] ^ children[2];
		children[0] = children[0] ^ tmp[0];
		children[1] = children[1] ^ children[0];
	}

	void node_expand_4to8(block *children, const block *parent) {
		count_log("aes", 4);
		block tmp[4];
		tmp[3] = children[6] = children[7] = parent[3];
		tmp[2] = children[4] = children[5] = parent[2];
		tmp[1] = children[2] = children[3] = parent[1];
		tmp[0] = children[0] = children[1] = parent[0];
		children[6] = tmp[3] = sigma(tmp[3]);
		children[4] = tmp[2] = sigma(tmp[2]);
		children[2] = tmp[1] = sigma(tmp[1]);
		children[0] = tmp[0] = sigma(tmp[0]);
		AES_ecb_encrypt_blks<4>(tmp, &aes_key);
		children[6] = children[6] ^ tmp[3];
		children[4] = children[4] ^ tmp[2];
		children[2] = children[2] ^ tmp[1];
		children[0] = children[0] ^ tmp[0];
		children[7] = children[7] ^ children[6];
		children[5] = children[5] ^ children[4];
		children[3] = children[3] ^ children[2];
		children[1] = children[1] ^ children[0];
	}
};

}//namespace
#endif// CCRH_H__
