#ifndef CGGM_SENDER_H__
#define CGGM_SENDER_H__
#include <iostream>
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "emp-ot/dory/ccrh.h"

using namespace emp;

template<typename IO>
class CGGM_Sender { public:
	block seed;
	block delta;
	block *ggm_tree, *half_sum;
	IO *io;
	int depth, leave_n;
	PRG prg;
	DoryCCRH *ccrh;

	CGGM_Sender(IO *io, int depth_in) {
		initialization(io, depth_in);
		prg.random_block(&seed, 1);
	}

	void initialization(IO *io, int depth_in) {
		this->io = io;
		this->depth = depth_in;
		this->leave_n = 1<<(this->depth-1);
		half_sum = new block[depth-1];
		ccrh = new DoryCCRH(zero_block);
	}

	~CGGM_Sender() {
		delete[] half_sum;
		delete ccrh;
	}

	// generate GGM tree, transfer secret, F2^k
	void compute(block* ggm_tree_mem, block secret) {
		this->delta = secret;
		// ggm_tree_gen(sum, ggm_tree_mem, secret);
		ggm_tree_gen(half_sum, ggm_tree_mem);
	}

	// send the nodes by oblivious transfer, F2^k
	template<typename OT>
	void send_f2k(OT * ot, IO * io2, int s) {
		ot->send(half_sum, depth-1, io2, s);
	}

	// void ggm_tree_gen(block *ot_msg, block* ggm_tree_mem, block secret) {
	// 	ggm_tree_gen(ot_msg, ggm_tree_mem);
	// 	secret_sum_f2 = zero_block;
	// 	block one = makeBlock(0xFFFFFFFFFFFFFFFFLL,0xFFFFFFFFFFFFFFFELL);
	// 	for(int i = 0; i < leave_n; ++i) {
	// 		ggm_tree[i] = ggm_tree[i] & one;
	// 	}
	// }

	// generate GGM tree from the top
	void ggm_tree_gen(block *ot_msg, block* ggm_tree_mem) {
		this->ggm_tree = ggm_tree_mem;
		ggm_tree[0] = seed;
		ggm_tree[1] = delta ^ ggm_tree[0];
		ot_msg[0] = ggm_tree[0];
		ccrh->node_expand_2to4(ggm_tree, ggm_tree);
		ot_msg[1] = ggm_tree[0] ^ ggm_tree[2];
		for(int h = 2; h < depth-1; ++h) {
			ot_msg[h] = zero_block;
			int sz = 1<<h;
			for(int i = sz-4; i >=0; i-=4) {
				ccrh->node_expand_4to8(&ggm_tree[i*2], &ggm_tree[i]);
				ot_msg[h] = ot_msg[h] ^ ggm_tree[i*2];
				ot_msg[h] = ot_msg[h] ^ ggm_tree[i*2+2];
				ot_msg[h] = ot_msg[h] ^ ggm_tree[i*2+4];
				ot_msg[h] = ot_msg[h] ^ ggm_tree[i*2+6];
			}
		}
		// block one = makeBlock(0xFFFFFFFFFFFFFFFFLL,0xFFFFFFFFFFFFFFFELL);
		// for(int i = 0; i < leave_n; ++i) {
		// 	ggm_tree[i] = ggm_tree[i] & one;
		// }
	}

	// compute sum of all leaves with index <= w
	// [TODO] batch execution
	void acc_left(block* acc, uint32_t w) {
		*acc = zero_block;
		block s[2] = {seed, delta ^ seed};
		// [TODO] this can be optimized by storing all nodes in the ggm_tree, it just doubles the current array size.
		for (int i = depth - 2; i >= 0; i--) {
			block to_expand = s[0];
			if ((w >> i) & 1) {
				*acc ^= s[0];
				to_expand = s[1];
			}
			if (i == 0) break; // don't expand beyond the last layer
			ccrh->node_expand_1to2(&s[0], &to_expand);
		}
		*acc ^= s[w & 1];
	}

	void consistency_check_msg_gen(block *V) {
		// // X
		// block *chi = new block[leave_n];
		// Hash hash;
		// block digest[2];
		// hash.hash_once(digest, &secret_sum_f2, sizeof(block));
		// uni_hash_coeff_gen(chi, digest[0], leave_n);

		// vector_inn_prdt_sum_red(V, chi, ggm_tree, leave_n);
		// delete[] chi;
	}
};

#endif
