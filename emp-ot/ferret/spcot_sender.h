#ifndef SPCOT_SENDER_H__
#define SPCOT_SENDER_H__
#include <iostream>
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "emp-ot/ferret/twokeyprp.h"
#include "emp-ot/ferret/ccrh.h"

using namespace emp;

template<typename IO>
class SPCOT_Sender { public:
	block seed;
	block delta;
	block *ggm_tree, *m;
	IO *io;
	int depth, leave_n;
	PRG prg;
	block secret_sum_f2;

	SPCOT_Sender(IO *io, int depth_in) {
		initialization(io, depth_in);
		prg.random_block(&seed, 1);
	}

	void initialization(IO *io, int depth_in) {
		this->io = io;
		this->depth = depth_in;
		this->leave_n = 1<<(this->depth-1);
		m = new block[depth-1];
	}

	~SPCOT_Sender() {
		delete[] m;
	}

	// generate GGM tree, transfer secret, F2^k
	void compute(block* ggm_tree_mem, block secret) {
		this->delta = secret;
		ggm_tree_gen(m, ggm_tree_mem, secret);
	}

	// send the nodes by oblivious transfer, F2^k
	template<typename OT>
	void send_f2k(OT * ot, IO * io2, int s) {
		ot->send(m, depth-1, io2, s);
		io2->send_data(&secret_sum_f2, sizeof(block));
	}

	void ggm_tree_gen(block *ot_msg, block* ggm_tree_mem, block secret) {
		ggm_tree_gen(ot_msg, ggm_tree_mem);
		secret_sum_f2 = zero_block;
		block one = makeBlock(0xFFFFFFFFFFFFFFFFLL,0xFFFFFFFFFFFFFFFELL);
		for(int i = 0; i < leave_n; ++i) {
			ggm_tree[i] = ggm_tree[i] & one;
			secret_sum_f2 = secret_sum_f2 ^ ggm_tree[i];
		}
		secret_sum_f2 = secret_sum_f2 ^ secret;
	}

	// generate GGM tree from the top
	void ggm_tree_gen(block *ot_msg, block* ggm_tree_mem) {
		this->ggm_tree = ggm_tree_mem;
		FerretCCRH *ccrh = new FerretCCRH(zero_block);
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
		delete ccrh;
	}

	void consistency_check_msg_gen(block *V) {
		// X
		block *chi = new block[leave_n];
		Hash hash;
		block digest[2];
		hash.hash_once(digest, &secret_sum_f2, sizeof(block));
		uni_hash_coeff_gen(chi, digest[0], leave_n);

		vector_inn_prdt_sum_red(V, chi, ggm_tree, leave_n);
		delete[] chi;
	}
};

#endif
