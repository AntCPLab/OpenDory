#ifndef CGGM_RECVER_H__
#define CGGM_RECVER_H__
#include <iostream>
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "emp-ot/dory/ccrh.h"

using namespace emp;

template<typename IO>
class CGGM_Recver {
public:
	block *ggm_tree, *half_sum;
	block *path_sum;
	bool *b;
	uint32_t choice_pos, depth, leave_n;
	IO *io;
	DoryCCRH *ccrh;

	CGGM_Recver(IO *io, uint32_t depth_in) {
		this->io = io;
		this->depth = depth_in;
		this->leave_n = 1<<(depth_in-1);
		half_sum = new block[depth-1];
		b = new bool[depth-1];
		path_sum = new block[depth];
		ccrh = new DoryCCRH(zero_block);
	}

	~CGGM_Recver(){
		delete[] half_sum;
		delete[] b;
		delete[] path_sum;
		delete ccrh;
	}

	int get_index() {
		choice_pos = 0;
		for(uint32_t i = 0; i < depth-1; ++i) {
			choice_pos <<= 1;
			if(!b[i])
				choice_pos +=1;
		}
		return choice_pos;
	}

	// receive the message and reconstruct the tree
	// j: position of the secret, begins from 0
	template<typename OT>
	void recv_f2k(OT * ot, IO * io2, int s) {
		ot->recv(half_sum, depth-1, io2, s);
	}

	// receive the message and reconstruct the tree
	// j: position of the secret, begins from 0
	void compute(block* ggm_tree_mem) {
		this->ggm_tree = ggm_tree_mem;
		ggm_tree_reconstruction(b, half_sum);
		// ggm_tree[choice_pos] = zero_block;
		// block nodes_sum = zero_block;
		// block one = makeBlock(0xFFFFFFFFFFFFFFFFLL,0xFFFFFFFFFFFFFFFELL);
		// for(int i = 0; i < leave_n; ++i) {
		// 	ggm_tree[i] = ggm_tree[i] & one;
		// 	nodes_sum = nodes_sum ^ ggm_tree[i];
		// }
		// ggm_tree[choice_pos] = nodes_sum;
	}

	void ggm_tree_reconstruction(bool *b, block *m) {
		uint32_t to_fill_idx = 0;
		for(uint32_t i = 1; i < depth; ++i) {
			to_fill_idx = to_fill_idx * 2;
			ggm_tree[to_fill_idx] = ggm_tree[to_fill_idx+1] = zero_block;
			// b[i-1] is negative of the choice bit
			if(b[i-1] == false) {
				layer_recover(i, 0, to_fill_idx, m[i-1]);
				to_fill_idx += 1;
			} 
			else 
				layer_recover(i, 1, to_fill_idx+1, m[i-1]);
		}
		ggm_tree[choice_pos] = zero_block;
		for(uint32_t i = 0; i < leave_n; ++i) {
			if (i != choice_pos)
				ggm_tree[choice_pos] ^= ggm_tree[i];
		}
		path_sum[depth-1] = ggm_tree[choice_pos];
	}

	void layer_recover(uint32_t depth, uint32_t lr, uint32_t to_fill_idx, block sum) {
		uint32_t item_n = 1 << depth;
		block nodes_sum = zero_block;
		
		for(uint32_t i = lr; i < item_n; i+=2)
			nodes_sum = nodes_sum ^ ggm_tree[i];
		path_sum[depth-1] = ggm_tree[to_fill_idx] = nodes_sum ^ sum;
		if(depth == this->depth-1) return;
		if (item_n == 2)
			ccrh->node_expand_2to4(ggm_tree, ggm_tree);
		else {
			for(int i = item_n-4; i >= 0; i-=4)
				ccrh->node_expand_4to8(&ggm_tree[i*2], &ggm_tree[i]);
		}
	}

	// compute sum of all leaves with index <= w
	// [TODO] batch execution
	void acc_left(block* acc, uint32_t w) {
		*acc = zero_block;
		if (w == choice_pos) {
			for (uint32_t i = 0; i < depth - 1; i++) {
				if (b[i] == false) {
					*acc ^= path_sum[i];
				}
			}
			*acc ^= path_sum[depth-1];
		}
		else {
			uint32_t i = 0;
			for (i = 0; i < depth - 1; i++) {
				if (((w >> (depth - 2 - i)) & 1) == b[i]) break; // find the first difference
				if (!b[i]) {
					*acc ^= path_sum[i];
				}
			}
			if (b[i]) {
				for (uint32_t j = i + 1; j < depth - 1; j++) {
					*acc ^= path_sum[j];
				}
				*acc ^= path_sum[depth-1];
			}
			block s[2] = {zero_block, zero_block};
			block to_expand = s[(w >> (depth - 2 - i)) & 1] = path_sum[i];
			for (i++; i < depth - 1; i++) {
				ccrh->node_expand_1to2(&s[0], &to_expand);
				to_expand = s[0];
				if ((w >> (depth - 2 - i)) & 1) {
					*acc ^= s[0];
					to_expand = s[1];
				}
			}
			*acc ^= s[w & 1];
		}
	}

	void consistency_check_msg_gen(block *chi_alpha, block *W) {
		// // X
		// block *chi = new block[leave_n];
		// Hash hash;
		// block digest[2];
		// hash.hash_once(digest, &secret_sum_f2, sizeof(block));
		// uni_hash_coeff_gen(chi, digest[0], leave_n);
		// *chi_alpha = chi[choice_pos];
		// vector_inn_prdt_sum_red(W, chi, ggm_tree, leave_n);
		// delete[] chi;
	}
};
#endif
