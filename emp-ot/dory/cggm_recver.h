#ifndef CGGM_RECVER_H__
#define CGGM_RECVER_H__
#include <iostream>
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "emp-ot/dory/ccrh.h"

using namespace emp;

template<typename IO, int BatchSize = 8>
class CGGM_Recver {
public:
	block *tree_traversal_stack, *half_sum;
	block *path_sum;
	uint32_t *dfs_levels;
	bool *b;
	uint32_t choice_pos[BatchSize];
	uint32_t depth, leave_n;
	IO *io;
	DoryCCRH<BatchSize> *ccrh;

	CGGM_Recver(IO *io, uint32_t depth_in) {
		this->io = io;
		this->depth = depth_in;
		this->leave_n = 1<<(depth_in-1);
		// tree_traversal_stack = new block[depth * BatchSize];
		tree_traversal_stack = reinterpret_cast<block*>(aligned_alloc(64, depth * BatchSize * sizeof(block)));
		half_sum = new block[(depth-1) * BatchSize];
		b = new bool[(depth-1) * BatchSize];
		path_sum = new block[depth * BatchSize];
		ccrh = new DoryCCRH<BatchSize>(zero_block);
		dfs_levels = new uint32_t[depth];
	}

	~CGGM_Recver(){
		// delete[] tree_traversal_stack;
		free(tree_traversal_stack);
		delete[] half_sum;
		delete[] b;
		delete[] path_sum;
		delete ccrh;
		delete[] dfs_levels;
	}

	uint32_t* get_index() {
		memset(choice_pos, 0, BatchSize * sizeof(uint32_t));
		for(uint32_t i = 0; i < depth-1; ++i) {
			for (int j = 0; j < BatchSize; j++) {
				choice_pos[j] <<= 1;
				if(!b[i*BatchSize + j])
					choice_pos[j] +=1;
			}
		}
		return choice_pos;
	}

	// receive the message and reconstruct the tree
	// j: position of the secret, begins from 0
	template<typename OT>
	void recv_f2k(OT * ot, IO * io2, int s) {
		ot->recv(half_sum, (depth-1) * BatchSize, io2, s);
	}

	// receive the message and reconstruct the tree
	// j: position of the secret, begins from 0
	void compute() {
		ggm_tree_reconstruction();
	}

	void ggm_tree_reconstruction() {
		block leaves_sum[BatchSize];
		for (int h = 1; h < depth - 1; h++)
			for (int j = 0; j < BatchSize; j++)
				path_sum[h * BatchSize + j] = zero_block;
		for (int j = 0; j < BatchSize; j++) {
			tree_traversal_stack[j] = path_sum[j] = half_sum[j];
			leaves_sum[j] = zero_block;
		}
		dfs_levels[0] = 0;
		
		int top = 0, filled_level = 0;
		while (top >= 0) {
			// When only one node left in stack, we are done with its corresponding level, and
			// it is time to calculate the path sum at this level
			if (top == 0) {
				if (dfs_levels[top] == filled_level + 1) {
					// Filled in the last off-path node, and insert it into the stack
					for (int j = 0; j < BatchSize; j++) {
						path_sum[dfs_levels[top] * BatchSize + j] ^= half_sum[dfs_levels[top] * BatchSize + j];
						tree_traversal_stack[(top + 1) * BatchSize + j] = path_sum[dfs_levels[top] * BatchSize + j];
					}
					dfs_levels[top + 1] = dfs_levels[top];
					top++;
					filled_level++;
					continue;
				}
			}
			// We arrive at a leave, don't expand and go back to last level
			if (dfs_levels[top] >= depth-2) {
				for (int j = 0; j < BatchSize; j++)
					leaves_sum[j] ^= tree_traversal_stack[top * BatchSize + j];
				top--;
				continue;
			}
			ccrh->batch_node_expand(&tree_traversal_stack[(top+1) * BatchSize], &tree_traversal_stack[top * BatchSize], &tree_traversal_stack[top * BatchSize]);
			dfs_levels[top] += 1;
			dfs_levels[top+1] = dfs_levels[top];
			top++;

			for (int j = 0; j < BatchSize; j++) {
				if (b[dfs_levels[top] * BatchSize + j])
					path_sum[dfs_levels[top] * BatchSize + j] ^= tree_traversal_stack[(top-1) * BatchSize + j];
				else
					path_sum[dfs_levels[top] * BatchSize + j] ^= tree_traversal_stack[top * BatchSize + j];
			}
		}
		for (int j = 0; j < BatchSize; j++)
			path_sum[(depth - 1) * BatchSize + j] = leaves_sum[j];
	}

	// compute sum of all leaves with index <= w for tree `tree_idx`
	void acc_left(block& acc, uint32_t tree_idx, uint32_t w) {
		acc = zero_block;
		if (w == choice_pos[tree_idx]) {
			for (uint32_t i = 0; i < depth - 1; i++) {
				if (b[i*BatchSize + tree_idx] == false) {
					acc ^= path_sum[i*BatchSize + tree_idx];
				}
			}
			acc ^= path_sum[(depth-1)*BatchSize + tree_idx];
		}
		else {
			uint32_t i = 0;
			for (i = 0; i < depth - 1; i++) {
				if (((w >> (depth - 2 - i)) & 1) == b[i*BatchSize + tree_idx]) break; // find the first difference
				if (!b[i*BatchSize + tree_idx]) {
					acc ^= path_sum[i*BatchSize + tree_idx];
				}
			}
			if (b[i*BatchSize + tree_idx]) {
				for (uint32_t k = i + 1; k < depth - 1; k++) {
					acc ^= path_sum[k*BatchSize + tree_idx];
				}
				acc ^= path_sum[(depth-1)*BatchSize + tree_idx];
			}
			block s[2] = {zero_block, zero_block};
			block to_expand = s[(w >> (depth - 2 - i)) & 1] = path_sum[i*BatchSize + tree_idx];
			for (i++; i < depth - 1; i++) {
				ccrh->single_node_expand(s[0], s[1], to_expand);
				to_expand = s[0];
				if ((w >> (depth - 2 - i)) & 1) {
					acc ^= s[0];
					to_expand = s[1];
				}
			}
			acc ^= s[w & 1];
		}
	}

	// compute sum of all leaves with index <= w
	// [TODO] batch execution
	void acc_left(block* acc, uint32_t* w) {
		// Receiver's acc is quite different from Sender's acc.
		// Considering that different trees might expand at different locations, what can we do to optimize for batch execution?
		for (int j = 0; j < BatchSize; j++) {
			acc[j] = zero_block;
			if (w[j] == choice_pos[j]) {
				for (uint32_t i = 0; i < depth - 1; i++) {
					if (b[i*BatchSize + j] == false) {
						acc[j] ^= path_sum[i*BatchSize + j];
					}
				}
				acc[j] ^= path_sum[(depth-1)*BatchSize + j];
			}
			else {
				uint32_t i = 0;
				for (i = 0; i < depth - 1; i++) {
					if (((w[j] >> (depth - 2 - i)) & 1) == b[i*BatchSize + j]) break; // find the first difference
					if (!b[i*BatchSize + j]) {
						acc[j] ^= path_sum[i*BatchSize + j];
					}
				}
				if (b[i*BatchSize + j]) {
					for (uint32_t k = i + 1; k < depth - 1; k++) {
						acc[j] ^= path_sum[k*BatchSize + j];
					}
					acc[j] ^= path_sum[(depth-1)*BatchSize + j];
				}
				block s[2] = {zero_block, zero_block};
				block to_expand = s[(w[j] >> (depth - 2 - i)) & 1] = path_sum[i*BatchSize + j];
				for (i++; i < depth - 1; i++) {
					ccrh->single_node_expand(s[0], s[1], to_expand);
					to_expand = s[0];
					if ((w[j] >> (depth - 2 - i)) & 1) {
						acc[j] ^= s[0];
						to_expand = s[1];
					}
				}
				acc[j] ^= s[w[j] & 1];
			}
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
