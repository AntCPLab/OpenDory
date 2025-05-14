#ifndef CGGM_RECVER_H__
#define CGGM_RECVER_H__
#include <iostream>
#include "emp-tool/emp-tool.h"
#include "emp-ot/dory/ccrh.h"
#include "emp-ot/dory/dory_preot.h"
#include "emp-ot/dory/performance.h"

using namespace emp;

/**
 * `B` denotes the number of cGGM trees represented by this class.
 * These trees will be evaluted together.
*/
template<typename IO, int B = 16>
class CGGM_Recver {
public:
	block *tree_traversal_stack, *half_sum;
	block *path_sum;
	uint32_t *dfs_levels;
	bool *b;
	block tree_delta[B];
	bool tree_delta_choice[B];
	uint32_t choice_pos[B];
	uint32_t depth, leave_n;
	IO *io;
	DoryCCRH *ccrh;

	CGGM_Recver(IO *io, uint32_t depth_in) {
		this->io = io;
		this->depth = depth_in;
		this->leave_n = 1<<(depth_in-1);
		tree_traversal_stack = new block[depth * B];
		half_sum = new block[(depth-1) * B];
		b = new bool[(depth-1) * B];
		path_sum = new block[depth * B];
		ccrh = new DoryCCRH(zero_block);
		dfs_levels = new uint32_t[depth];
	}

	~CGGM_Recver(){
		delete[] tree_traversal_stack;
		delete[] half_sum;
		delete[] b;
		delete[] path_sum;
		delete ccrh;
		delete[] dfs_levels;
	}

	uint32_t* get_index() {
		memset(choice_pos, 0, B * sizeof(uint32_t));
		for(uint32_t i = 0; i < depth-1; ++i) {
			for (int j = 0; j < B; j++) {
				choice_pos[j] <<= 1;
				if(!b[i*B + j])
					choice_pos[j] +=1;
			}
		}
		return choice_pos;
	}

	void extract_tree_delta(DoryOTPre<IO>* ot, int s) {
		memcpy(tree_delta, ot->unit_offsets + s * B, B * sizeof(block));
		memcpy(tree_delta_choice, ot->unit_choices + s * B, B * sizeof(bool));
	}

	void recv_f2k(DoryOTPre<IO> * ot, IO * io2, int s) {
		ot->template recv<B>(half_sum, io2, s * B);


		// block* sender_blocks = new block[(depth-1) * B];
		// block* sender_offsets = new block[B];
		// io2->recv_block(sender_blocks, (depth-1) * B);
		// io2->recv_block(sender_offsets, B);
		// for (int i = 0; i < depth - 1; i++) {
		// 	for (int j = 0; j < B; j++) {
		// 		block sblock = sender_blocks[i * B + j];
		// 		if (b[i * B + j])
		// 			sblock ^= sender_offsets[j];
		// 		if (!cmpBlock(&half_sum[i * B + j], &sblock, 1)) {
		// 			std::cout << "dory recv_f2k data: " << half_sum[i * B + j] << ",\t" << "sblock:\t" << sblock << std::endl;
		// 			error("wrong!\n");
		// 		}
		// 	}
		// }

		// delete[] sender_blocks;
		// delete[] sender_offsets;
	}

	void compute() {
		ggm_tree_reconstruction();
	}

	void ggm_tree_reconstruction() {
		block leaves_sum[B];
		for (uint32_t h = 1; h < depth - 1; h++)
			for (int j = 0; j < B; j++)
				path_sum[h * B + j] = zero_block;
		for (int j = 0; j < B; j++) {
			tree_traversal_stack[j] = path_sum[j] = half_sum[j];
			leaves_sum[j] = zero_block;
		}
		dfs_levels[0] = 0;
		
		int top = 0;
		uint32_t filled_level = 0;
		while (top >= 0) {
			// When only one node left in stack, we are done with its corresponding level, and
			// it is time to calculate the path sum at this level
			if (top == 0) {
				if (dfs_levels[top] == filled_level + 1) {
					// Filled in the last off-path node, and insert it into the stack
					for (int j = 0; j < B; j++) {
						path_sum[dfs_levels[top] * B + j] ^= half_sum[dfs_levels[top] * B + j];
						tree_traversal_stack[(top + 1) * B + j] = path_sum[dfs_levels[top] * B + j];
					}
					dfs_levels[top + 1] = dfs_levels[top];
					top++;
					filled_level++;
					continue;
				}
			}
			// We arrive at a leave, don't expand and go back to last level
			if (dfs_levels[top] >= depth-2) {
				for (int j = 0; j < B; j++)
					leaves_sum[j] ^= tree_traversal_stack[top * B + j];
				top--;
				continue;
			}
			ccrh->batch_node_expand<B>(&tree_traversal_stack[(top+1) * B], &tree_traversal_stack[top * B], &tree_traversal_stack[top * B]);
			dfs_levels[top] += 1;
			dfs_levels[top+1] = dfs_levels[top];
			top++;

			for (int j = 0; j < B; j++) {
				if (b[dfs_levels[top] * B + j])
					path_sum[dfs_levels[top] * B + j] ^= tree_traversal_stack[(top-1) * B + j];
				else
					path_sum[dfs_levels[top] * B + j] ^= tree_traversal_stack[top * B + j];
			}
		}
		// leaves_sum is the accumulation of all nodes except the choice node
		for (int j = 0; j < B; j++) {
			path_sum[(depth - 1) * B + j] = leaves_sum[j];
		}
	}

	block acc_left(uint32_t tree_idx, uint32_t w) {
		block acc;
		acc_left(acc, tree_idx, w);
		return acc;
	}

	// compute sum of all leaves with index <= w for tree `tree_idx`
	void acc_left(block& acc, uint32_t tree_idx, uint32_t w) {
		acc = zero_block;
		if (w == choice_pos[tree_idx]) {
			for (uint32_t i = 0; i < depth - 1; i++) {
				if (b[i*B + tree_idx] == false) {
					acc ^= path_sum[i*B + tree_idx];
				}
			}
			acc ^= path_sum[(depth-1)*B + tree_idx];
		}
		else {
			bool direction = w < choice_pos[tree_idx];
			uint32_t i = 0;
			for (i = 0; i < depth - 1; i++) {
				if (((w >> (depth - 2 - i)) & 1) == b[i*B + tree_idx]) break; // find the first difference
				if (b[i*B + tree_idx] ^ direction) {
					acc ^= path_sum[i*B + tree_idx];
				}
			}

			block s[2] = {zero_block, zero_block};
			block to_expand = s[(w >> (depth - 2 - i)) & 1] = path_sum[i*B + tree_idx];
			for (i++; i < depth - 1; i++) {
				ccrh->single_node_expand(s[0], s[1], to_expand);
				to_expand = s[1-direction];
				if (((w >> (depth - 2 - i)) & 1) == direction) {
					acc ^= s[1-direction];
					to_expand = s[direction];
				}
			}
			if (direction)
				acc ^= s[w & 1];
		}
	}

	// Compute the leave with index = w for tree `tree_idx`
	// Used for debugging purpose
	block leave(uint32_t tree_idx, uint32_t w) {
		if (w == choice_pos[tree_idx]) {
			return path_sum[(depth-1)*B + tree_idx];
		}
		else {
			bool direction = w < choice_pos[tree_idx];
			uint32_t i = 0;
			for (i = 0; i < depth - 1; i++) {
				if (((w >> (depth - 2 - i)) & 1) == b[i*B + tree_idx]) break; // find the first difference
			}

			block s[2] = {zero_block, zero_block};
			block to_expand = s[(w >> (depth - 2 - i)) & 1] = path_sum[i*B + tree_idx];
			for (i++; i < depth - 1; i++) {
				ccrh->single_node_expand(s[0], s[1], to_expand);
				to_expand = s[1-direction];
				if (((w >> (depth - 2 - i)) & 1) == direction) {
					to_expand = s[direction];
				}
			}
			return s[w & 1];
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
