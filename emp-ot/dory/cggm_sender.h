#ifndef CGGM_SENDER_H__
#define CGGM_SENDER_H__
#include <iostream>
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "emp-ot/dory/ccrh.h"

using namespace emp;

/**
 * `BatchSize` denotes the number of cGGM trees represented by this class.
 * These trees will be evaluted together.
*/
template<typename IO, int BatchSize = 8>
class CGGM_Sender { public:
	block seed[BatchSize];
	block delta;
	block *tree_traversal_stack, *half_sum;
	uint32_t *dfs_levels;
	IO *io;
	int depth, leave_n;
	PRG prg;
	DoryCCRH<BatchSize> *ccrh;

	CGGM_Sender(IO *io, int depth_in) {
		initialization(io, depth_in);
		prg.random_block(seed, BatchSize);
	}

	void initialization(IO *io, int depth_in) {
		this->io = io;
		this->depth = depth_in;
		this->leave_n = 1<<(this->depth-1);
		tree_traversal_stack = new block[depth * BatchSize];
		half_sum = new block[(depth-1) * BatchSize];
		dfs_levels = new uint32_t[depth];
		ccrh = new DoryCCRH<BatchSize>(zero_block);
	}

	~CGGM_Sender() {
		delete[] tree_traversal_stack;
		delete[] half_sum;
		delete[] dfs_levels;
		delete ccrh;
	}

	// generate GGM tree, transfer secret, F2^k
	void compute(block secret) {
		this->delta = secret;
		ggm_tree_gen();
	}

	// send the nodes by oblivious transfer, F2^k
	template<typename OT>
	void send_f2k(OT * ot, IO * io2, int s) {
		ot->send(half_sum, (depth-1) * BatchSize, io2, s);
	}

	// generate GGM tree from the top
	void ggm_tree_gen() {
		for (size_t i = 0; i < BatchSize; i++) {
			tree_traversal_stack[BatchSize + i] = half_sum[i] = seed[i];
			tree_traversal_stack[i] = delta ^ tree_traversal_stack[BatchSize + i];
			for (int h = 1; h < depth - 1; h++)
				half_sum[h*BatchSize + i] = zero_block;
		}
		dfs_levels[0] = dfs_levels[1] = 0;

		int top = 1;
		while (top >= 0) {
			// We arrive at a leave, don't expand and go back to last level
			if (dfs_levels[top] >= depth-2) {
				top--;
				continue;
			}
			ccrh->batch_node_expand(&tree_traversal_stack[(top+1) * BatchSize], &tree_traversal_stack[top * BatchSize], &tree_traversal_stack[top * BatchSize]);
			dfs_levels[top] += 1;
			dfs_levels[top+1] = dfs_levels[top];
			top++;

			for (size_t i = 0; i < BatchSize; i++)
				half_sum[dfs_levels[top] * BatchSize + i] ^= tree_traversal_stack[top * BatchSize + i];
		}
	}

	// compute sum of all leaves with index <= w for tree `tree_idx`
	void acc_left(block& acc, uint32_t tree_idx, uint32_t w) {
		block s[2], to_expand;
		acc = zero_block;
		s[0] = seed[tree_idx];
		s[1] = delta ^ seed[tree_idx];
		for (int i = depth - 2; i >= 0; i--) {
			if ((w >> i) & 1) {
				acc ^= s[0];
				to_expand = s[1];
			}
			else {
				to_expand = s[0];
			}
			if (i == 0) break; // don't expand beyond the last layer
			ccrh->single_node_expand(s[0], s[1], to_expand);
		}
		acc ^= s[(w & 1)];
	}

	// compute sum of all leaves with index <= w
	// Although we can batch compute the acc efficiently, this API is not really used anywhere.
	void acc_left(block* acc, uint32_t* w) {
		block s[2 * BatchSize], to_expand[BatchSize];
		for(size_t i = 0; i < BatchSize; i++) {
			acc[i] = zero_block;
			s[i] = seed[i];
			s[BatchSize + i] = delta ^ seed[i];
		}
		for (int i = depth - 2; i >= 0; i--) {

			for (int j = 0; j < BatchSize; j++) {
				if ((w[j] >> i) & 1) {
					acc[j] ^= s[j];
					to_expand[j] = s[BatchSize + j];
				}
				else {
					to_expand[j] = s[j];
				}
			}
			if (i == 0) break; // don't expand beyond the last layer
			ccrh->batch_node_expand(&s[0], &s[BatchSize], to_expand);
		}
		for (size_t i = 0; i < BatchSize; i++)
			acc[i] ^= s[(w[i] & 1) * BatchSize + i];
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

// template<typename IO>
// class CGGM_Sender<IO, 1> { public:
// 	block seed;
// 	block delta;
// 	block *tree_traversal_stack, *half_sum;
// 	uint32_t *dfs_levels;
// 	IO *io;
// 	int depth, leave_n;
// 	PRG prg;
// 	DoryCCRH<1> *ccrh;

// 	CGGM_Sender(IO *io, int depth_in) {
// 		initialization(io, depth_in);
// 		prg.random_block(&seed, 1);
// 	}

// 	void initialization(IO *io, int depth_in) {
// 		this->io = io;
// 		this->depth = depth_in;
// 		this->leave_n = 1<<(this->depth-1);
// 		tree_traversal_stack = new block[depth];
// 		half_sum = new block[depth-1];
// 		dfs_levels = new uint32_t[depth];
// 		ccrh = new DoryCCRH<1>(zero_block);
// 	}

// 	~CGGM_Sender() {
// 		delete[] tree_traversal_stack;
// 		delete[] half_sum;
// 		delete[] dfs_levels;
// 		delete ccrh;
// 	}

// 	// generate GGM tree, transfer secret, F2^k
// 	void compute(block secret) {
// 		this->delta = secret;
// 		ggm_tree_gen();
// 	}

// 	// send the nodes by oblivious transfer, F2^k
// 	template<typename OT>
// 	void send_f2k(OT * ot, IO * io2, int s) {
// 		ot->send(half_sum, depth-1, io2, s);
// 	}

// 	// generate GGM tree from the top
// 	void ggm_tree_gen() {
// 		tree_traversal_stack[1] = half_sum[0] = seed;
// 		tree_traversal_stack[0] = delta ^ tree_traversal_stack[1];
// 		for (int h = 1; h < depth - 1; h++)
// 			half_sum[h] = zero_block;

// 		dfs_levels[0] = 0;
// 		dfs_levels[1] = 0;
// 		int top = 1;
// 		while (top >= 0) {
// 			// We arrive at a leave, don't expand and go back to last level
// 			if (dfs_levels[top] >= depth-2) {
// 				top--;
// 				continue;
// 			}
// 			ccrh->node_expand(&tree_traversal_stack[top+1], &tree_traversal_stack[top], &tree_traversal_stack[top]);
// 			dfs_levels[top] += 1;
// 			dfs_levels[top+1] = dfs_levels[top];
// 			top++;

// 			half_sum[dfs_levels[top]] ^= tree_traversal_stack[top];
// 		}
// 	}

// 	// compute sum of all leaves with index <= w
// 	// [TODO] batch execution
// 	void acc_left(block* acc, uint32_t w) {
// 		*acc = zero_block;
// 		block s[2] = {seed, delta ^ seed};
// 		// [TODO] this can be optimized by storing all nodes in the ggm_tree, it just doubles the current array size.
// 		for (int i = depth - 2; i >= 0; i--) {
// 			block to_expand = s[0];
// 			if ((w >> i) & 1) {
// 				*acc ^= s[0];
// 				to_expand = s[1];
// 			}
// 			if (i == 0) break; // don't expand beyond the last layer
// 			ccrh->node_expand(&s[0], &s[1], &to_expand);
// 		}
// 		*acc ^= s[w & 1];
// 	}

// 	void consistency_check_msg_gen(block *V) {
// 		// // X
// 		// block *chi = new block[leave_n];
// 		// Hash hash;
// 		// block digest[2];
// 		// hash.hash_once(digest, &secret_sum_f2, sizeof(block));
// 		// uni_hash_coeff_gen(chi, digest[0], leave_n);

// 		// vector_inn_prdt_sum_red(V, chi, ggm_tree, leave_n);
// 		// delete[] chi;
// 	}
// };

#endif
