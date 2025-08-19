#ifndef CGGM_SENDER_H__
#define CGGM_SENDER_H__
#include <iostream>
#include "emp-tool/emp-tool.h"
#include "emp-ot/dory/ccrh.h"
#include "emp-ot/dory/dory_preot.h"
#include "emp-ot/dory/performance.h"
#include "emp-ot/utils.h"

using namespace emp;

/**
 * `B` denotes the number of cGGM trees represented by this class.
 * These trees will be evaluted together.
*/
template<typename IO, int B = 16>
class CGGM_Sender { public:
	block seed[B];
	block tree_delta[B];
	block *tree_traversal_stack, *half_sum;
	uint32_t *dfs_levels;
	IO *io;
	uint32_t depth, leave_n;
	PRG prg;
	DoryCCRH *ccrh;
	block one;

	CGGM_Sender(IO *io, uint32_t depth_in) {
		this->io = io;
		this->depth = depth_in;
		this->leave_n = 1<<(this->depth-1);
		tree_traversal_stack = new block[depth * B];
		half_sum = new block[(depth-1) * B];
		dfs_levels = new uint32_t[depth];
		ccrh = new DoryCCRH(zero_block);
		one = makeBlock(0x0LL, 0x1LL);

		initialize();
	}

	void initialize() {
		prg.random_block(seed, B);
	}

	~CGGM_Sender() {
		delete[] tree_traversal_stack;
		delete[] half_sum;
		delete[] dfs_levels;
		delete ccrh;
	}

	void extract_tree_delta(DoryOTPre<IO>* ot, int s) {
		memcpy(tree_delta, ot->unit_offsets + s * B, B * sizeof(block));
	}

	// generate GGM tree
	void compute() {
		ggm_tree_gen();
	}

	// send the nodes by oblivious transfer, F2^k
	void send_f2k(DoryOTPre<IO> * ot, IO * io2, int s) {
		ot->template send<B>(half_sum, io2, s*B);


		// io2->send_block(half_sum, (depth-1)*B);
		// io2->send_block(tree_delta, B);
	}

	// generate GGM tree from the top
	void ggm_tree_gen() {
		for (size_t i = 0; i < B; i++) {
			tree_traversal_stack[B + i] = half_sum[i] = seed[i];
			tree_traversal_stack[i] = tree_delta[i] ^ tree_traversal_stack[B + i];
			for (uint32_t h = 1; h < depth - 1; h++)
				half_sum[h*B + i] = zero_block;
		}
		dfs_levels[0] = dfs_levels[1] = 0;

		int top = 1;
		while (top >= 0) {
			// We arrive at a leave, don't expand and go back to last level
			if (dfs_levels[top] >= depth-2) {
				top--;
				continue;
			}
			ccrh->batch_node_expand<B>(&tree_traversal_stack[(top+1) * B], &tree_traversal_stack[top * B], &tree_traversal_stack[top * B]);
			dfs_levels[top] += 1;
			dfs_levels[top+1] = dfs_levels[top];
			top++;

			for (size_t i = 0; i < B; i++)
				half_sum[dfs_levels[top] * B + i] ^= tree_traversal_stack[top * B + i];
		}
	}

	// generate GGM tree from the top
	void ggm_tree_gen(block* leaves_acc) {
		for (size_t i = 0; i < B; i++) {
			tree_traversal_stack[B + i] = seed[i];
			tree_traversal_stack[i] = tree_delta[i] ^ tree_traversal_stack[B + i];
		}
		dfs_levels[0] = dfs_levels[1] = 0;

		int next_leave_idx = 0;
		int top = 1;
		while (top >= 0) {
			// We arrive at a leave, don't expand and go back to last level
			if (dfs_levels[top] >= depth-2) {
				for(int i = 0; i < B; i++) {
					leaves_acc[next_leave_idx*B + i] = tree_traversal_stack[top * B + i];
				}
				next_leave_idx++;
				top--;
				continue;
			}
			ccrh->batch_node_expand<B>(&tree_traversal_stack[(top+1) * B], &tree_traversal_stack[top * B], &tree_traversal_stack[top * B]);
			dfs_levels[top] += 1;
			dfs_levels[top+1] = dfs_levels[top];
			top++;
		}
		for (int i = 1; i < leave_n; i++) {
			for (int j = 0; j < B; j++)
				leaves_acc[i * B + j] ^= leaves_acc[(i-1) * B + j];
		}
	}

	/**
	 * Linear combination of leaves with coefficents derived from universal hash.
	 * Memory consumption: logarithmic.
	*/
	void ggm_tree_lin_comb(block* res, block uh_seed) {

		block coeff = one;
		memset(res, 0, B * sizeof(block));

		for (size_t i = 0; i < B; i++) {
			tree_traversal_stack[B + i] = seed[i];
			tree_traversal_stack[i] = tree_delta[i] ^ seed[i];
		}
		dfs_levels[0] = dfs_levels[1] = 0;

		int top = 1;
		while (top >= 0) {
			// We arrive at a leave, don't expand and go back to last level
			if (dfs_levels[top] >= depth-2) {
				block r[B];
				vector_gfmul<B>(r, &tree_traversal_stack[top * B], coeff);
				gfmul(coeff, uh_seed, &coeff);
				for (int i = 0; i < B; i++)
					res[i] ^= r[i];
				top--;
				continue;
			}
			ccrh->batch_node_expand<B>(&tree_traversal_stack[(top+1) * B], &tree_traversal_stack[top * B], &tree_traversal_stack[top * B]);
			dfs_levels[top] += 1;
			dfs_levels[top+1] = dfs_levels[top];
			top++;
		}

		// Multiply everything with seed because the coeffs's powers were one less during the above expansion
		vector_gfmul<B>(res, res, uh_seed);
	}

	// compute sum of all leaves with index <= w for tree `tree_idx`
	void acc_left(block& acc, uint32_t tree_idx, uint32_t w) {
		block s[2], to_expand;
		acc = zero_block;
		s[0] = seed[tree_idx];
		s[1] = tree_delta[tree_idx] ^ seed[tree_idx];
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

	// Compute the leave with index = w for tree `tree_idx`
	// Used for debugging purpose
	block leave(uint32_t tree_idx, uint32_t w) {
		block s[2], to_expand;
		s[0] = seed[tree_idx];
		s[1] = tree_delta[tree_idx] ^ seed[tree_idx];
		for (int i = depth - 2; i >= 0; i--) {
			if ((w >> i) & 1) {
				to_expand = s[1];
			}
			else {
				to_expand = s[0];
			}
			if (i == 0) break; // don't expand beyond the last layer
			ccrh->single_node_expand(s[0], s[1], to_expand);
		}
		return s[(w & 1)];
	}

	// compute sum of all leaves with index <= w
	// Although we can batch compute the acc efficiently, this API is not really used anywhere.
	void acc_left(block* acc, uint32_t* w) {
		block s[2 * B], to_expand[B];
		for(size_t i = 0; i < B; i++) {
			acc[i] = zero_block;
			s[i] = seed[i];
			s[B + i] = tree_delta[i] ^ seed[i];
		}
		for (int i = depth - 2; i >= 0; i--) {

			for (int j = 0; j < B; j++) {
				if ((w[j] >> i) & 1) {
					acc[j] ^= s[j];
					to_expand[j] = s[B + j];
				}
				else {
					to_expand[j] = s[j];
				}
			}
			if (i == 0) break; // don't expand beyond the last layer
			ccrh->batch_node_expand<B>(&s[0], &s[B], to_expand);
		}
		for (size_t i = 0; i < B; i++)
			acc[i] ^= s[(w[i] & 1) * B + i];
	}

	void consistency_check_msg_gen(IO* io2, block *V) {
		block uh_seed;
		io2->recv_block(&uh_seed, 1);
		ggm_tree_lin_comb(V, uh_seed);
	}
};

#endif
