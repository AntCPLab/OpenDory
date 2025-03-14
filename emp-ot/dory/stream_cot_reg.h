#ifndef STREAM_COT_REG_H__
#define STREAM_COT_REG_H__

#include <emp-tool/emp-tool.h>
#include <set>
#include "emp-ot/dory/cggm_sender.h"
#include "emp-ot/dory/cggm_recver.h"
#include "emp-ot/dory/preot.h"
#include "emp-ot/dory/performance.h"
#include <list>
#include <utility>

using namespace emp;
using std::future;

template<typename IO, int BatchSize>
class StreamCotReg {
public:
	constexpr static int EVAL_SIZE = 8;
	int party, threads;
	int item_n, m;
	uint32_t idx_max;
	int tree_height, leave_n;
	int tree_n;
	int batch_tree_n;
	int consist_check_cot_num;
	bool is_malicious;

	PRG prg;
	IO *netio;
	IO **ios;
	block Delta_f2k;
	block *consist_check_chi_alpha = nullptr, *consist_check_VW = nullptr;
	ThreadPool *pool;
	
	std::vector<uint32_t> item_pos_recver;
	GaloisFieldPacking pack;

	vector<CGGM_Sender<IO, BatchSize>*> senders;
	vector<CGGM_Recver<IO, BatchSize>*> recvers;
	int mask;
	int ell = 16;
	uint32_t upper_bound;
	uint32_t cnt;
	DoryPRP prp;
	block minustwo, one;

	// block* eval_path_sum_buf;


	DoryCCRH *ccrh;

	/**
	 * Stream COT with regular LPN noise assumption, the param `n`, `t`, and `log_bin_sz` are
	 * related as: `n = t * (2**log_bin_sz)`,
	 * meaning `t` calls to CGGM, each with a vector length of `2**log_bin_sz`.
	*/
	StreamCotReg(int party, int threads, int n, int t, int log_bin_sz, ThreadPool * pool, IO **ios) {
		this->party = party;
		this->threads = threads;
		netio = ios[0];
		this->ios = ios;
		consist_check_cot_num = 128;

		this->pool = pool;
		this->is_malicious = false;

		this->item_n = t;
		this->idx_max = n;
		this->tree_height = log_bin_sz+1;
		this->leave_n = 1<<(this->tree_height-1);
		this->tree_n = this->item_n;
		this->batch_tree_n = (this->tree_n + BatchSize - 1) / BatchSize;

		this->cnt = this->upper_bound = n;

		mask = 1;
		while(mask < n) {
			mask <<=1;
			mask = mask | 0x1;
		}

		minustwo = makeBlock(0xFFFFFFFFFFFFFFFFLL,0xFFFFFFFFFFFFFFFELL);
		one = makeBlock(0x0LL, 0x1LL);

		if (party == ALICE) {
			for(int i = 0; i < batch_tree_n; ++i) {
				senders.push_back(new CGGM_Sender<IO, BatchSize>(netio, tree_height));
			}
		}
		else {
			for(int i = 0; i < batch_tree_n; ++i) {
				recvers.push_back(new CGGM_Recver<IO, BatchSize>(netio, tree_height));
			}
		}

		ccrh = new DoryCCRH(zero_block);

		// eval_path_sum_buf = new block[tree_height*EVAL_SIZE];
	}

	~StreamCotReg() {
		for (auto p : senders) delete p;
		for (auto p : recvers) delete p;
		delete ccrh;
		// delete[] eval_path_sum_buf;
	}

	void set_malicious() {
		this->is_malicious = true;
	}

	void sender_init(block delta) {
		Delta_f2k = delta;
	}

	void recver_init() {
		item_pos_recver.resize(this->batch_tree_n * BatchSize);
	}

	// MPFSS F_2k
	void bootstrap(OTPre<IO> * ot, block *pre_cot_data) {
		acc_time_log("bootstrap");

		if(party == ALICE) {
			mpcot_init_sender(senders, ot);
			exec_parallel_sender(senders, ot);
		} else {
			mpcot_init_recver(recvers, ot);
			exec_parallel_recver(recvers, ot);
		}

		if(is_malicious)
			consistency_check_f2k(pre_cot_data, tree_n);

		cnt = 0;
		acc_time_log("bootstrap");
	}

	void mpcot_init_sender(vector<CGGM_Sender<IO, BatchSize>*> &senders, OTPre<IO> *ot) {
		for(int i = 0; i < batch_tree_n; ++i) {
			senders[i]->initialize();
			ot->choices_sender();
		}
		netio->flush();
		ot->reset();
	}

	void mpcot_init_recver(vector<CGGM_Recver<IO, BatchSize>*> &recvers, OTPre<IO> *ot) {
		for(int i = 0; i < batch_tree_n; ++i) {
			ot->choices_recver(recvers[i]->b);
			const uint32_t* idx = recvers[i]->get_index();
			for (int j = 0; j < BatchSize; j++)
				item_pos_recver[i*BatchSize + j] = idx[j];
		}
		netio->flush();
		ot->reset();
	}

	void exec_parallel_sender(vector<CGGM_Sender<IO, BatchSize>*> &senders, OTPre<IO> *ot) {
		vector<future<void>> fut;
		// Assume LPN with a regular noise distribution,
		// the task is simply divided into t calls of SPCOT, 
		// each with a length of n/t. Here `tree_n` is t, `leave_n` is n/t.
		int width = batch_tree_n / threads;
		int start = 0, end = width;
		for(int i = 0; i < threads - 1; ++i) {
			fut.push_back(this->pool->enqueue([this, start, end, width, 
						senders, ot](){
				for(int i = start; i < end; ++i)
					exec_f2k_sender(senders[i], ot, ios[start/width], i);
			}));
			start = end;
			end += width;
		}
		end = batch_tree_n;
		for(int i = start; i < end; ++i)
			exec_f2k_sender(senders[i], ot, ios[threads - 1], i);
		for (auto & f : fut) f.get();
	}

	void exec_parallel_recver(vector<CGGM_Recver<IO, BatchSize>*> &recvers, OTPre<IO> *ot) {
		vector<future<void>> fut;		
		int width = batch_tree_n / threads;
		int start = 0, end = width;
		for(int i = 0; i < threads - 1; ++i) {
			fut.push_back(this->pool->enqueue([this, start, end, width, 
						recvers, ot](){
				for(int i = start; i < end; ++i)
					exec_f2k_recver(recvers[i], ot, ios[start/width], i);
			}));
			start = end;
			end += width;
		}
		end = batch_tree_n;
		for(int i = start; i < end; ++i)
			exec_f2k_recver(recvers[i], ot, ios[threads - 1], i);
		for (auto & f : fut) f.get();
	}

	void exec_f2k_sender(CGGM_Sender<IO, BatchSize> *sender, OTPre<IO> *ot, IO *io, int i) {
		sender->compute(Delta_f2k);
		sender->template send_f2k<OTPre<IO>>(ot, io, i);
		io->flush();
		if(is_malicious)
			sender->consistency_check_msg_gen(consist_check_VW+i);
	}

	void exec_f2k_recver(CGGM_Recver<IO, BatchSize> *recver, OTPre<IO> *ot, IO *io, int i) {
		recver->template recv_f2k<OTPre<IO>>(ot, io, i);
		recver->compute();
		if(is_malicious) 
			recver->consistency_check_msg_gen(consist_check_chi_alpha+i, consist_check_VW+i);
	}

	inline void sample_J(uint32_t** J, int ell, int idx) {
		int n_blocks = (ell + 3) / 4;
		block* tmp = new block[n_blocks];
		for(int m = 0; m < n_blocks; ++m)
			tmp[m] = makeBlock(cnt, m);
		prp.permute_block(tmp, n_blocks);
		*J = (uint32_t*)(tmp);
		for (int i = 0; i < ell; i++) {
			(*J)[i] &= mask;
			(*J)[i] = (*J)[i] >= idx_max? (*J)[i]-idx_max : (*J)[i];
		}
	}

	inline void sample_J(uint32_t** J, int ell, int start, int end) {
		int n_blocks = (ell + 3) / 4;
		block* tmp = new block[(end-start) * n_blocks];
		acc_time_log("sample 1st loop");
		block* pt = tmp;
		for (int i = start; i < end; i++) {
			for(int m = 0; m < n_blocks; ++m, pt++)
				*pt = makeBlock(i, m);
		}
		acc_time_log("sample 1st loop");
		acc_time_log("sample enc");
		prp.permute_block(tmp, (end-start) * n_blocks);
		acc_time_log("sample enc");
		*J = (uint32_t*)(tmp);
		acc_time_log("sample 2nd loop");
		for (int i = 0; i < (end-start) * n_blocks * 4; i++) {
			(*J)[i] &= mask;
			(*J)[i] = (*J)[i] >= idx_max? (*J)[i]-idx_max : (*J)[i];
		}
		acc_time_log("sample 2nd loop");
	}

	// inline void sample_J_batch(uint32_t** J, int start) {
	// 	int n_blocks = (ell + 3) / 4;
	// 	block* tmp = new block[n_blocks * BatchSize];
	// 	acc_time_log("sample 1st loop");
	// 	block* pt = tmp;
	// 	for (int i = start; i < start + BatchSize; i++) {
	// 		for(int m = 0; m < n_blocks; ++m, pt++)
	// 			*pt = makeBlock(i, m);
	// 	}
	// 	acc_time_log("sample 1st loop");
	// 	acc_time_log("sample enc");
	// 	prp.permute_block(tmp, BatchSize * n_blocks);
	// 	acc_time_log("sample enc");
	// 	*J = (uint32_t*)(tmp);
	// 	acc_time_log("sample 2nd loop");
	// 	for (int i = 0; i < BatchSize * n_blocks * 4; i++) {
	// 		(*J)[i] &= mask;
	// 		(*J)[i] = (*J)[i] >= idx_max? (*J)[i]-idx_max : (*J)[i];
	// 	}
	// 	acc_time_log("sample 2nd loop");
	// }

	inline void sample_J_batch(uint32_t* J, int start) {
		assert(reinterpret_cast<uintptr_t>(data) % 16 == 0);
		int n_blocks = (ell + 3) / 4;
		block* tmp = reinterpret_cast<block*>(J);
		acc_time_log("sample 1st loop");
		block* pt = tmp;
		for (int i = start; i < start + BatchSize; i++) {
			for(int m = 0; m < n_blocks; ++m, pt++)
				*pt = makeBlock(i, m);
		}
		acc_time_log("sample 1st loop");
		acc_time_log("sample enc");
		prp.permute_block(tmp, BatchSize * n_blocks);
		acc_time_log("sample enc");
		acc_time_log("sample 2nd loop");
		for (int i = 0; i < BatchSize * n_blocks * 4; i++) {
			J[i] &= mask;
			J[i] = J[i] >= idx_max? J[i]-idx_max : J[i];
		}
		acc_time_log("sample 2nd loop");
	}

	uint32_t silent_ot_left() {
		return upper_bound - cnt;
	}

	void eval_full(block* data) {
		if (cnt > 0)
			error("Can only call eval_full when cnt == 0");
		eval(data, upper_bound);
	}

	void eval(block *data, uint32_t num) {
		if (cnt + num > upper_bound)
			error("Eval more than upper limit. Please try a smaller number and bootstrap.");

		vector<future<void>> fut;		
		int width = num / threads;
		int start = 0, end = width;
		for(int i = 0; i < threads - 1; ++i) {
			fut.push_back(this->pool->enqueue([this, data, start, end](){
				exec_eval(data, start, end);
			}));
			start = end;
			end += width;
		}
		end = num;
		exec_eval(data, start, end);
		for (auto & f : fut) f.get();

		cnt += num;
	}

	void exec_eval(block* data, int start, int end) {
		// block* pt = data + start;
		// for (int i = start; i < end; i++) {
		// 	exec_eval(pt, i);
		// 	pt++;
		// }

		int i = start;
		for(; i < end-EVAL_SIZE; i+=EVAL_SIZE) {
			__eval4(data, i);
		}
		for (; i < end; i++) {
			exec_eval(data, i);
		}

		// int length = end - start;
		// for(int i = 0; i < length/BatchSize; ++i) {
		// 	exec_eval_batch(data, start + i*BatchSize);
		// 	data += BatchSize;
		// }
		// int remain = length % BatchSize;
		// for (int i = end-remain; i < end; i++) {
		// 	exec_eval(data, i);
		// 	data++;
		// }

		// exec_eval__(pt, start, end);
		// exec_eval_(pt, start, end);

		// exec_eval_with_space(pt, start, end);


	}

	void exec_eval(block* data, int idx) {
		acc_time_log("sample");
		uint32_t* J;
		sample_J(&J, ell, idx);
		acc_time_log("sample");
		int leave_mask = (1 << (tree_height - 1)) - 1;
		*data = zero_block;
		acc_time_log("eval");
		if (party == ALICE) {
			/* Unbatched impl. */
			// for (int x = 0; x < ell; x++) {
			// 	int uj = J[x] >> (tree_height - 1), wj = J[x] & leave_mask;
			// 	block tmp;
			// 	senders[uj/DEFAULT_EXPAND_SIZE]->acc_left(tmp, uj % DEFAULT_EXPAND_SIZE, wj);
			// 	*data ^= tmp;
			// 	if (uj & 1)
			// 		*data ^= Delta_f2k;
			// }
			
			/* Batch impl. */
			int y;
			bool correction = false;
			block seed[DEFAULT_EXPAND_SIZE];
			uint32_t w[DEFAULT_EXPAND_SIZE];
			for (y = 0; y < ell/DEFAULT_EXPAND_SIZE; y++) {
				for (int x = 0; x < DEFAULT_EXPAND_SIZE; x++) {
					int uj = J[y*DEFAULT_EXPAND_SIZE + x] >> (tree_height - 1), wj = J[y*DEFAULT_EXPAND_SIZE + x] & leave_mask;
					seed[x] = senders[uj/BatchSize]->seed[uj % BatchSize];
					w[x] = wj;
					correction ^= uj & 1;
				}
				*data ^= batch_sender_acc_left<DEFAULT_EXPAND_SIZE>(seed, w);
			}
			for (y = y * DEFAULT_EXPAND_SIZE; y < ell; y++) {
				int uj = J[y] >> (tree_height - 1), wj = J[y] & leave_mask;
				block tmp;
				senders[uj/BatchSize]->acc_left(tmp, uj % BatchSize, wj);
				*data ^= tmp;
				correction ^= uj & 1;
			}
			if (correction)
				*data ^= Delta_f2k;
		}
		else {
			for (int x = 0; x < ell; x++) {
				int uj = J[x] >> (tree_height - 1), wj = J[x] & leave_mask;
				*data ^= recvers[uj/BatchSize]->acc_left(uj % BatchSize, wj);
			}
		}
		acc_time_log("eval");
		*data &= minustwo;
		acc_time_log("choice");
		if (party == BOB) {
			bool choice = false;
			for (int x = 0; x < ell; x++) {
				int uj = J[x] >> (tree_height - 1), wj = J[x] & leave_mask;
				choice ^= ((uj & 1) ^ (wj >= recvers[uj/BatchSize]->choice_pos[uj%BatchSize]));
			}
			if (choice)
				*data ^= one; 
		}
		acc_time_log("choice");
		delete ((block*)J);
	}
	
	void exec_eval_batch(block* data, int cnt_start) {
		block J_blocks[64];
		acc_time_log("sample");
		uint32_t* J;
		sample_J_batch((uint32_t*)J_blocks, cnt_start);
		J = (uint32_t*)(&J_blocks[0]);
		acc_time_log("sample");
		int leave_mask = (1 << (tree_height - 1)) - 1;
		memset(data, 0, BatchSize*sizeof(block));
		acc_time_log("eval");
		int stride = (ell + 3) / 4 * 4;
		if (party == ALICE) {
			/* Batch impl. */
			block seed[BatchSize];
			uint32_t w[BatchSize];
			bool correction[BatchSize];
			memset(correction, 0, BatchSize);
			uint32_t* J_first = J;
			for (int i = 0; i < ell; i++) {
				for (int k = 0; k < BatchSize; k++) {
					int uj = J[k*stride + i] >> (tree_height - 1), wj = J[k*stride + i] & leave_mask;
					seed[k] = senders[uj/BatchSize]->seed[uj%BatchSize];
					w[k] = wj;
					correction[k] ^= uj & 1;
				}
				batch_sender_acc_left<BatchSize>(data, seed, w, senders[0]->ccrh);
			}
			for (int k = 0; k < BatchSize; k++) {
				if (correction[k])
					data[k] ^= Delta_f2k;
			}
			J = J_first;
		}
		else {
			for (int x = 0; x < BatchSize; x++) {
				for (int y = 0; y < ell; y++) {
					int uj = J[x*stride + y] >> (tree_height - 1), wj = J[x*stride + y] & leave_mask;
					data[x] ^= recvers[uj/BatchSize]->acc_left(uj % BatchSize, wj);
				}
			}
		}
		acc_time_log("eval");
		for (int x = 0; x < BatchSize; x++)
			data[x] &= minustwo;
		acc_time_log("choice");
		if (party == BOB) {
			for (int x = 0; x < BatchSize; x++) {
				bool choice = false;
				for (int y = 0; y < ell; y++) {
					int uj = J[x*stride + y] >> (tree_height - 1), wj = J[x*stride + y] & leave_mask;
					choice ^= ((uj & 1) ^ (wj >= recvers[uj/BatchSize]->choice_pos[uj%BatchSize]));
				}
				if (choice)
					data[x] ^= one; 
			}
		}
		acc_time_log("choice");
		// delete ((block*)J);
	}

	void __eval4(block* data, int i) {
		int leave_mask = (1 << (tree_height - 1)) - 1;
		constexpr int d = 10; // [TODO] This is just copied from Ferret, not correct for Dory.
		acc_time_log("sample");
		constexpr int nblks = d * EVAL_SIZE / 4;
		block tmp[nblks];
		for(int m = 0; m < nblks; ++m)
			tmp[m] = makeBlock(cnt+i, m);
		prp.permute_block(tmp, nblks);
		acc_time_log("sample");
		uint32_t* r = (uint32_t*)(tmp);
		block ch[2] = {zero_block, Delta_f2k};
		acc_time_log("eval");
		memset(data+i, 0, EVAL_SIZE*sizeof(block));
		if (party == ALICE) {
			block seed[EVAL_SIZE];
			uint32_t w[EVAL_SIZE];
			bool correction[EVAL_SIZE];
			memset(correction, 0, EVAL_SIZE);
			for (int y = 0; y < d; y++) {
				for (int m = 0; m < EVAL_SIZE; m++) {
					int index = *r & mask;
					index = index >= idx_max? index-idx_max : index;
					int uj = index >> (tree_height - 1), wj = index & leave_mask;
					++r;
					int batch_tree_idx = uj/BatchSize, internal_tree_idx = uj % BatchSize;
					seed[m] = senders[batch_tree_idx]->seed[internal_tree_idx];
					w[m] = wj;
					correction[m] ^= uj & 1;
				}
				batch_sender_acc_left<EVAL_SIZE>(data + i, seed, w);
			}
			for (int m = 0; m < EVAL_SIZE; m++) {
				data[i+m] ^= ch[correction[m]];
			}
		}
		else {
			uint32_t choice[EVAL_SIZE];
			uint32_t w[EVAL_SIZE];
			block* path_sum = new block[tree_height*EVAL_SIZE];
			for (int y = 0; y < d; y++) {
				for (int m = 0; m < EVAL_SIZE; m++) {
					int index = *r & mask;
					index = index >= idx_max? index-idx_max : index;
					int uj = index >> (tree_height - 1), wj = index & leave_mask;
					++r;
					int batch_tree_idx = uj/BatchSize, internal_tree_idx = uj % BatchSize;
					// data[i+m] ^= recvers[batch_tree_idx]->acc_left(internal_tree_idx, wj);

					choice[m] = recvers[batch_tree_idx]->choice_pos[internal_tree_idx];
					w[m] = wj;
					for(int i = 0; i < tree_height; i++)
						path_sum[i*EVAL_SIZE + m] = recvers[batch_tree_idx]->path_sum[i*BatchSize + internal_tree_idx];
				}
				batch_recver_acc_left<EVAL_SIZE>(data + i, path_sum, choice, w);
			}
			delete[] path_sum;
		}
		acc_time_log("eval");
		for (int x = 0; x < EVAL_SIZE; x++)
			data[i+x] &= minustwo;
		acc_time_log("choice");
		if (party == BOB) {
			r = (uint32_t*)(tmp);
			bool choices[EVAL_SIZE];
			memset(choices, 0, EVAL_SIZE);
			for (int y = 0; y < d; y++) {
				for (int m = 0; m < EVAL_SIZE; m++) {
					int index = *r & mask;
					index = index >= idx_max? index-idx_max : index;
					int uj = index >> (tree_height - 1), wj = index & leave_mask;
					++r;
					int batch_tree_idx = uj/BatchSize, internal_tree_idx = uj % BatchSize;
					choices[m] ^= ((uj & 1) ^ (wj >= recvers[batch_tree_idx]->choice_pos[internal_tree_idx]));
				}
			}
			for (int m = 0; m < EVAL_SIZE; m++) {
				if (choices[m])
					data[i+m] ^= one;
			}
		}
		acc_time_log("choice");
	}

	void exec_eval__(block* data, int cnt_start, int cnt_end) {
		acc_time_log("sample");
		uint32_t* J;
		sample_J(&J, ell, cnt_start, cnt_end);
		acc_time_log("sample");
		int length = cnt_end - cnt_start;
		int leave_mask = (1 << (tree_height - 1)) - 1;
		memset(data, 0, length*sizeof(block));
		acc_time_log("eval");
		int stride = (ell + 3) / 4 * 4;
		if (party == ALICE) {
			/* Batch impl. */
			block seed[BatchSize];
			uint32_t w[BatchSize];
			for (int i = 0; i < length; i++) {
				int y;
				bool correction = false;
				for (y = 0; y < ell/BatchSize; y++) {
					for (int x = 0; x < BatchSize; x++) {
						int uj = J[y*BatchSize + x] >> (tree_height - 1), wj = J[y*BatchSize + x] & leave_mask;
						seed[x] = senders[uj/BatchSize]->seed[uj % BatchSize];
						w[x] = wj;
						correction ^= uj & 1;
					}
					data[i] ^= batch_sender_acc_left<BatchSize>(seed, w, senders[0]->ccrh);
				}
				for (y = y * BatchSize; y < ell; y++) {
					int uj = J[y] >> (tree_height - 1), wj = J[y] & leave_mask;
					block tmp;
					senders[uj/BatchSize]->acc_left(tmp, uj % BatchSize, wj);
					data[i] ^= tmp;
					correction ^= uj & 1;
				}
				if (correction)
					data[i] ^= Delta_f2k;
			}
		}
		else {
			for (int x = 0; x < length; x++) {
				for (int y = 0; y < ell; y++) {
					int uj = J[x*stride + y] >> (tree_height - 1), wj = J[x*stride + y] & leave_mask;
					block tmp;
					recvers[uj/BatchSize]->acc_left(tmp, uj % BatchSize, wj);
					data[x] ^= tmp;
				}
			}
		}
		acc_time_log("eval");
		for (int x = 0; x < length; x++)
			data[x] &= minustwo;
		acc_time_log("choice");
		if (party == BOB) {
			for (int x = 0; x < length; x++) {
				bool choice = false;
				for (int y = 0; y < ell; y++) {
					int uj = J[x*stride + y] >> (tree_height - 1), wj = J[x*stride + y] & leave_mask;
					choice ^= ((uj & 1) ^ (wj >= recvers[uj/BatchSize]->choice_pos[uj%BatchSize]));
				}
				if (choice)
					data[x] ^= one; 
			}
		}
		acc_time_log("choice");
		delete ((block*)J);
	}

	void exec_eval_(block* data, int cnt_start, int cnt_end) {
		acc_time_log("sample");
		uint32_t* J;
		sample_J(&J, ell, cnt_start, cnt_end);
		acc_time_log("sample");
		int length = cnt_end - cnt_start;
		int leave_mask = (1 << (tree_height - 1)) - 1;
		memset(data, 0, length*sizeof(block));
		acc_time_log("eval");
		int stride = (ell + 3) / 4 * 4;
		if (party == ALICE) {
			
			acc_time_log("1st loop");
			acc_time_log("summary");
			vector<size_t> sizes(batch_tree_n, 0);
			for (int x = 0; x < length * stride; x++) {
				int uj = J[x] >> (tree_height - 1);
				sizes[uj / BatchSize]++;
			}
			acc_time_log("summary");
			std::vector<std::vector<uint64_t>> lists(batch_tree_n);
			for (int i = 0; i < batch_tree_n; i++)
				lists[i].reserve(sizes[i]);

			block ch[2] = {zero_block, Delta_f2k};
			block* data_first = data;
			uint32_t* J_first = J;
			for (int x = 0; x < length; x++) {
				bool correction = false;
				for (int y = 0; y < ell; y++, J++) {
					int uj = *J >> (tree_height - 1), wj = *J & leave_mask;
					lists[uj/BatchSize].push_back((((uint64_t)x) << 32) | (wj * BatchSize + uj % BatchSize));
					correction ^= uj & 1;
				}
				J += stride - ell;
				*data ^= ch[correction];
				data++;
			}
			J = J_first;
			data = data_first;
			acc_time_log("1st loop");
			block *buf = new block[senders[0]->leave_n * BatchSize];
			for (int i = 0; i < batch_tree_n; i++) {
				acc_time_log("acc expand");
				if (lists[i].size() == 0) continue;
				senders[i]->ggm_tree_gen(buf);
				acc_time_log("acc expand");
				acc_time_log("2nd loop");
				for (std::vector<uint64_t>::iterator it = lists[i].begin(); it != lists[i].end(); ++it) {
					int x = *it >> 32;
					uint32_t j = *it & 0xFFFFFFFFUL;
					data[x] ^= buf[j];
				}
				acc_time_log("2nd loop");
			}

			delete[] buf;
		}
		else {
			for (int x = 0; x < length; x++) {
				for (int y = 0; y < ell; y++) {
					int uj = J[x*stride + y] >> (tree_height - 1), wj = J[x*stride + y] & leave_mask;
					block tmp;
					recvers[uj/BatchSize]->acc_left(tmp, uj % BatchSize, wj);
					data[x] ^= tmp;
				}
			}
		}
		acc_time_log("eval");
		for (int x = 0; x < length; x++)
			data[x] &= minustwo;
		acc_time_log("choice");
		if (party == BOB) {
			for (int x = 0; x < length; x++) {
				bool choice = false;
				for (int y = 0; y < ell; y++) {
					int uj = J[x*stride + y] >> (tree_height - 1), wj = J[x*stride + y] & leave_mask;
					choice ^= ((uj & 1) ^ (wj >= recvers[uj/BatchSize]->choice_pos[uj%BatchSize]));
				}
				if (choice)
					data[x] ^= one; 
			}
		}
		acc_time_log("choice");
		delete ((block*)J);
	}

	void __compute4(block* data, block* buf, int i) {
		int leave_mask = (1 << (tree_height - 1)) - 1;
		int batch_tree_space = senders[0]->leave_n * BatchSize;
		constexpr int d = 10; // [TODO] This is just copied from Ferret, not correct for Dory.
		block tmp[d];
		for(int m = 0; m < d; ++m)
			tmp[m] = makeBlock(i, m);
		prp.permute_block(tmp, d);
		uint32_t* r = (uint32_t*)(tmp);
		block ch[2] = {zero_block, Delta_f2k};
		for (int m = 0; m < 4; m++) {
			bool correction = false;
			for (int y = 0; y < d; y++) {
				int index = *r & mask;
				index = index >= idx_max? index-idx_max : index;
				int uj = index >> (tree_height - 1), wj = index & leave_mask;
				++r;
				int batch_tree_idx = uj/BatchSize, leave_idx = wj * BatchSize + uj % BatchSize;
				data[i + m] ^= buf[batch_tree_idx * batch_tree_space + leave_idx];
				correction ^= uj & 1;
			}
			data[i + m] ^= ch[correction];
		}
	}

	void exec_eval_with_space(block* data, int cnt_start, int cnt_end) {
		acc_time_log("sample");
		uint32_t* J;
		sample_J(&J, ell, cnt_start, cnt_end);
		acc_time_log("sample");
		int length = cnt_end - cnt_start;
		int leave_mask = (1 << (tree_height - 1)) - 1;
		memset(data, 0, length*sizeof(block));
		acc_time_log("eval");
		int stride = (ell + 3) / 4 * 4;
		if (party == ALICE) {
			block ch[2] = {zero_block, Delta_f2k};
			int batch_tree_space = senders[0]->leave_n * BatchSize;
			block *buf = new block[batch_tree_space * batch_tree_n];
			acc_time_log("acc expand");
			for (int i = 0; i < batch_tree_n; i++) {
				senders[i]->ggm_tree_gen(buf + i * batch_tree_space);
			}
			acc_time_log("acc expand");
			acc_time_log("compute data");
			// for (int x = 0; x < length; x++) {
			// 	bool correction = false;
			// 	for (int y = 0; y < ell; y++) {
			// 		int uj = J[x * stride + y] >> (tree_height - 1), wj = J[x * stride + y] & leave_mask;
			// 		int batch_tree_idx = uj/BatchSize, leave_idx = wj * BatchSize + uj % BatchSize;
			// 		data[x] ^= buf[batch_tree_idx * batch_tree_space + leave_idx];
			// 		correction ^= uj & 1;
			// 	}
			// 	data[x] ^= ch[correction];
			// }
			for (int x = 0; x < length-4; x+=4) {
				__compute4(data, buf, x);
			}
			acc_time_log("compute data");

			delete[] buf;
		}
		else {
			for (int x = 0; x < length; x++) {
				for (int y = 0; y < ell; y++) {
					int uj = J[x*stride + y] >> (tree_height - 1), wj = J[x*stride + y] & leave_mask;
					block tmp;
					recvers[uj/BatchSize]->acc_left(tmp, uj % BatchSize, wj);
					data[x] ^= tmp;
				}
			}
		}
		acc_time_log("eval");
		for (int x = 0; x < length; x++)
			data[x] &= minustwo;
		acc_time_log("choice");
		if (party == BOB) {
			for (int x = 0; x < length; x++) {
				bool choice = false;
				for (int y = 0; y < ell; y++) {
					int uj = J[x*stride + y] >> (tree_height - 1), wj = J[x*stride + y] & leave_mask;
					choice ^= ((uj & 1) ^ (wj >= recvers[uj/BatchSize]->choice_pos[uj%BatchSize]));
				}
				if (choice)
					data[x] ^= one; 
			}
		}
		acc_time_log("choice");
		delete ((block*)J);
	}


	// compute sum of all leaves with index <= w
	template<int S>
	block batch_sender_acc_left(const block* seed, const uint32_t* w) {
		// block acc = zero_block;
		// block s[2 * BatchSize], to_expand[BatchSize];
		// for(size_t i = 0; i < BatchSize; i++) {
		// 	s[i] = seed[i];
		// 	s[BatchSize + i] = Delta_f2k ^ seed[i];
		// }
		// acc_time_log("batch_node_expand");
		// for (int i = tree_height - 2; i >= 0; i--) {
		// 	if (i==tree_height-2) acc_time_log("loop");
		// 	for (int j = 0; j < BatchSize; j++) {
		// 		if ((w[j] >> i) & 1) {
		// 			acc ^= s[j];
		// 			to_expand[j] = s[BatchSize + j];
		// 		}
		// 		else {
		// 			to_expand[j] = s[j];
		// 		}
		// 	}
		// 	if (i==tree_height-2) acc_time_log("loop");
		// 	if (i == 0) break; // don't expand beyond the last layer
		// 	if (i==tree_height-2) acc_time_log("exact");
		// 	ccrh->batch_node_expand(&s[0], &s[BatchSize], to_expand);
		// 	if (i==tree_height-2) acc_time_log("exact");
		// }
		// acc_time_log("batch_node_expand");
		// for (size_t i = 0; i < BatchSize; i++)
		// 	acc ^= s[(w[i] & 1) * BatchSize + i];
		// return acc;
		block acc[S];
		memset(acc, 0, S*sizeof(block));
		batch_sender_acc_left<S>(acc, seed, w);
		for (int i = 1; i < S; i++)
			acc[i] ^= acc[i-1];
		return acc[S - 1];
	}

	// // compute sum of all leaves with index <= w
	// void batch_sender_acc_left(block* acc, const block* seed, const uint32_t* w) {
	// 	block s[2 * DEFAULT_EXPAND_SIZE], to_expand[DEFAULT_EXPAND_SIZE];
	// 	for(size_t i = 0; i < DEFAULT_EXPAND_SIZE; i++) {
	// 		s[i] = seed[i];
	// 		s[DEFAULT_EXPAND_SIZE + i] = Delta_f2k ^ seed[i];
	// 	}
	// 	// acc_time_log("batch_node_expand");
	// 	for (int i = tree_height - 2; i >= 0; i--) {
	// 		// if (i==tree_height-2) acc_time_log("loop");
	// 		for (int j = 0; j < DEFAULT_EXPAND_SIZE; j++) {
	// 			if ((w[j] >> i) & 1) {
	// 				acc[j] ^= s[j];
	// 				to_expand[j] = s[DEFAULT_EXPAND_SIZE + j];
	// 			}
	// 			else {
	// 				to_expand[j] = s[j];
	// 			}
	// 		}
	// 		// if (i==tree_height-2) acc_time_log("loop");
	// 		if (i == 0) break; // don't expand beyond the last layer
	// 		// if (i==tree_height-2) acc_time_log("exact");
	// 		ccrh->batch_node_expand<DEFAULT_EXPAND_SIZE>(&s[0], &s[DEFAULT_EXPAND_SIZE], to_expand);
	// 		// if (i==tree_height-2) acc_time_log("exact");
	// 	}
	// 	// acc_time_log("batch_node_expand");
	// 	for (size_t i = 0; i < DEFAULT_EXPAND_SIZE; i++) {
	// 		acc[i] ^= s[(w[i] & 1) * DEFAULT_EXPAND_SIZE + i];
	// 	}
	// }

	// compute sum of all leaves with index <= w
	template<int S>
	void batch_sender_acc_left(block* acc, const block* seed, const uint32_t* w) {
		block s[2 * S], to_expand[S];
		for(size_t i = 0; i < S; i++) {
			s[i] = seed[i];
			s[S + i] = Delta_f2k ^ seed[i];
		}
		// acc_time_log("batch_node_expand");
		for (int i = tree_height - 2; i >= 0; i--) {
			// if (i==tree_height-2) acc_time_log("loop");
			for (int j = 0; j < S; j++) {
				if ((w[j] >> i) & 1) {
					acc[j] ^= s[j];
					to_expand[j] = s[S + j];
				}
				else {
					to_expand[j] = s[j];
				}
			}
			// if (i==tree_height-2) acc_time_log("loop");
			if (i == 0) break; // don't expand beyond the last layer
			// if (i==tree_height-2) acc_time_log("exact");
			ccrh->batch_node_expand<S>(&s[0], &s[S], to_expand);
			// if (i==tree_height-2) acc_time_log("exact");
		}
		// acc_time_log("batch_node_expand");
		for (size_t i = 0; i < S; i++) {
			acc[i] ^= s[(w[i] & 1) * S + i];
		}
	}

	// compute sum of all leaves with index <= w for tree `tree_idx`
	template<int S>
	void batch_recver_acc_left(block* acc, const block* path_sum, const uint32_t* choice_pos, const uint32_t* w) {
		bool direction[S];
		for(int i = 0; i < S; i++)
			direction[i] = w[i] <= choice_pos[i];

		uint32_t diff[S];
		uint32_t min_i = tree_height - 1;
		for(int j = 0; j < S; j++) {
			diff[j] = tree_height - 1;
			for (int i = 0; i < tree_height - 1; i++) {
				if (((w[j] >> (tree_height - 2 - i)) & 1) != ((choice_pos[j] >> (tree_height - 2 - i)) & 1)) {
					diff[j] = i; // find the first difference
					min_i = std::min(min_i, (uint32_t)i);
					break;
				}
				if (((w[j] >> (tree_height - 2 - i)) & 1) == direction[j]) {
					acc[j] ^= path_sum[i*S + j];
				}
			}
		}

		block s[2 * S];
		block to_expand[S];
		for (int i = 0; i < S; i++) {
			if (diff[i] < tree_height - 2)
				to_expand[i] = path_sum[diff[i]*S + i];
			else if ((diff[i] == tree_height - 2) && direction[i])
				acc[i] ^= path_sum[diff[i]*S + i];
			else if (direction[i])
				acc[i] ^= path_sum[(tree_height-1)*S + i];
		}
		for (int i = min_i + 1; i < tree_height - 1; i++) {
			ccrh->batch_node_expand<S>(&s[0], &s[S], to_expand);
			for (int j = 0; j < S; j++) {
				if (diff[j] < i) {
					if (((w[j] >> (tree_height - 2 - i)) & 1) == direction[j]) {
						acc[j] ^= s[(1-direction[j]) * S + j];
						to_expand[j] = s[direction[j] * S + j];
					}
					else {
						to_expand[j] = s[(1-direction[j]) * S + j];
					}
				}
			}
		}
		for (int i = 0; i < S; i++) {
			if (direction[i] && diff[i] < tree_height - 2)
				acc[i] ^= s[(w[i] & 1) * S + i];
		}
	}



	// f2k consistency check
	void consistency_check_f2k(block *pre_cot_data, int num) {
		// if(this->party == ALICE) {
		// 	block r1, r2;
		// 	vector_self_xor(&r1, this->consist_check_VW, num);
		// 	bool x_prime[128];
		// 	this->netio->recv_data(x_prime, 128*sizeof(bool));
		// 	for(int i = 0; i < 128; ++i) {
		// 		if(x_prime[i])
		// 			pre_cot_data[i] = pre_cot_data[i] ^ this->Delta_f2k;
		// 	}
		// 	pack.packing(&r2, pre_cot_data);
		// 	r1 = r1 ^ r2;
		// 	block dig[2];
		// 	Hash hash;
		// 	hash.hash_once(dig, &r1, sizeof(block));
		// 	this->netio->send_data(dig, 2*sizeof(block));
		// 	this->netio->flush();
		// } else {
		// 	block r1, r2, r3;
		// 	vector_self_xor(&r1, this->consist_check_VW, num);
		// 	vector_self_xor(&r2, this->consist_check_chi_alpha, num);
		// 	uint64_t pos[2];
		// 	pos[0] = _mm_extract_epi64(r2, 0);
		// 	pos[1] = _mm_extract_epi64(r2, 1);
		// 	bool pre_cot_bool[128];
		// 	for(int i = 0; i < 2; ++i) {
		// 		for(int j = 0; j < 64; ++j) {
		// 			pre_cot_bool[i*64+j] = ((pos[i] & 1) == 1) ^ getLSB(pre_cot_data[i*64+j]);
		// 			pos[i] >>= 1;
		// 		}
		// 	}
		// 	this->netio->send_data(pre_cot_bool, 128*sizeof(bool));
		// 	this->netio->flush();
		// 	pack.packing(&r3, pre_cot_data);
		// 	r1 = r1 ^ r3;
		// 	block dig[2];
		// 	Hash hash;
		// 	hash.hash_once(dig, &r1, sizeof(block));
		// 	block recv[2];
		// 	this->netio->recv_data(recv, 2*sizeof(block));
		// 	if(!cmpBlock(dig, recv, 2))
		// 		std::cout << "SPCOT consistency check fails" << std::endl;
		// }
	}
};
#endif
