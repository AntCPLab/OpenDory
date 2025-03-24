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

#define __AVX512F__

using namespace emp;
using std::future;

template<typename IO, int B>
class StreamCotReg {
public:
	constexpr static int EVAL_SIZE = 32;
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

	vector<CGGM_Sender<IO, B>*> senders;
	vector<CGGM_Recver<IO, B>*> recvers;
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
		this->batch_tree_n = (this->tree_n + B - 1) / B;

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
				senders.push_back(new CGGM_Sender<IO, B>(netio, tree_height));
			}
		}
		else {
			for(int i = 0; i < batch_tree_n; ++i) {
				recvers.push_back(new CGGM_Recver<IO, B>(netio, tree_height));
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
		item_pos_recver.resize(this->batch_tree_n * B);
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

	void mpcot_init_sender(vector<CGGM_Sender<IO, B>*> &senders, OTPre<IO> *ot) {
		for(int i = 0; i < batch_tree_n; ++i) {
			senders[i]->initialize();
			ot->choices_sender();
		}
		netio->flush();
		ot->reset();
	}

	void mpcot_init_recver(vector<CGGM_Recver<IO, B>*> &recvers, OTPre<IO> *ot) {
		for(int i = 0; i < batch_tree_n; ++i) {
			ot->choices_recver(recvers[i]->b);
			const uint32_t* idx = recvers[i]->get_index();
			for (int j = 0; j < B; j++)
				item_pos_recver[i*B + j] = idx[j];
		}
		netio->flush();
		ot->reset();
	}

	void exec_parallel_sender(vector<CGGM_Sender<IO, B>*> &senders, OTPre<IO> *ot) {
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

	void exec_parallel_recver(vector<CGGM_Recver<IO, B>*> &recvers, OTPre<IO> *ot) {
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

	void exec_f2k_sender(CGGM_Sender<IO, B> *sender, OTPre<IO> *ot, IO *io, int i) {
		sender->compute(Delta_f2k);
		sender->template send_f2k<OTPre<IO>>(ot, io, i);
		io->flush();
		if(is_malicious)
			sender->consistency_check_msg_gen(consist_check_VW+i);
	}

	void exec_f2k_recver(CGGM_Recver<IO, B> *recver, OTPre<IO> *ot, IO *io, int i) {
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
	// 	block* tmp = new block[n_blocks * B];
	// 	acc_time_log("sample 1st loop");
	// 	block* pt = tmp;
	// 	for (int i = start; i < start + B; i++) {
	// 		for(int m = 0; m < n_blocks; ++m, pt++)
	// 			*pt = makeBlock(i, m);
	// 	}
	// 	acc_time_log("sample 1st loop");
	// 	acc_time_log("sample enc");
	// 	prp.permute_block(tmp, B * n_blocks);
	// 	acc_time_log("sample enc");
	// 	*J = (uint32_t*)(tmp);
	// 	acc_time_log("sample 2nd loop");
	// 	for (int i = 0; i < B * n_blocks * 4; i++) {
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
		for (int i = start; i < start + B; i++) {
			for(int m = 0; m < n_blocks; ++m, pt++)
				*pt = makeBlock(i, m);
		}
		acc_time_log("sample 1st loop");
		acc_time_log("sample enc");
		prp.permute_block(tmp, B * n_blocks);
		acc_time_log("sample enc");
		acc_time_log("sample 2nd loop");
		for (int i = 0; i < B * n_blocks * 4; i++) {
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
		// for(int i = 0; i < length/B; ++i) {
		// 	exec_eval_batch(data, start + i*B);
		// 	data += B;
		// }
		// int remain = length % B;
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
			// 	senders[uj/B]->acc_left(tmp, uj % B, wj);
			// 	*data ^= tmp;
			// 	if (uj & 1)
			// 		*data ^= Delta_f2k;
			// }
			
			/* Batch impl. */
			int y;
			bool correction = false;
			block seed[EVAL_SIZE];
			uint32_t w[EVAL_SIZE];
			for (y = 0; y < ell/EVAL_SIZE; y++) {
				for (int x = 0; x < EVAL_SIZE; x++) {
					int uj = J[y*EVAL_SIZE + x] >> (tree_height - 1), wj = J[y*EVAL_SIZE + x] & leave_mask;
					seed[x] = senders[uj/B]->seed[uj % B];
					w[x] = wj;
					correction ^= uj & 1;
				}
				*data ^= batch_sender_acc_left<EVAL_SIZE>(seed, w);
			}
			for (y = y * EVAL_SIZE; y < ell; y++) {
				int uj = J[y] >> (tree_height - 1), wj = J[y] & leave_mask;
				block tmp;
				senders[uj/B]->acc_left(tmp, uj % B, wj);
				*data ^= tmp;
				correction ^= uj & 1;
			}
			if (correction)
				*data ^= Delta_f2k;
		}
		else {
			for (int x = 0; x < ell; x++) {
				int uj = J[x] >> (tree_height - 1), wj = J[x] & leave_mask;
				*data ^= recvers[uj/B]->acc_left(uj % B, wj);
			}
		}
		acc_time_log("eval");
		*data &= minustwo;
		acc_time_log("choice");
		if (party == BOB) {
			bool choice = false;
			for (int x = 0; x < ell; x++) {
				int uj = J[x] >> (tree_height - 1), wj = J[x] & leave_mask;
				choice ^= ((uj & 1) ^ (wj >= recvers[uj/B]->choice_pos[uj%B]));
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
		memset(data, 0, B*sizeof(block));
		acc_time_log("eval");
		int stride = (ell + 3) / 4 * 4;
		if (party == ALICE) {
			/* Batch impl. */
			block seed[B];
			uint32_t w[B];
			bool correction[B];
			memset(correction, 0, B);
			uint32_t* J_first = J;
			for (int i = 0; i < ell; i++) {
				for (int k = 0; k < B; k++) {
					int uj = J[k*stride + i] >> (tree_height - 1), wj = J[k*stride + i] & leave_mask;
					seed[k] = senders[uj/B]->seed[uj%B];
					w[k] = wj;
					correction[k] ^= uj & 1;
				}
				batch_sender_acc_left<B>(data, seed, w, senders[0]->ccrh);
			}
			for (int k = 0; k < B; k++) {
				if (correction[k])
					data[k] ^= Delta_f2k;
			}
			J = J_first;
		}
		else {
			for (int x = 0; x < B; x++) {
				for (int y = 0; y < ell; y++) {
					int uj = J[x*stride + y] >> (tree_height - 1), wj = J[x*stride + y] & leave_mask;
					data[x] ^= recvers[uj/B]->acc_left(uj % B, wj);
				}
			}
		}
		acc_time_log("eval");
		for (int x = 0; x < B; x++)
			data[x] &= minustwo;
		acc_time_log("choice");
		if (party == BOB) {
			for (int x = 0; x < B; x++) {
				bool choice = false;
				for (int y = 0; y < ell; y++) {
					int uj = J[x*stride + y] >> (tree_height - 1), wj = J[x*stride + y] & leave_mask;
					choice ^= ((uj & 1) ^ (wj >= recvers[uj/B]->choice_pos[uj%B]));
				}
				if (choice)
					data[x] ^= one; 
			}
		}
		acc_time_log("choice");
		// delete ((block*)J);
	}

	void __eval4(block* data, int i) {
		static int flag = 0;
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
					int batch_tree_idx = uj/B, internal_tree_idx = uj % B;
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
					int batch_tree_idx = uj/B, internal_tree_idx = uj % B;
					// data[i+m] ^= recvers[batch_tree_idx]->acc_left(internal_tree_idx, wj);

					choice[m] = recvers[batch_tree_idx]->choice_pos[internal_tree_idx];
					w[m] = wj;
					for(int i = 0; i < tree_height; i++)
						path_sum[i*EVAL_SIZE + m] = recvers[batch_tree_idx]->path_sum[i*B + internal_tree_idx];
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
					int batch_tree_idx = uj/B, internal_tree_idx = uj % B;
					choices[m] ^= ((uj & 1) ^ (wj >= recvers[batch_tree_idx]->choice_pos[internal_tree_idx]));
				}
			}
			for (int m = 0; m < EVAL_SIZE; m++) {
				if (choices[m])
					data[i+m] ^= one;
			}
		}
		acc_time_log("choice");
		flag++;
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
			block seed[B];
			uint32_t w[B];
			for (int i = 0; i < length; i++) {
				int y;
				bool correction = false;
				for (y = 0; y < ell/B; y++) {
					for (int x = 0; x < B; x++) {
						int uj = J[y*B + x] >> (tree_height - 1), wj = J[y*B + x] & leave_mask;
						seed[x] = senders[uj/B]->seed[uj % B];
						w[x] = wj;
						correction ^= uj & 1;
					}
					data[i] ^= batch_sender_acc_left<B>(seed, w, senders[0]->ccrh);
				}
				for (y = y * B; y < ell; y++) {
					int uj = J[y] >> (tree_height - 1), wj = J[y] & leave_mask;
					block tmp;
					senders[uj/B]->acc_left(tmp, uj % B, wj);
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
					recvers[uj/B]->acc_left(tmp, uj % B, wj);
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
					choice ^= ((uj & 1) ^ (wj >= recvers[uj/B]->choice_pos[uj%B]));
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
				sizes[uj / B]++;
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
					lists[uj/B].push_back((((uint64_t)x) << 32) | (wj * B + uj % B));
					correction ^= uj & 1;
				}
				J += stride - ell;
				*data ^= ch[correction];
				data++;
			}
			J = J_first;
			data = data_first;
			acc_time_log("1st loop");
			block *buf = new block[senders[0]->leave_n * B];
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
					recvers[uj/B]->acc_left(tmp, uj % B, wj);
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
					choice ^= ((uj & 1) ^ (wj >= recvers[uj/B]->choice_pos[uj%B]));
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
		int batch_tree_space = senders[0]->leave_n * B;
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
				int batch_tree_idx = uj/B, leave_idx = wj * B + uj % B;
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
			int batch_tree_space = senders[0]->leave_n * B;
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
			// 		int batch_tree_idx = uj/B, leave_idx = wj * B + uj % B;
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
					recvers[uj/B]->acc_left(tmp, uj % B, wj);
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
					choice ^= ((uj & 1) ^ (wj >= recvers[uj/B]->choice_pos[uj%B]));
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
		// block s[2 * B], to_expand[B];
		// for(size_t i = 0; i < B; i++) {
		// 	s[i] = seed[i];
		// 	s[B + i] = Delta_f2k ^ seed[i];
		// }
		// acc_time_log("batch_node_expand");
		// for (int i = tree_height - 2; i >= 0; i--) {
		// 	if (i==tree_height-2) acc_time_log("loop");
		// 	for (int j = 0; j < B; j++) {
		// 		if ((w[j] >> i) & 1) {
		// 			acc ^= s[j];
		// 			to_expand[j] = s[B + j];
		// 		}
		// 		else {
		// 			to_expand[j] = s[j];
		// 		}
		// 	}
		// 	if (i==tree_height-2) acc_time_log("loop");
		// 	if (i == 0) break; // don't expand beyond the last layer
		// 	if (i==tree_height-2) acc_time_log("exact");
		// 	ccrh->batch_node_expand(&s[0], &s[B], to_expand);
		// 	if (i==tree_height-2) acc_time_log("exact");
		// }
		// acc_time_log("batch_node_expand");
		// for (size_t i = 0; i < B; i++)
		// 	acc ^= s[(w[i] & 1) * B + i];
		// return acc;
		block acc[S];
		memset(acc, 0, S*sizeof(block));
		batch_sender_acc_left<S>(acc, seed, w);
		for (int i = 1; i < S; i++)
			acc[i] ^= acc[i-1];
		return acc[S - 1];
	}

	// compute sum of all leaves with index <= w
	template<int S>
	void batch_sender_acc_left(block* acc, const block* seed, const uint32_t* w) {
		static int flag = 0;
		alignas(64) block s[2 * S], to_expand[S];
		for(size_t i = 0; i < S; i++) {
			s[i] = seed[i];
			s[S + i] = Delta_f2k ^ seed[i];
		}
		if (flag < 1000000) acc_time_log("batch sender 3rd loop");
		for (int i = tree_height - 2; i >= 0; i--) {
#ifdef __AVX512F__
			for (int j = 0; j < S; j+=4) {
				// load w[j..j+3]
				__m128i w_pack = _mm_loadu_si128((__m128i*)&w[j]);
				__m128i shifted = _mm_and_si128(_mm_srli_epi32(w_pack, i), _mm_set1_epi32(1));
				__mmask8 conds = _mm_cmpeq_epi32_mask(shifted, _mm_set1_epi32(1));
				conds = double_mask(conds);

				__m512i s_low = _mm512_load_epi32((void const*)&s[j]);
				__m512i s_high = _mm512_load_epi32((void const*)&s[S+j]);
				__m512i expanded = _mm512_mask_blend_epi64(conds, s_low, s_high);
				_mm512_store_epi32((void*)&to_expand[j], expanded);

				__m512i acced = _mm512_mask_blend_epi64(conds, _mm512_setzero_si512(), s_low);
				__m512i cur = _mm512_loadu_epi32((void const*)&acc[j]);
				cur = _mm512_xor_si512(cur, acced);
				_mm512_storeu_epi32((void*)&acc[j], cur);

#else
			for (int j = 0; j < S; j++) {
				const uint32_t w_val = w[j];
				const int cond = (w_val >> i) & 1;
				const __m128i cond_mask = _mm_set1_epi32(-cond);

				// to_expand[j] = cond ? s[S + j] : s[j]
				const __m128i s_low = s[j];
				const __m128i s_high = s[S + j];
				to_expand[j] = _mm_blendv_epi8(s_low, s_high, cond_mask);

				// acc[j] ^= (cond ? s[j] : 0)
				const __m128i masked_s = _mm_and_si128(cond_mask, s[j]);
				acc[j] = _mm_xor_si128(acc[j], masked_s);
#endif
			}
			if (i == 0) break; // don't expand beyond the last layer
			ccrh->batch_node_expand<S>(&s[0], &s[S], to_expand);
		}
		if (flag < 1000000) acc_time_log("batch sender 3rd loop");
		for (size_t i = 0; i < S; i++) {
			acc[i] ^= s[(w[i] & 1) * S + i];
		}
		flag++;
	}

#ifdef __AVX512F__
	__mmask8 double_mask(__mmask8 mask) {
		uint8_t mask_bits = _cvtmask8_u32(mask);

		mask_bits = ((mask_bits & 0x01) * 0x03) |
						((mask_bits & 0x02) * 0x06) | 
						((mask_bits & 0x04) * 0x0C) |
						((mask_bits & 0x08) * 0x18);
		return _cvtu32_mask8(mask_bits);
	}

	// compute sum of all leaves with index <= w for tree `tree_idx`
	// template<int S>
	// void batch_recver_acc_left(block* acc, const block* path_sum, const uint32_t* choice_pos, const uint32_t* w) {
	// 	static int flag = 0;
	// 	alignas(16) uint32_t direction[S];
	// 	for(int i = 0; i < S; i++) {
	// 		direction[i] = w[i] <= choice_pos[i];
	// 	}

	// 	alignas(16) uint32_t diff[S];
	// 	uint32_t min_i = tree_height - 1;
	// 	// for(int j = 0; j < S; j++) {
	// 	// 	diff[j] = tree_height - 1;
	// 	// 	uint32_t tmp = w[j] ^ choice_pos[j];
	// 	// 	for (int i = 0; i < tree_height - 1; i++) {
	// 	// 		if ((tmp >> (tree_height - 2 - i)) & 1) {
	// 	// 			diff[j] = i; // find the first difference
	// 	// 			min_i = std::min(min_i, (uint32_t)i);
	// 	// 			break;
	// 	// 		}
	// 	// 		if (((w[j] >> (tree_height - 2 - i)) & 1) == direction[j]) {
	// 	// 			acc[j] ^= path_sum[i*S + j];
	// 	// 		}
	// 	// 	}
	// 	// }
	// 	if (flag < 1000000) acc_time_log("batch recver 1st loop");
	// 	// for(int j = 0; j < S; j++) {
	// 	// 	uint32_t tmp = w[j] ^ choice_pos[j];
	// 	// 	// find the first difference
	// 	// 	diff[j] = __builtin_clz(tmp) + tree_height - 33;
	// 	// 	min_i = std::min(min_i, diff[j]);
	// 	// 	for (int i = 0; i < diff[j]; i++) {
	// 	// 		if (((w[j] >> (tree_height - 2 - i)) & 1) == direction[j]) {
	// 	// 			acc[j] ^= path_sum[i*S + j];
	// 	// 		}
	// 	// 	}
	// 	// }
	// 	__m512i v_min = _mm512_set1_epi32(UINT32_MAX);
	// 	// This requires S to be a multiple of 16
	// 	for(int j = 0; j < S; j+=16) {
	// 		// find the first difference
	// 		__m512i w_pack = _mm512_loadu_epi32((void const*)&w[j]);
	// 		__m512i choice_pack = _mm512_loadu_epi32((void const*)&choice_pos[j]);
	// 		__m512i tmp = _mm512_xor_si512(w_pack, choice_pack);
	// 		__m512i diff_pack = _mm512_add_epi32(_mm512_lzcnt_epi32(tmp), _mm512_set1_epi32(tree_height-33));
	// 		_mm512_store_epi32((void*)&diff[j], diff_pack);
	// 		// minimum diff
	// 		v_min = _mm512_min_epu32(v_min, diff_pack);
	// 	}
	// 	min_i = _mm512_reduce_min_epu32(v_min);
	// 	// for (int i = 0; i < tree_height - 1; i++) {
	// 	// 	for (int j = 0; j < S; j+=4) {
	// 	// 		// load w[j..j+3]
	// 	// 		__m128i w_pack = _mm_loadu_si128((__m128i*)&w[j]);
	// 	// 		__m128i shifted = _mm_and_si128(_mm_srli_epi32(w_pack, tree_height-2-i), _mm_set1_epi32(1));
	// 	// 		__m128i dir_pack = _mm_load_si128((__m128i*)&direction[j]);
	// 	// 		__mmask8 conds = _mm_cmpeq_epi32_mask(shifted, dir_pack);
	// 	// 		conds = double_mask(conds);

	// 	// 		// load diff[j..j+3]
	// 	// 		__m128i diff_pack = _mm_load_si128((__m128i*)&diff[j]);
	// 	// 		__mmask8 diff_conds = _mm_cmp_epi32_mask(_mm_set1_epi32(i), diff_pack, 1);
	// 	// 		conds = _kand_mask8(conds, double_mask(diff_conds));

	// 	// 		__m512i ps_pack = _mm512_loadu_epi32((void const*)&path_sum[i*S + j]);
	// 	// 		__m512i acced = _mm512_mask_blend_epi64(conds, _mm512_setzero_si512(), ps_pack);
	// 	// 		__m512i cur = _mm512_loadu_epi32((void const*)&acc[j]);
	// 	// 		cur = _mm512_xor_si512(cur, acced);
	// 	// 		_mm512_storeu_epi32((void*)&acc[j], cur);
	// 	// 	}
	// 	// }
	// 	for(int j = 0; j < S; j++) {
	// 		for (int i = 0; i < diff[j]; i++) {
	// 			if (((w[j] >> (tree_height - 2 - i)) & 1) == direction[j]) {
	// 				acc[j] ^= path_sum[i*S + j];
	// 			}
	// 		}
	// 	}

	// 	if (flag < 1000000) acc_time_log("batch recver 1st loop");

	// 	alignas(64) block s[2 * S];
	// 	alignas(64) block to_expand[S];
	// 	if (flag < 1000000) acc_time_log("batch recver 2nd loop");
	// 	for (int i = 0; i < S; i++) {
	// 		if (diff[i] < tree_height - 2)
	// 			to_expand[i] = path_sum[diff[i]*S + i];
	// 		// else if ((diff[i] == tree_height - 2) && direction[i])
	// 		// 	acc[i] ^= path_sum[diff[i]*S + i];
	// 		// else if (direction[i])
	// 		// 	acc[i] ^= path_sum[(tree_height-1)*S + i];
	// 	}
	// 	if (flag < 1000000) acc_time_log("batch recver 2nd loop");
	// 	if (flag < 1000000) acc_time_log("batch recver 3rd loop");
	// 	for (int i = min_i + 1; i < tree_height - 1; i++) {
	// 		ccrh->batch_node_expand<S>(&s[0], &s[S], to_expand);
	// 		for (int j = 0; j < S; j+=4) {
	// 			// load diff[j..j+3]
	// 			__m128i diff_pack = _mm_load_si128((__m128i*)&diff[j]);
	// 			__mmask8 diff_conds = _mm_cmp_epi32_mask(diff_pack, _mm_set1_epi32(i), 1);
	// 			diff_conds = double_mask(diff_conds);

	// 			// load w[j..j+3]
	// 			__m128i w_pack = _mm_loadu_si128((__m128i*)&w[j]);
	// 			__m128i shifted = _mm_and_si128(_mm_srli_epi32(w_pack, tree_height-2-i), _mm_set1_epi32(1));
	// 			__mmask8 conds = _mm_cmpeq_epi32_mask(shifted, _mm_set1_epi32(1));
	// 			conds = double_mask(conds);

	// 			// to_expand[j] = cond ? s[S+j] : s[j]
	// 			__m512i s_low = _mm512_load_epi32((void const*)&s[j]);
	// 			__m512i s_high = _mm512_load_epi32((void const*)&s[S+j]);
	// 			__m512i expanded = _mm512_mask_blend_epi64(conds, s_low, s_high);
	// 			__m512i cur_expand = _mm512_load_epi32((void const*)&to_expand[j]);
	// 			expanded = _mm512_mask_blend_epi64(diff_conds, cur_expand, expanded);
	// 			_mm512_store_epi32((void*)&to_expand[j], expanded);

	// 			// acc[j] ^= (cond^direction) ? 0 : (cond ? s[j] : s[S+j])
	// 			__m512i s_tmp = _mm512_mask_blend_epi64(conds, s_high, s_low);
	// 			__m128i dir_pack = _mm_load_si128((__m128i*)&direction[j]);
	// 			conds = _kand_mask8(double_mask(_mm_cmpeq_epi32_mask(shifted, dir_pack)), diff_conds);
	// 			__m512i acced = _mm512_mask_blend_epi64(conds, _mm512_setzero_si512(), s_tmp);
	// 			__m512i cur = _mm512_loadu_epi32((void const*)&acc[j]);
	// 			cur = _mm512_xor_si512(cur, acced);
	// 			_mm512_storeu_epi32((void*)&acc[j], cur);
	// 		}
	// 	}
	// 	if (flag < 1000000) acc_time_log("batch recver 3rd loop");
	// 	if (flag < 1000000) acc_time_log("batch recver 4th loop");
	// 	for (int i = 0; i < S; i++) {
	// 		// if (direction[i] && diff[i] < tree_height - 2)
	// 		// 	acc[i] ^= s[(w[i] & 1) * S + i];
	// 		int d = __builtin_clz(w[i] ^ choice_pos[i]) + tree_height - 33;
	// 		if (direction[i] && d < tree_height - 2)
	// 			acc[i] ^= s[(w[i] & 1) * S + i];
	// 		if (direction[i] && d == tree_height - 2)
	// 			acc[i] ^= path_sum[(tree_height-2)*S + i];	
	// 		if (direction[i] && d == tree_height - 1)
	// 			acc[i] ^= path_sum[(tree_height-1)*S + i];
	// 	}
	// 	if (flag < 1000000) acc_time_log("batch recver 4th loop");
	// 	flag++;
	// }

	// compute sum of all leaves with index <= w for tree `tree_idx`
	template<int S>
	void batch_recver_acc_left(block* acc, const block* path_sum, const uint32_t* choice_pos, const uint32_t* w) {
		static int flag = 0;
		__mmask8 direction[S/4];
		for(int i = 0; i < S; i+=4) {
			__m128i w_pack = _mm_loadu_epi32((void const*)&w[i]);
			__m128i choice_pack = _mm_loadu_epi32((void const*)&choice_pos[i]);
			direction[i/4] = double_mask(_mm_cmple_epi32_mask(w_pack, choice_pack));
		}

		alignas(64) block s[2 * S];
		alignas(64) block to_expand[S];
		if (flag < 1000000) acc_time_log("batch recver 3rd loop");
		__mmask8 diff[S/4];
		memset(diff, 0, S/4 * sizeof(__mmask8));
		for (int i = 0; i < tree_height - 1; i++) {
			for (int j = 0; j < S; j+=4) {
				__m128i w_pack = _mm_loadu_epi32((void const*)&w[j]);
				__m128i choice_pack = _mm_loadu_epi32((void const*)&choice_pos[j]);
				__m128i tmp = _mm_xor_si128(w_pack, choice_pack);
				
				__mmask8 prev_diff_conds = diff[j/4];
				__mmask8 diff_conds = _kor_mask8(
					double_mask(_mm_test_epi32_mask(_mm_srli_epi32(tmp, tree_height-2-i), _mm_set1_epi32(1))), 
					prev_diff_conds);
				diff[j/4] = diff_conds;

				__m512i ps_pack = _mm512_loadu_epi32((void const*)&path_sum[i*S + j]);

				__mmask8 w_cond = double_mask(_mm_test_epi32_mask(_mm_srli_epi32(w_pack, tree_height-2-i), _mm_set1_epi32(1)));

				// to_expand[j] = cond ? s[S+j] : s[j]
				__m512i s_low = _mm512_load_epi32((void const*)&s[j]);
				__m512i s_high = _mm512_load_epi32((void const*)&s[S+j]);
				__m512i expanded = _mm512_mask_blend_epi64(w_cond, s_low, s_high);
				expanded = _mm512_mask_blend_epi64(prev_diff_conds, ps_pack, expanded);
				_mm512_store_epi32((void*)&to_expand[j], expanded);

				// acc[j] ^= (cond^direction) ? 0 : (cond ? s[j] : s[S+j])
				__m512i s_tmp = _mm512_mask_blend_epi64(w_cond, s_high, s_low);
				__mmask8 dir_conds = _kxor_mask8(w_cond, direction[j/4]);
				__m512i acced = _mm512_mask_blend_epi64(diff_conds, ps_pack, s_tmp);
				acced = _mm512_mask_blend_epi64(_kxor_mask8(prev_diff_conds, diff_conds), acced, _mm512_setzero_si512());
				acced = _mm512_mask_blend_epi64(dir_conds, acced, _mm512_setzero_si512());
				__m512i cur = _mm512_loadu_epi32((void const*)&acc[j]);
				cur = _mm512_xor_si512(cur, acced);
				_mm512_storeu_epi32((void*)&acc[j], cur);
			}
			if (i == tree_height - 2) break;
			ccrh->batch_node_expand<S>(&s[0], &s[S], to_expand);
		}
		if (flag < 1000000) acc_time_log("batch recver 3rd loop");
		if (flag < 1000000) acc_time_log("batch recver 4th loop");
		// for (int i = 0; i < S; i++) {
		// 	// // if (direction[i] && diff[i] < tree_height - 2)
		// 	// // 	acc[i] ^= s[(w[i] & 1) * S + i];
		// 	// int d = __builtin_clz(w[i] ^ choice_pos[i]) + tree_height - 33;
		// 	// // if (direction[i] && d <= tree_height - 2)
		// 	// // 	acc[i] ^= to_expand[i];
		// 	if (direction[i] && diff[i])
		// 		acc[i] ^= to_expand[i];
		// 	else if (direction[i])
		// 		acc[i] ^= path_sum[(tree_height-1)*S + i];
		// }
		for (int i = 0; i < S; i+=4) {
			__mmask8 diff_cond = diff[i/4];
			__mmask8 dir_cond = direction[i/4];
			
			__m512i ps_pack = _mm512_loadu_epi32((void const*)&path_sum[(tree_height-1)*S + i]);
			__m512i leaf_pack = _mm512_load_epi32((void const*)&to_expand[i]);

			__m512i acced = _mm512_mask_blend_epi64(diff_cond, ps_pack, leaf_pack);
			acced = _mm512_mask_blend_epi64(dir_cond, _mm512_setzero_si512(), acced);
			
			__m512i cur = _mm512_loadu_epi32((void const*)&acc[i]);
			cur = _mm512_xor_si512(cur, acced);
			_mm512_storeu_epi32((void*)&acc[i], cur);
		}
		if (flag < 1000000) acc_time_log("batch recver 4th loop");
		flag++;
	}

#else
	// compute sum of all leaves with index <= w for tree `tree_idx`
	template<int S>
	void batch_recver_acc_left(block* acc, const block* path_sum, const uint32_t* choice_pos, const uint32_t* w) {
		static int flag = 0;
		alignas(16) uint32_t direction[S];
		if (flag < 1000000) acc_time_log("batch init");
		for(int i = 0; i < S; i++)
			direction[i] = w[i] <= choice_pos[i];
		if (flag < 1000000) acc_time_log("batch init");

		alignas(16) uint32_t diff[S];
		uint32_t min_i = tree_height - 1;
		if (flag < 1000000) acc_time_log("batch 1st loop");
		for(int j = 0; j < S; j++) {
			diff[j] = tree_height - 1;
			uint32_t tmp = w[j] ^ choice_pos[j];
			for (int i = 0; i < tree_height - 1; i++) {
				if ((tmp >> (tree_height - 2 - i)) & 1) {
					diff[j] = i; // find the first difference
					min_i = std::min(min_i, (uint32_t)i);
					break;
				}
				if (((w[j] >> (tree_height - 2 - i)) & 1) == direction[j]) {
					acc[j] ^= path_sum[i*S + j];
				}
			}
		}
		if (flag < 1000000) acc_time_log("batch 1st loop");

		alignas(64) block s[2 * S];
		alignas(64) block to_expand[S];
		if (flag < 1000000) acc_time_log("batch 2nd loop");
		for (int i = 0; i < S; i++) {
			if (diff[i] < tree_height - 2)
				to_expand[i] = path_sum[diff[i]*S + i];
			else if ((diff[i] == tree_height - 2) && direction[i])
				acc[i] ^= path_sum[diff[i]*S + i];
			else if (direction[i])
				acc[i] ^= path_sum[(tree_height-1)*S + i];
		}
		if (flag < 1000000) acc_time_log("batch 2nd loop");
		if (flag < 1000000) acc_time_log("batch 3rd loop");
		for (int i = min_i + 1; i < tree_height - 1; i++) {
			ccrh->batch_node_expand<S>(&s[0], &s[S], to_expand);
			// for (int j = 0; j < S; j++) {
			// 	if (diff[j] < i) {
			// 		if (((w[j] >> (tree_height - 2 - i)) & 1) == direction[j]) {
			// 			acc[j] ^= s[(1-direction[j]) * S + j];
			// 			to_expand[j] = s[direction[j] * S + j];
			// 		}
			// 		else {
			// 			to_expand[j] = s[(1-direction[j]) * S + j];
			// 		}
			// 	}
			// }
			for (int j = 0; j < S; j++) {
				if (diff[j] < i) {
					const uint32_t w_val = w[j];
					const int cond = (w_val >> (tree_height - 2 - i)) & 1;
					const __m128i cond_mask = _mm_set1_epi32(-cond);

					// to_expand[j] = cond ? s[S+j] : s[j]
					const __m128i s_low = s[j];
					const __m128i s_high = s[S + j];
					to_expand[j] = _mm_blendv_epi8(s_low, s_high, cond_mask);

					// acc[j] ^= (cond^direction) ? 0 : (cond ? s[j] : s[S+j])
					const __m128i s_tmp = _mm_blendv_epi8(s_high, s_low, cond_mask);
					const int acc_cond = (cond ^ direction[j]) - 1;
					const __m128i acc_cond_mask = _mm_set1_epi32(acc_cond);
					const __m128i masked_s = _mm_and_si128(acc_cond_mask, s_tmp);
					acc[j] = _mm_xor_si128(acc[j], masked_s);
				}
			}
		}
		if (flag < 1000000) acc_time_log("batch 3rd loop");
		if (flag < 1000000) acc_time_log("batch end");
		for (int i = 0; i < S; i++) {
			if (direction[i] && diff[i] < tree_height - 2)
				acc[i] ^= s[(w[i] & 1) * S + i];
		}
		if (flag < 1000000) acc_time_log("batch end");
		flag++;
	}
#endif


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
