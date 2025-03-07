#ifndef STREAM_COT_REG_H__
#define STREAM_COT_REG_H__

#include <emp-tool/emp-tool.h>
#include <set>
#include "emp-ot/dory/cggm_sender.h"
#include "emp-ot/dory/cggm_recver.h"
#include "emp-ot/dory/preot.h"
#include "emp-ot/dory/performance.h"

using namespace emp;
using std::future;

template<typename IO, int BatchSize>
class StreamCotReg {
public:
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
	int ell = 32;
	uint32_t upper_bound;
	uint32_t cnt;
	PRP prp;
	block minustwo, one;

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
	}

	~StreamCotReg() {
		for (auto p : senders) delete p;
		for (auto p : recvers) delete p;
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
		if(party == BOB) consist_check_chi_alpha = new block[item_n];
		consist_check_VW = new block[item_n];

		if(party == ALICE) {
			mpcot_init_sender(senders, ot);
			exec_parallel_sender(senders, ot);
		} else {
			mpcot_init_recver(recvers, ot);
			exec_parallel_recver(recvers, ot);
		}

		if(is_malicious)
			consistency_check_f2k(pre_cot_data, tree_n);

		if(party == BOB) delete[] consist_check_chi_alpha;
		delete[] consist_check_VW;

		cnt = 0;
	}

	void mpcot_init_sender(vector<CGGM_Sender<IO, BatchSize>*> &senders, OTPre<IO> *ot) {
		for(int i = 0; i < batch_tree_n; ++i) {
			senders.push_back(new CGGM_Sender<IO, BatchSize>(netio, tree_height));
			ot->choices_sender();
		}
		netio->flush();
		ot->reset();
	}

	void mpcot_init_recver(vector<CGGM_Recver<IO, BatchSize>*> &recvers, OTPre<IO> *ot) {
		for(int i = 0; i < batch_tree_n; ++i) {
			recvers.push_back(new CGGM_Recver<IO, BatchSize>(netio, tree_height));
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
		acc_time_log("sender compute");
		sender->compute(Delta_f2k);
		acc_time_log("sender compute");
		sender->template send_f2k<OTPre<IO>>(ot, io, i);
		io->flush();
		if(is_malicious)
			sender->consistency_check_msg_gen(consist_check_VW+i);
	}

	void exec_f2k_recver(CGGM_Recver<IO, BatchSize> *recver, OTPre<IO> *ot, IO *io, int i) {
		recver->template recv_f2k<OTPre<IO>>(ot, io, i);
		acc_time_log("recver compute");
		recver->compute();
		acc_time_log("recver compute");
		if(is_malicious) 
			recver->consistency_check_msg_gen(consist_check_chi_alpha+i, consist_check_VW+i);
	}

	inline void sample_J(uint32_t** J, int ell, int idx) {
		int n_blocks = (ell + 3) / 4;
		block* tmp = new block[n_blocks];
		for(int m = 0; m < n_blocks; ++m)
			tmp[m] = makeBlock(cnt, m);
		AES_ecb_encrypt_blks(tmp, n_blocks, &prp.aes);
		*J = (uint32_t*)(tmp);
		for (int i = 0; i < ell; i++) {
			(*J)[i] &= mask;
			(*J)[i] = (*J)[i] >= idx_max? (*J)[i]-idx_max : (*J)[i];
		}
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
		block* pt = data + start;
		for (int i = start; i < end; i++) {
			exec_eval(pt, i);
			pt++;
		}
	}

	void exec_eval(block* data, int idx) {
		uint32_t* J;
		sample_J(&J, ell, idx);
		int leave_mask = (1 << (tree_height - 1)) - 1;
		*data = zero_block;
		for (int x = 0; x < ell; x++) {
			int uj = J[x] >> (tree_height - 1), wj = J[x] & leave_mask;
			for (int i = 0; i < tree_n; i++) {
				block tmp;
				exec_eval(tmp, i, uj, wj);
				*data ^= tmp;
			}
		}
		*data &= minustwo;
		if (party == BOB) {
			bool choice = false;
			for (int x = 0; x < ell; x++) {
				for (int i = 0; i < tree_n; i++) {
					choice ^= (J[x] >= (i * leave_n + recvers[i/BatchSize]->choice_pos[i%BatchSize]));
				}
			}
			if (choice)
				*data ^= one; 
		}
		delete ((block*)J);
	}

	void exec_eval(block& tmp, int i, int uj, uint32_t wj) {
		if (party == ALICE) {
			if (uj < i)
				tmp = zero_block;
			else if (uj > i) {
				tmp = Delta_f2k;
			}
			else 
				senders[i/BatchSize]->acc_left(tmp, i % BatchSize, wj);
		}
		else {
			if (uj < i || uj > i)
				tmp = zero_block;
			else {
				recvers[i/BatchSize]->acc_left(tmp, i % BatchSize, wj);
			}
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
