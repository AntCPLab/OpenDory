#ifndef STREAM_COT_REG_H__
#define STREAM_COT_REG_H__

#include <emp-tool/emp-tool.h>
#include <set>
#include "emp-ot/dory/cggm_sender.h"
#include "emp-ot/dory/cggm_recver.h"
#include "emp-ot/dory/preot.h"
#include "emp-ot/dory/dory_preot.h"
#include "emp-ot/dory/performance.h"
#include "emp-ot/dory/constants.h"
#include <list>
#include <utility>

using namespace emp;
using std::future;

template<typename IO, int B>
class StreamCotReg {
public:
	constexpr static int EVAL_SIZE = 32;
	constexpr static int ELL_BOUND = 16;
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
	// A cache for accumulated XOR of tree deltas: acc_delta[i] = delta[0] XOR ... XOR delta[i-1]
	block* acc_delta = nullptr;
	// A cache for accumulated XOR of tree delta choices: acc_delta_choice[i] = delta_choice[0] XOR ... XOR delta_choice[i-1]
	bool* acc_delta_choice = nullptr;
	int mask;
	int ell = -1;
	uint32_t upper_bound;
	uint32_t cnt;
	DoryPRP prp;
	block minustwo, one;

	DoryCCRH *ccrh;

	/**
	 * Stream COT with regular LPN noise assumption, the param `n`, `t`, and `log_bin_sz` are
	 * related as: `n = t * (2**log_bin_sz)`,
	 * meaning `t` calls to CGGM, each with a vector length of `2**log_bin_sz`.
	*/
	StreamCotReg(int party, int threads, const DualLPNParameter& param, ThreadPool * pool, IO **ios) {
		assert(param.ell < ELL_BOUND);
		this->party = party;
		this->threads = threads;
		netio = ios[0];
		this->ios = ios;
		consist_check_cot_num = 128;

		this->pool = pool;
		this->is_malicious = false;

		this->item_n = param.t;
		this->idx_max = param.n;
		this->tree_height = param.log_bin_sz+1;
		this->leave_n = 1<<(this->tree_height-1);
		this->tree_n = this->item_n;
		this->batch_tree_n = (this->tree_n + B - 1) / B;
		this->ell = param.ell;

		this->cnt = this->upper_bound = param.ot_limit();

		mask = 1;
		while(mask < param.n) {
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
		acc_delta = new block[param.t];
		acc_delta_choice = new bool[param.t+1];

		ccrh = new DoryCCRH(zero_block);
	}

	~StreamCotReg() {
		for (auto p : senders) delete p;
		for (auto p : recvers) delete p;
		delete[] acc_delta;
		delete[] acc_delta_choice;
		delete ccrh;
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

	/// @brief 
	/// @param ot The preprocessed OT used for GGM tree expansion
	/// @param pre_cot_data The OT data used for malicious check
	void bootstrap(OTPre<IO> * ot, block *pre_cot_data) {
		if(party == BOB) consist_check_chi_alpha = new block[batch_tree_n * B];
		consist_check_VW = new block[batch_tree_n * B];

		DoryOTPre<IO> dory_preot(ot);

		if(party == ALICE) {
			dory_preot.sender_refactor();
			mpcot_init_sender(senders, &dory_preot);
			exec_parallel_sender(senders, &dory_preot);
		} else {
			dory_preot.receiver_refactor();
			mpcot_init_recver(recvers, &dory_preot);
			exec_parallel_recver(recvers, &dory_preot);
		}
		memset(acc_delta, 0, tree_n * sizeof(block));
		for (int i = 1; i < tree_n; i++) {
			acc_delta[i] = acc_delta[i-1] ^ dory_preot.unit_offset(i-1);
		}
		if (party == BOB) {
			memset(acc_delta_choice, 0, (tree_n + 1) * sizeof(bool));
			for (int i = 1; i < tree_n + 1; i++) {
				acc_delta_choice[i] = acc_delta_choice[i-1] ^ dory_preot.unit_choice(i-1);
			}
		}

		if(is_malicious)
			consistency_check_f2k(pre_cot_data, tree_n);

		cnt = 0;

		if(party == BOB) delete[] consist_check_chi_alpha;
		delete[] consist_check_VW;
	}

	void mpcot_init_sender(vector<CGGM_Sender<IO, B>*> &senders, DoryOTPre<IO> *ot) {
		for(int i = 0; i < batch_tree_n; ++i) {
			senders[i]->initialize();
			ot->template choices_sender<B>();
		}
		netio->flush();
		ot->reset();
	}

	void mpcot_init_recver(vector<CGGM_Recver<IO, B>*> &recvers, DoryOTPre<IO> *ot) {
		for(int i = 0; i < batch_tree_n; ++i) {
			ot->template choices_recver<B>(recvers[i]->b);
			const uint32_t* idx = recvers[i]->get_index();
			for (int j = 0; j < B; j++)
				item_pos_recver[i*B + j] = idx[j];
		}
		netio->flush();
		ot->reset();
	}

	void exec_parallel_sender(vector<CGGM_Sender<IO, B>*> &senders, DoryOTPre<IO> *ot) {
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

	void exec_parallel_recver(vector<CGGM_Recver<IO, B>*> &recvers, DoryOTPre<IO> *ot) {
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

	void exec_f2k_sender(CGGM_Sender<IO, B> *sender, DoryOTPre<IO> *ot, IO *io, int i) {
		sender->extract_tree_delta(ot, i);
		sender->compute();
		sender->send_f2k(ot, io, i);
		io->flush();
		if(is_malicious)
			sender->consistency_check_msg_gen(io, consist_check_VW + i * B);
	}

	void exec_f2k_recver(CGGM_Recver<IO, B> *recver, DoryOTPre<IO> *ot, IO *io, int i) {
		recver->extract_tree_delta(ot, i);
		recver->recv_f2k(ot, io, i);
		recver->compute();
		if(is_malicious) 
			recver->consistency_check_msg_gen(io, consist_check_chi_alpha + i * B, consist_check_VW + i * B);
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
		int i = start;
		for(; i <= end-EVAL_SIZE; i+=EVAL_SIZE) {
			exec_eval_batch(data, i);
		}
		for (; i < end; i++) {
			exec_eval(data, i);
		}
	}

	void exec_eval(block* data, int idx) {
		constexpr int nblks = (ELL_BOUND + 3) / 4;
		block tmp[nblks];
		for(int m = 0; m < nblks; ++m)
			tmp[m] = makeBlock(cnt+idx, m);
		prp.permute_block(tmp, nblks);
		uint32_t* r = (uint32_t*)(tmp);

		int leave_mask = (1 << (tree_height - 1)) - 1;
		data[idx] = zero_block;
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
			// bool correction = false;
			block delta[EVAL_SIZE];
			block seed[EVAL_SIZE];
			uint32_t w[EVAL_SIZE];
			for (y = 0; y < ell/EVAL_SIZE; y++) {
				for (int x = 0; x < EVAL_SIZE; x++) {
					int index = *r & mask;
					index = index >= idx_max? index-idx_max : index;
					++r;
					int uj = index >> (tree_height - 1), wj = index & leave_mask;
					delta[x] = senders[uj/B]->tree_delta[uj%B];
					seed[x] = senders[uj/B]->seed[uj % B];
					w[x] = wj;
					// correction ^= uj & 1;
					data[idx] ^= acc_delta[uj];
				}
				data[idx] ^= batch_sender_acc_left<EVAL_SIZE>(delta, seed, w);
			}
			for (y = y * EVAL_SIZE; y < ell; y++) {
				int index = *r & mask;
				index = index >= idx_max? index-idx_max : index;
				++r;
				int uj = index >> (tree_height - 1), wj = index & leave_mask;
				block tmp;
				senders[uj/B]->acc_left(tmp, uj % B, wj);
				data[idx] ^= tmp;
				// correction ^= uj & 1;
				data[idx] ^= acc_delta[uj];
			}
			// if (correction)
			// 	data[idx] ^= Delta_f2k;
		}
		else {
			for (int x = 0; x < ell; x++) {
				int index = *r & mask;
				index = index >= idx_max? index-idx_max : index;
				++r;
				int uj = index >> (tree_height - 1), wj = index & leave_mask;
				block tmp = recvers[uj/B]->acc_left(uj % B, wj);
				data[idx] ^= tmp;
				if (wj >= (recvers[uj/B]->choice_pos[uj%B]))
					data[idx] ^= recvers[uj/B]->tree_delta[uj % B];
				data[idx] ^= acc_delta[uj];
			}
		}
		data[idx] &= minustwo;
		if (party == BOB) {
			r = (uint32_t*)(tmp);
			bool choice = false;
			for (int x = 0; x < ell; x++) {
				int index = *r & mask;
				index = index >= idx_max? index-idx_max : index;
				++r;
				int uj = index >> (tree_height - 1), wj = index & leave_mask; 
				// choice ^= ((uj & 1) ^ (wj >= recvers[uj/B]->choice_pos[uj%B]));
				choice ^= acc_delta_choice[uj + (wj >= recvers[uj/B]->choice_pos[uj%B])];
			}
			if (choice)
				data[idx] ^= one; 
		}
	}

	void exec_eval_batch(block* data, int i) {
		int leave_mask = (1 << (tree_height - 1)) - 1;
		constexpr int nblks = ELL_BOUND * EVAL_SIZE / 4;
		block tmp[nblks];
		for(int m = 0; m < nblks; ++m)
			tmp[m] = makeBlock(cnt+i, m);
		prp.permute_block(tmp, nblks);
		uint32_t* r = (uint32_t*)(tmp);
		// block ch[2] = {zero_block, Delta_f2k};
		memset(data+i, 0, EVAL_SIZE*sizeof(block));
		bool correction[EVAL_SIZE];
		memset(correction, 0, EVAL_SIZE*sizeof(bool));
		if (party == ALICE) {
			block delta[EVAL_SIZE];
			block seed[EVAL_SIZE];
			uint32_t w[EVAL_SIZE];
			for (int y = 0; y < ell; y++) {
				for (int m = 0; m < EVAL_SIZE; m++) {
					int index = *r & mask;
					index = index >= idx_max? index-idx_max : index;
					int uj = index >> (tree_height - 1), wj = index & leave_mask;
					++r;
					int batch_tree_idx = uj/B, internal_tree_idx = uj % B;
					seed[m] = senders[batch_tree_idx]->seed[internal_tree_idx];
					delta[m] = senders[batch_tree_idx]->tree_delta[internal_tree_idx];
					w[m] = wj;
					// correction[m] ^= uj & 1;
					data[i + m] ^= acc_delta[uj];
				}
				batch_sender_acc_left<EVAL_SIZE>(data + i, delta, seed, w);
			}
			// for (int m = 0; m < EVAL_SIZE; m++) {
			// 	data[i+m] ^= ch[correction[m]];
			// }
		}
		else {
			uint32_t choice[EVAL_SIZE];
			uint32_t w[EVAL_SIZE];
			block* path_sum = new block[tree_height*EVAL_SIZE];
			for (int y = 0; y < ell; y++) {
				for (int m = 0; m < EVAL_SIZE; m++) {
					int index = *r & mask;
					index = index >= idx_max? index-idx_max : index;
					int uj = index >> (tree_height - 1), wj = index & leave_mask;
					++r;
					int batch_tree_idx = uj/B, internal_tree_idx = uj % B;

					choice[m] = recvers[batch_tree_idx]->choice_pos[internal_tree_idx];
					w[m] = wj;
					for(int i = 0; i < tree_height; i++)
						path_sum[i*EVAL_SIZE + m] = recvers[batch_tree_idx]->path_sum[i*B + internal_tree_idx];

					// correction[m] ^= ((uj & 1) ^ (wj >= choice[m]));
					correction[m] ^= acc_delta_choice[uj + (wj >= choice[m])];

					if (wj >= choice[m])
						data[i + m] ^= recvers[batch_tree_idx]->tree_delta[internal_tree_idx];
					data[i + m] ^= acc_delta[uj];
				}
				batch_recver_acc_left<EVAL_SIZE>(data + i, path_sum, choice, w);
			}
			delete[] path_sum;
		}
		for (int x = 0; x < EVAL_SIZE; x++)
			data[i+x] &= minustwo;
		if (party == BOB) {
			for (int m = 0; m < EVAL_SIZE; m++) {
				// if (correction[m])
				// 	data[i+m] ^= one;
				data[i+m] |= _mm_and_si128(_mm_set1_epi32(-correction[m]), one);
			}
		}
	}

	/**
	 * Compute sum of all leaves with index <= w.
	 * Do this for a batch of `S` trees, and sum the results of all trees.
	 * */ 
	template<int S>
	block batch_sender_acc_left(const block* delta, const block* seed, const uint32_t* w) {
		block acc[S];
		memset(acc, 0, S*sizeof(block));
		batch_sender_acc_left<S>(acc, delta, seed, w);
		for (int i = 1; i < S; i++)
			acc[i] ^= acc[i-1];
		return acc[S - 1];
	}

	/**
	 * Compute sum of all leaves with index <= w.
	 * Do this for a batch of `S` trees.
	 * */ 
	template<int S>
	void batch_sender_acc_left(block* acc, const block* delta, const block* seed, const uint32_t* w) {
		alignas(64) block s[2 * S], to_expand[S];
		for(size_t i = 0; i < S; i++) {
			s[i] = seed[i];
			s[S + i] = delta[i] ^ seed[i];
		}
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
		for (size_t i = 0; i < S; i++) {
			acc[i] ^= s[(w[i] & 1) * S + i];
		}
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

	/**
	 * Compute sum of all leaves with index <= w.
	 * Do this for a batch of `S` trees.
	 * Each tree is provided with the accumulation position `w`, the GGM choice position `choice_pos`, and the
	 * off-path sum `path_sum`.
	 * */ 
	template<int S>
	void batch_recver_acc_left(block* acc, const block* path_sum, const uint32_t* choice_pos, const uint32_t* w) {
		__mmask8 direction[S/4];
		alignas(16) uint32_t wc[S];
		for(int i = 0; i < S; i+=4) {
			__m128i w_pack = _mm_loadu_epi32((void const*)&w[i]);
			__m128i choice_pack = _mm_loadu_epi32((void const*)&choice_pos[i]);
			direction[i/4] = double_mask(_mm_cmple_epi32_mask(w_pack, choice_pack));
			_mm_store_epi32((void*)&wc[i], _mm_xor_si128(w_pack, choice_pack));
		}

		alignas(64) block s[2 * S];
		alignas(64) block to_expand[S];
		__mmask8 diff[S/4];
		memset(diff, 0, S/4 * sizeof(__mmask8));
		__m128i test_mask = _mm_set1_epi32(1 << tree_height-2);
		for (int i = 0; i < tree_height - 1; i++) {
			
			for (int j = 0; j < S; j+=4) {
				__m128i w_pack = _mm_loadu_epi32((void const*)&w[j]);
				__m128i wc_pack = _mm_load_epi32((void const*)&wc[j]);
				
				__mmask8 prev_diff_conds = diff[j/4];
				__mmask8 diff_conds = _kor_mask8(
					double_mask(_mm_test_epi32_mask(wc_pack, test_mask)), 
					prev_diff_conds);
				diff[j/4] = diff_conds;

				__m512i ps_pack = _mm512_loadu_epi32((void const*)&path_sum[i*S + j]);

				__mmask8 w_cond = double_mask(_mm_test_epi32_mask(w_pack, test_mask));

				// if this is NOT after first diff (including the 1st diff), `to_expand` should be taken from `path_sum`;
				// otherwise, taken from previous expansion: to_expand[j] = w_cond ? s[S+j] : s[j]
				__m512i s_low = _mm512_load_epi32((void const*)&s[j]);
				__m512i s_high = _mm512_load_epi32((void const*)&s[S+j]);
				__m512i s_tmp = _mm512_mask_blend_epi64(w_cond, s_low, s_high);
				__m512i expanded = _mm512_mask_blend_epi64(prev_diff_conds, ps_pack, s_tmp);
				__m512i prev_to_expand = _mm512_load_epi32((void const*)&to_expand[j]);
				_mm512_store_epi32((void*)&to_expand[j], expanded);

				// if this is before 1st diff (prev_diff and diff are both 0s), should be taken from `path_sum` or just 0: `(w_cond^direction) ? 0 : path_sum`;
				// if this is exactly 1st diff (prev_diff = 0 and diff = 1), should be 0;
				// if this is after 1st diff (prev_diff and diff are both 1s), should be taken from `s` or just 0: `(w_cond^direction) ? 0 : (w_cond ? s[j] : s[S+j])`.
				// s_tmp = _mm512_mask_blend_epi64(w_cond, s_high, s_low);
				s_tmp = _mm512_xor_si512(prev_to_expand, s_tmp);
				__mmask8 dir_conds = _kxor_mask8(w_cond, direction[j/4]);
				__m512i acced = _mm512_mask_blend_epi64(diff_conds, ps_pack, s_tmp);
				acced = _mm512_mask_blend_epi64(_kor_mask8(_kxor_mask8(prev_diff_conds, diff_conds), dir_conds), acced, _mm512_setzero_si512());
				__m512i cur = _mm512_loadu_epi32((void const*)&acc[j]);
				cur = _mm512_xor_si512(cur, acced);
				_mm512_storeu_epi32((void*)&acc[j], cur);
			}
			test_mask = _mm_srli_epi32(test_mask, 1);
			if (i == tree_height - 2) break;
			ccrh->batch_node_expand<S>(&s[0], &s[S], to_expand);
		}

		for (int i = 0; i < S; i+=4) {
			__mmask8 diff_cond = diff[i/4];
			__mmask8 dir_cond = direction[i/4];
			
			// the leaf corresponding to choice
			__m512i ps_pack = _mm512_loadu_epi32((void const*)&path_sum[(tree_height-1)*S + i]);
			// the leaf corresponding to w
			__m512i leaf_pack = _mm512_load_epi32((void const*)&to_expand[i]);

			// if `direction & diff`, taken dfrom `leaf_pack`;
			// else if `direction`, taken from `ps_pack`.
			__m512i acced = _mm512_mask_blend_epi64(diff_cond, ps_pack, leaf_pack);
			acced = _mm512_mask_blend_epi64(dir_cond, _mm512_setzero_si512(), acced);
			
			__m512i cur = _mm512_loadu_epi32((void const*)&acc[i]);
			cur = _mm512_xor_si512(cur, acced);
			_mm512_storeu_epi32((void*)&acc[i], cur);
		}
	}

#else
	// compute sum of all leaves with index <= w for tree `tree_idx`
	template<int S>
	void batch_recver_acc_left(block* acc, const block* path_sum, const uint32_t* choice_pos, const uint32_t* w) {
		alignas(16) uint32_t direction[S];
		for(int i = 0; i < S; i++)
			direction[i] = w[i] <= choice_pos[i];

		alignas(16) uint32_t diff[S];
		uint32_t min_i = tree_height - 1;
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

		alignas(64) block s[2 * S];
		alignas(64) block to_expand[S];
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
		for (int i = 0; i < S; i++) {
			if (direction[i] && diff[i] < tree_height - 2)
				acc[i] ^= s[(w[i] & 1) * S + i];
		}
	}
#endif


	// f2k consistency check
	void consistency_check_f2k(block *pre_cot_data, int num) {
		if(this->party == ALICE) {
			block r1, r2;
			vector_self_xor(&r1, this->consist_check_VW, num);
			bool x_prime[128];
			this->netio->recv_data(x_prime, 128*sizeof(bool));
			for(int i = 0; i < 128; ++i) {
				if(x_prime[i])
					pre_cot_data[i] = pre_cot_data[i] ^ this->Delta_f2k;
			}
			pack.packing(&r2, pre_cot_data);
			r1 = r1 ^ r2;
			block dig[2];
			Hash hash;
			hash.hash_once(dig, &r1, sizeof(block));
			this->netio->send_data(dig, 2*sizeof(block));
			this->netio->flush();
		} else {
			block r1, r2, r3;
			vector_self_xor(&r1, this->consist_check_VW, num);
			vector_self_xor(&r2, this->consist_check_chi_alpha, num);
			uint64_t pos[2];
			pos[0] = _mm_extract_epi64(r2, 0);
			pos[1] = _mm_extract_epi64(r2, 1);
			bool pre_cot_bool[128];
			for(int i = 0; i < 2; ++i) {
				for(int j = 0; j < 64; ++j) {
					pre_cot_bool[i*64+j] = ((pos[i] & 1) == 1) ^ getLSB(pre_cot_data[i*64+j]);
					pos[i] >>= 1;
				}
			}
			this->netio->send_data(pre_cot_bool, 128*sizeof(bool));
			this->netio->flush();
			pack.packing(&r3, pre_cot_data);
			r1 = r1 ^ r3;
			block dig[2];
			Hash hash;
			hash.hash_once(dig, &r1, sizeof(block));
			block recv[2];
			this->netio->recv_data(recv, 2*sizeof(block));
			if(!cmpBlock(dig, recv, 2))
				std::cout << "SPCOT consistency check fails" << std::endl;
		}
	}
};
#endif
