#ifndef EMP_DORY_COT_H_
#define EMP_DORY_COT_H_
#include "emp-ot/dory/stream_cot_reg.h"
#include "emp-ot/dory/base_cot.h"
#include "emp-ot/dory/constants.h"

namespace emp {

template<typename T, int B = 8>
class DoryCOT: public COT<T> {
public:
	using COT<T>::io;
	using COT<T>::Delta;

	DualLPNParameter param;
	int64_t ot_limit;

	DoryCOT(int party, int threads, T **ios, bool malicious = false, bool run_setup = true, bool run_bootstrap = true,
DualLPNParameter param = dory_b13, std::string pre_file="");
	

	~DoryCOT();

	void setup(block Deltain, std::string pre_file = "", bool *choice=nullptr, block seed=zero_block);

	void setup(std::string pre_file = "", bool *choice = nullptr, block seed= zero_block);

	void bootstrap();

	void send_cot(block * data, int64_t length) override;

	void recv_cot(block* data, const bool * b, int64_t length) override;

	void rcot(block *data, int64_t num);

	int64_t rcot_inplace(block *ot_buffer, int64_t length, block seed = zero_block);

	int64_t byte_memory_need_inplace(int64_t ot_need);

	void assemble_state(void * data, int64_t size);

	int disassemble_state(const void * data, int64_t size);

	int64_t state_size();

	int64_t multithread_eval_batch_size();

private:
	block ch[2];

	T **ios;
	int party, threads;
	int64_t M;
	bool is_malicious;
	bool extend_initialized;

	block one;

	block * ot_pre_data = nullptr;

	std::string pre_ot_filename;

	DoryBaseCot<T> *base_cot = nullptr;
	SimpleOTPre<T> *pre_ot = nullptr;
	ThreadPool *pool = nullptr;
	StreamCotReg<T, B> *stream_cot = nullptr;
	
	void online_sender(block *data, int64_t length);

	void online_recver(block *data, const bool *b, int64_t length);

	void set_param();

	void set_preprocessing_param();

	void extend_initialization();

	void extend_full(block* ot_output, StreamCotReg<T, B> *mpfss, SimpleOTPre<T> *preot, 
		block *ot_input);

	void extend_full(block *ot_buffer);

	void extend_limit(block *ot_buffer, int64_t num);

	int64_t silent_ot_left();

	void write_pre_data128_to_file(void* loc, __uint128_t delta, std::string filename);

	__uint128_t read_pre_data128_from_file(void* pre_loc, std::string filename);
};

#include "emp-ot/dory/dory_cot.hpp"
}
#endif// _VOLE_H_
