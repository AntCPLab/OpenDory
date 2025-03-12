template<typename T, int BatchSize>
DoryCOT<T, BatchSize>::DoryCOT(int party, int threads, T **ios,
		bool malicious, bool run_setup, DualLPNParameter param, std::string pre_file) {
	this->party = party;
	this->threads = threads;
	io = ios[0];
	this->ios = ios;
	this->is_malicious = malicious;
	one = makeBlock(0xFFFFFFFFFFFFFFFFLL,0xFFFFFFFFFFFFFFFELL);
	ch[0] = zero_block;
	base_cot = new BaseCot<T>(party, io, malicious);
	pool = new ThreadPool(threads);
	this->param = param;

	this->extend_initialized = false;


	if(run_setup) {
		if(party == ALICE) {
			PRG prg;
			prg.random_block(&Delta);
			Delta = Delta & one;
			Delta = Delta ^ 0x1;
			setup(Delta, pre_file);
		} else setup(pre_file);
	}
}

template<typename T, int BatchSize>
DoryCOT<T, BatchSize>::~DoryCOT() {
	if (ot_pre_data != nullptr) {
		if(party == ALICE) write_pre_data128_to_file((void*)ot_pre_data, (__uint128_t)Delta, pre_ot_filename);
		else write_pre_data128_to_file((void*)ot_pre_data, (__uint128_t)0, pre_ot_filename);
		delete[] ot_pre_data;
	}
	if(pre_ot != nullptr) delete pre_ot;
	delete base_cot;
	delete pool;
	if(stream_cot != nullptr) delete stream_cot;
}

template<typename T, int BatchSize>
void DoryCOT<T, BatchSize>::extend_initialization() {
	stream_cot = new StreamCotReg<T, BatchSize>(party, threads, param.n, param.t, param.log_bin_sz, pool, ios);
	if(is_malicious) stream_cot->set_malicious();

	pre_ot = new OTPre<T>(io, (stream_cot->tree_height-1) * BatchSize, (stream_cot->tree_n + BatchSize - 1)/BatchSize);
	M = pre_ot->n + stream_cot->consist_check_cot_num;
	// [TODO] Need to modify the calculation of ot_limit.
	ot_limit = param.n - M;
	ot_used = ot_limit;
	extend_initialized = true;
}

template<typename T, int BatchSize>
void DoryCOT<T, BatchSize>::extend_full(block* ot_output, StreamCotReg<T, BatchSize> *stream_cot, OTPre<T> *preot, 
		block *ot_input) {
	if(party == ALICE) stream_cot->sender_init(Delta);
	else stream_cot->recver_init();
	stream_cot->bootstrap(preot, ot_input);
	stream_cot->eval_full(ot_output);
}

template<typename T, int BatchSize>
void DoryCOT<T, BatchSize>::extend_full(block *ot_buffer) {
	if(party == ALICE)
	    pre_ot->send_pre(ot_pre_data, Delta);
	else pre_ot->recv_pre(ot_pre_data);
	// [TODO] Need to advance ot_pre_data
	extend_full(ot_buffer, stream_cot, pre_ot, ot_pre_data);
	memcpy(ot_pre_data, ot_buffer + ot_limit, M*sizeof(block));
}

template<typename T, int BatchSize>
void DoryCOT<T, BatchSize>::extend_limit(block *ot_buffer, int64_t num) {
	if(party == ALICE) {
	    pre_ot->send_pre(ot_pre_data, Delta);
		stream_cot->sender_init(Delta);
	}
	else {
		pre_ot->recv_pre(ot_pre_data);
		stream_cot->recver_init();
	}
	// [TODO] Need to advance ot_pre_data
	stream_cot->bootstrap(pre_ot, ot_pre_data);
	stream_cot->eval(ot_pre_data, (uint32_t)M);
	stream_cot->eval(ot_buffer, (uint32_t)num);
}

template<typename T, int BatchSize>
void DoryCOT<T, BatchSize>::setup(block Deltain, std::string pre_file, bool *choice, block seed) {
	this->Delta = Deltain;
	if(this->is_malicious) seed = zero_block;
	setup(pre_file, choice, seed);
	ch[1] = Delta;
}

template<typename T, int BatchSize>
void DoryCOT<T, BatchSize>::setup(std::string pre_file, bool *choice, block seed) {
	if(pre_file != "") pre_ot_filename = pre_file;
	else {
		pre_ot_filename=(party==ALICE?DORY_PRE_OT_DATA_REG_SEND_FILE:DORY_PRE_OT_DATA_REG_RECV_FILE);
	}

	ThreadPool pool2(1);
	auto fut = pool2.enqueue([this](){
		extend_initialization();
	});

	ot_pre_data = new block[param.n_pre];
	bool hasfile = file_exists(pre_ot_filename), hasfile2;
	if(party == ALICE) {
		io->send_data(&hasfile, sizeof(bool));
		io->flush();
		io->recv_data(&hasfile2, sizeof(bool));
	} else {
		io->recv_data(&hasfile2, sizeof(bool));
		io->send_data(&hasfile, sizeof(bool));
		io->flush();
	}
	if(hasfile & hasfile2) {
		Delta = (block)read_pre_data128_from_file((void*)ot_pre_data, pre_ot_filename);
	} else {
		if(party == BOB) base_cot->cot_gen_pre();
		else base_cot->cot_gen_pre(Delta);

		StreamCotReg<T, BatchSize> stream_cot_ini(party, threads, param.n_pre, param.t_pre, param.log_bin_sz_pre, pool, ios);
		if(is_malicious) stream_cot_ini.set_malicious();
		OTPre<T> pre_ot_ini(ios[0], (stream_cot_ini.tree_height-1) * BatchSize, (stream_cot_ini.tree_n + BatchSize + 1) / BatchSize);

		block *pre_data_ini = new block[stream_cot_ini.consist_check_cot_num];
		memset(this->ot_pre_data, 0, param.n_pre*16);
		if(this->is_malicious){
			seed = zero_block;
			choice = nullptr;
		}
		if(choice){
            base_cot->cot_gen(&pre_ot_ini, pre_ot_ini.n, choice);
            base_cot->cot_gen(pre_data_ini, stream_cot_ini.consist_check_cot_num, choice+pre_ot_ini.n);
        }else {
            base_cot->cot_gen(&pre_ot_ini, pre_ot_ini.n);
            base_cot->cot_gen(pre_data_ini, stream_cot_ini.consist_check_cot_num);
        }
		extend_full(ot_pre_data, &stream_cot_ini, &pre_ot_ini, pre_data_ini);
		delete[] pre_data_ini;
	}

	fut.get();
}

template<typename T, int BatchSize>
void DoryCOT<T, BatchSize>::rcot(block *data, int64_t num) {
	if(extend_initialized == false) 
		error("Run setup before extending");
	if(num <= silent_ot_left()) {
		stream_cot->eval(data, num);
		return;
	}
	block *pt = data;
	int64_t left = silent_ot_left();
	if (left > 0) {
		stream_cot->eval(pt, left);
		pt += left;
	}

	// We are using `pt` as the inplace buffer, so the `M` ot pre data are 
	// first stored in `pt` and then copied out. Hence we need to make sure 
	// `pt` have enough space and thus need to `-M` below for computing round_inplace.
	int64_t round_inplace = (num-left-M) / ot_limit;
	int64_t last_round_ot = num-left-round_inplace*ot_limit;
	bool round_memcpy = last_round_ot > ot_limit ? true : false;
	if(round_memcpy) last_round_ot -= ot_limit;
	for(int64_t i = 0; i < round_inplace; ++i) {
		extend_full(pt);
		pt += ot_limit;
	}
	if(round_memcpy) {
		extend_limit(pt, ot_limit);
		pt += ot_limit;
	}
	if(last_round_ot > 0) {
		extend_limit(pt, last_round_ot);
	}
}

template<typename T, int BatchSize>
int64_t DoryCOT<T, BatchSize>::silent_ot_left() {
	return stream_cot->silent_ot_left();
}

template<typename T, int BatchSize>
void DoryCOT<T, BatchSize>::write_pre_data128_to_file(void* loc, __uint128_t delta, std::string filename) {
	std::ofstream outfile(filename);
	if(outfile.is_open()) outfile.close();
	else error("create a directory to store pre-OT data");
	FileIO fio(filename.c_str(), false);
	fio.send_data(&party, sizeof(int64_t));
	if(party == ALICE) fio.send_data(&delta, 16);
	fio.send_data(&param.n, sizeof(int64_t));
	fio.send_data(&param.t, sizeof(int64_t));
	fio.send_data(loc, param.n_pre*16);
}

template<typename T, int BatchSize>
__uint128_t DoryCOT<T, BatchSize>::read_pre_data128_from_file(void* pre_loc, std::string filename) {
	FileIO fio(filename.c_str(), true);
	int in_party;
	fio.recv_data(&in_party, sizeof(int64_t));
	if(in_party != party) error("wrong party");
	__uint128_t delta = 0;
	if(party == ALICE) fio.recv_data(&delta, 16);
	int64_t nin, tin;
	fio.recv_data(&nin, sizeof(int64_t));
	fio.recv_data(&tin, sizeof(int64_t));
	if(nin != param.n || tin != param.t)
		error("wrong parameters");
	fio.recv_data(pre_loc, param.n_pre*16);
	std::remove(filename.c_str());
	return delta;
}

template<typename T, int BatchSize>
int64_t DoryCOT<T, BatchSize>::byte_memory_need_inplace(int64_t ot_need) {
	int64_t round = (ot_need - 1) / ot_limit;
	return round * ot_limit + param.n;
}

// extend f2k (benchmark)
// parameter "length" should be the return of "byte_memory_need_inplace"
// output the number of COTs that can be used
template<typename T, int BatchSize>
int64_t DoryCOT<T, BatchSize>::rcot_inplace(block *ot_buffer, int64_t byte_space, block seed) {
	if(byte_space < param.n) error("space not enough");
	if((byte_space - M) % ot_limit != 0) error("call byte_memory_need_inplace \
			to get the correct length of memory space");
	int64_t ot_output_n = byte_space - M;
	int64_t round = ot_output_n / ot_limit;
	block *pt = ot_buffer;
	for(int64_t i = 0; i < round; ++i) {
		if(party == ALICE)
		    pre_ot->send_pre(ot_pre_data, Delta);
		else pre_ot->recv_pre(ot_pre_data);
		if(this->is_malicious) seed = zero_block;
		extend_full(pt, stream_cot, pre_ot, ot_pre_data);
		pt += ot_limit;
		memcpy(ot_pre_data, pt, M*sizeof(block));
	}
	return ot_output_n;
}

template<typename T, int BatchSize>
void DoryCOT<T, BatchSize>::online_sender(block *data, int64_t length) {
	bool *bo = new bool[length];
	io->recv_bool(bo, length*sizeof(bool));
	for(int64_t i = 0; i < length; ++i) {
		data[i] = data[i] ^ ch[bo[i]];
	}
	delete[] bo;
}

template<typename T, int BatchSize>
void DoryCOT<T, BatchSize>::online_recver(block *data, const bool *b, int64_t length) {
	bool *bo = new bool[length];
	for(int64_t i = 0; i < length; ++i) {
		bo[i] = b[i] ^ getLSB(data[i]);
	}
	io->send_bool(bo, length*sizeof(bool));
	delete[] bo;
}

template<typename T, int BatchSize>
void DoryCOT<T, BatchSize>::send_cot(block * data, int64_t length) {
	rcot(data, length);
	online_sender(data, length);
}

template<typename T, int BatchSize>
void DoryCOT<T, BatchSize>::recv_cot(block* data, const bool * b, int64_t length) {
	rcot(data, length);
	online_recver(data, b, length);
}

// template<typename T>
// void DoryCOT<T>::assemble_state(void * data, int64_t size) {
// 	unsigned char * array = (unsigned char * )data;
// 	int64_t party_tmp = party;
// 	memcpy(array, &party_tmp, sizeof(int64_t));
// 	memcpy(array + sizeof(int64_t), &param.n, sizeof(int64_t));
// 	memcpy(array + sizeof(int64_t) * 2, &param.t, sizeof(int64_t));
// 	memcpy(array + sizeof(int64_t) * 3, &param.k, sizeof(int64_t));
// 	memcpy(array + sizeof(int64_t) * 4, &Delta, sizeof(block));	
// 	memcpy(array + sizeof(int64_t) * 4 + sizeof(block), ot_pre_data, sizeof(block)*param.n_pre);
// 	if (ot_pre_data!= nullptr)
// 		delete[] ot_pre_data;
// 	ot_pre_data = nullptr;
// }

// template<typename T>
// int DoryCOT<T>::disassemble_state(const void * data, int64_t size) {
// 	const unsigned char * array = (const unsigned char * )data;
// 	int64_t n2 = 0, t2 = 0, k2 = 0, party2 = 0;
// 	ot_pre_data = new block[param.n_pre];
// 	memcpy(&party2, array, sizeof(int64_t));
// 	memcpy(&n2, array + sizeof(int64_t), sizeof(int64_t));
// 	memcpy(&t2, array + sizeof(int64_t) * 2, sizeof(int64_t));
// 	memcpy(&k2, array + sizeof(int64_t) * 3, sizeof(int64_t));
// 	if(party2 != party or n2 != param.n or t2 != param.t or k2 != param.k) {
// 		return -1;
// 	}
// 	memcpy(&Delta, array + sizeof(int64_t) * 4, sizeof(block));	
// 	memcpy(ot_pre_data, array + sizeof(int64_t) * 4 + sizeof(block), sizeof(block)*param.n_pre);

// 	extend_initialization();
// 	ch[1] = Delta;
// 	return 0;
// }

// template<typename T>
// int64_t DoryCOT<T>::state_size() {
// 	return sizeof(int64_t) * 4 + sizeof(block) + sizeof(block)*param.n_pre;
// }

