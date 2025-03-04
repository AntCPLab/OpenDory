#include "emp-ot/dory/stream_cot_reg.h"
#include "emp-ot/dory/base_cot.h"
using namespace std;

int port, party;
const static int threads = 1;
const static int batch_size = 1;

void test_streamcot(int party, NetIO *ios[threads]) {
	BaseCot<NetIO> base_cot(party, ios[0], false);
    base_cot.cot_gen_pre();
    block secret = base_cot.ot_delta;
    if (party == ALICE)
        std::cout << "Sender's secret: " << secret << std::endl;
	
    OTPre<NetIO> pre_ot(ios[0], ferret_b13.log_bin_sz * batch_size, ferret_b13.t / batch_size);
    base_cot.cot_gen(&pre_ot, pre_ot.n);

	block* buf = new block[ferret_b13.n];
	cout << party << ": pre_ot.n: " << pre_ot.n << ", buf.n: " << ferret_b13.n << endl;

	auto start = clock_start();
	ThreadPool* pool = new ThreadPool(threads);
	StreamCotReg<NetIO, batch_size> * streamcot = new StreamCotReg<NetIO, batch_size>(party, threads, ferret_b13.n, ferret_b13.t, ferret_b13.log_bin_sz, pool, ios);
	if(party == ALICE) streamcot->sender_init(secret);
	else streamcot->recver_init();
	streamcot->mpcot(buf, &pre_ot, nullptr);
	double timeused = time_from(start);
	std::cout << party << "\tsetup\t" << timeused/1000 << "ms" << std::endl;

	// RCOT
	// The RCOTs will be generated at internal memory, and copied to user buffer
	block data;
	streamcot->rcot(&data, 1);
	std::cout << "data:\t" << data << std::endl;

	if (party == ALICE) {
		ios[0]->send_block(&secret, 1);
		ios[0]->send_block(&data, 1);
	}
	else {
		block sender_secret, sender_data;
		ios[0]->recv_block(&sender_secret, 1);
		ios[0]->recv_block(&sender_data, 1);
		if (getLSB(data))
			sender_data ^= sender_secret;
		if(!cmpBlock(&data, &sender_data, 1)) {
			std::cout << "Inconsistent data: " << data << ",\t" << "Sender data:\t" << sender_data << std::endl;
			error("wrong!\n");
		}
	}

	delete streamcot;
	delete pool;
	delete[] buf;
}

int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);
	NetIO* ios[threads];
	for(int i = 0; i < threads; ++i)
		ios[i] = new NetIO(party == ALICE?nullptr:"127.0.0.1",port+i);
		
	test_streamcot(party, ios);

	for(int i = 0; i < threads; ++i)
		delete ios[i];
}
