#include "emp-ot/dory/mpcot_reg.h"
#include "emp-ot/dory/base_cot.h"
using namespace std;

int port, party;
const static int threads = 1;

void test_mpcot(int party, NetIO *ios[threads], int64_t num_ot) {
	BaseCot<NetIO> base_cot(party, ios[0], false);
    base_cot.cot_gen_pre();
    block secret = base_cot.ot_delta;
    if (party == ALICE)
        std::cout << "Sender's secret: " << secret << std::endl;
	
    OTPre<NetIO> pre_ot(ios[0], ferret_b13.log_bin_sz, ferret_b13.t);
    base_cot.cot_gen(&pre_ot, pre_ot.n);

	block* buf = new block[ferret_b13.n];
	cout << party << ": pre_ot.n: " << pre_ot.n << ", buf.n: " << ferret_b13.n << endl;

	auto start = clock_start();
	ThreadPool* pool = new ThreadPool(threads);
	DoryMpcotReg<NetIO> * mpcot = new DoryMpcotReg<NetIO>(party, threads, ferret_b13.n, ferret_b13.t, ferret_b13.log_bin_sz, pool, ios);
	if(party == ALICE) mpcot->sender_init(secret);
	else mpcot->recver_init();
	mpcot->mpcot(buf, &pre_ot, nullptr);
	double timeused = time_from(start);
	std::cout << party << "\tsetup\t" << timeused/1000 << "ms" << std::endl;

	// RCOT
	// The RCOTs will be generated at internal memory, and copied to user buffer
	block data;
	mpcot->rcot(&data, 1);
	std::cout << "data:\t" << data << std::endl;

	delete mpcot;
	delete pool;
	delete[] buf;
}

int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);
	NetIO* ios[threads];
	for(int i = 0; i < threads; ++i)
		ios[i] = new NetIO(party == ALICE?nullptr:"127.0.0.1",port+i);

	int64_t length = 24;
	if (argc > 3)
		length = atoi(argv[3]);
	if(length > 30) {
		cout <<"Large test size! comment me if you want to run this size\n";
		exit(1);
	}
		
	test_mpcot(party, ios, length);

	for(int i = 0; i < threads; ++i)
		delete ios[i];
}
