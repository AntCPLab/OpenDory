#include "emp-ot/emp-ot.h"
#include "test/test.h"
#include "emp-ot/dory/performance.h"
using namespace std;

int port, party;
const static int threads = 1;
const static int batch_size = 16;

void test_dory(int party, NetIO *ios[threads], int64_t num_ot) {
	auto start = clock_start();
	DoryCOT<NetIO, batch_size> * dorycot = new DoryCOT<NetIO, batch_size>(party, threads, ios, false, true, dory_b13);
	double timeused = time_from(start);
	std::cout << party << "\tsetup\t" << timeused/1000 << "ms" << std::endl;

	// RCOT
	// The RCOTs will be generated at internal memory, and copied to user buffer
	int64_t num = 1 << num_ot;
	cout <<"Active DORY RCOT\t"<<double(num)/test_rcot<DoryCOT<NetIO, batch_size>>(dorycot, ios[0], party, num, false)*1e6<<" OTps"<<endl;

	cout << "Comm: " << ios[0]->counter / 1e6 << " MB" << endl;

	// RCOT inplace
	// The RCOTs will be generated at user buffer
	// Get the buffer size needed by calling byte_memory_need_inplace()
	// uint64_t batch_size = dorycot->ot_limit;
	// cout <<"Active DORY RCOT inplace\t"<<double(batch_size)/test_rcot<DoryCOT<NetIO>>(dorycot, ios[0], party, batch_size, true)*1e6<<" OTps"<<endl;
	delete dorycot;

	print_profiling();
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
		
	test_dory(party, ios, length);

	for(int i = 0; i < threads; ++i)
		delete ios[i];
}
