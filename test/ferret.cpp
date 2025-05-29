#include "emp-ot/emp-ot.h"
#include "test/test.h"
#include "emp-ot/dory/performance.h"
using namespace std;


int port, party;
// const static int threads = 16;

void test_ferret(int party, NetIO **ios, int threads, int64_t num_ot, bool is_malicious) {
	auto start = clock_start();
	FerretCOT<NetIO> * ferretcot = new FerretCOT<NetIO>(party, threads, ios, is_malicious, true, ferret_b13);
	double timeused = time_from(start);
	std::cout << party << "\tsetup\t" << timeused/1000 << "ms" << std::endl;

	// RCOT
	// The RCOTs will be generated at internal memory, and copied to user buffer
	int64_t num = 1 << num_ot;
	num = 10000000;
	double ot_time = test_rcot<FerretCOT<NetIO>>(ferretcot, ios[0], party, num, false);
	double ot_throughput = double(num) / ot_time * 1e6;
	cout << (is_malicious? "Active" : "Passive") << " FERRET RCOT\tTime:\t"<< ot_time/1000 << " ms\tThroughput:\t" << ot_throughput <<" OTps\tPer OT:\t" << (ot_time / num) << " micro secs" <<endl;

	cout << "Comm: " << comm(ios, threads) / 1e6 << " MB" << endl;

	start = clock_start();
	ferretcot->extend_f2k();
	timeused = time_from(start);
	std::cout << "Worst case latency: " << timeused / 1000 << "ms" << std::endl;

	// RCOT inplace
	// The RCOTs will be generated at user buffer
	// Get the buffer size needed by calling byte_memory_need_inplace()
	// uint64_t batch_size = ferretcot->ot_limit;
	// cout <<"Passive FERRET RCOT inplace\t"<<double(batch_size)/test_rcot<FerretCOT<NetIO>>(ferretcot, ios[0], party, batch_size, true)*1e6<<" OTps"<<endl;
	delete ferretcot;

	print_op_counts();
}

// void test_ferret_active(int party, NetIO *ios[threads], int64_t num_ot) {
// 	auto start = clock_start();
// 	FerretCOT<NetIO> * ferretcot = new FerretCOT<NetIO>(party, threads, ios, false, true, ferret_b13);
// 	double timeused = time_from(start);
// 	std::cout << party << "\tsetup\t" << timeused/1000 << "ms" << std::endl;

// 	// RCOT
// 	// The RCOTs will be generated at internal memory, and copied to user buffer
// 	int64_t num = 1 << num_ot;
// 	cout <<"Active FERRET RCOT\t"<<double(num)/test_rcot<FerretCOT<NetIO>>(ferretcot, ios[0], party, num, false)*1e6<<" OTps"<<endl;

// 	cout << "Comm: " << comm<threads>(ios) / 1e6 << " MB" << endl;

// 	// RCOT inplace
// 	// The RCOTs will be generated at user buffer
// 	// Get the buffer size needed by calling byte_memory_need_inplace()
// 	uint64_t batch_size = ferretcot->ot_limit;
// 	cout <<"Active FERRET RCOT inplace\t"<<double(batch_size)/test_rcot<FerretCOT<NetIO>>(ferretcot, ios[0], party, batch_size, true)*1e6<<" OTps"<<endl;
// 	delete ferretcot;

// 	print_op_counts();
// }

int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);

	int64_t length = 24;
	if (argc > 3)
		length = atoi(argv[3]);
	if(length > 30) {
		cout <<"Large test size! comment me if you want to run this size\n";
		exit(1);
	}
	int threads = 1;
	if (argc > 4)
		threads = atoi(argv[4]);

	bool is_malicious = false;
	if (argc > 5)
		is_malicious = atoi(argv[5]) > 0;

	// {
	// 	NetIO* ios[threads];
	// 	for(int i = 0; i < threads; ++i)
	// 		ios[i] = new NetIO(party == ALICE?nullptr:"127.0.0.1",port+i);	
	// 	test_ferret_passive(party, ios, length);

	// 	for(int i = 0; i < threads; ++i)
	// 		delete ios[i];
	// }
	{
		NetIO** ios = new NetIO*[threads];
		for(int i = 0; i < threads; ++i)
			ios[i] = new NetIO(party == ALICE?nullptr:"127.0.0.1",port+i);	
		test_ferret(party, ios, threads, length, is_malicious);

		for(int i = 0; i < threads; ++i)
			delete ios[i];
		delete ios;
	}
}
