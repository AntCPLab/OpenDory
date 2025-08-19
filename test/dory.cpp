#include "emp-ot/emp-ot.h"
#include "test/test.h"
#include "emp-ot/dory/performance.h"
#include "emp-ot/utils.h"
using namespace std;

int port, party;
// const static int threads = 8;
const static int batch_size = 16;

void test_dory(int party, NetIO **ios, int threads, int64_t num_ot, bool is_malicious, const DualLPNParameter& param) {
	auto start = clock_start();
	DoryCOT<NetIO, batch_size> * dorycot = new DoryCOT<NetIO, batch_size>(party, threads, ios, is_malicious, true, true, param);
	double timeused = time_from(start);
	std::cout << party << "\tsetup\t" << timeused/1000 << "ms" << std::endl;

	// RCOT
	// The RCOTs will be generated at internal memory, and copied to user buffer
	int64_t num = 1 << num_ot;
	num = 10000000;
	double ot_time = test_rcot_stream<DoryCOT<NetIO, batch_size>>(dorycot, ios[0], party, num, false);
	double ot_throughput = double(num) / ot_time * 1e6;
	cout << (is_malicious? "Active" : "Passive") << " DORY RCOT\tTotal Time:\t"<< (timeused + ot_time)/1000 << " ms\tThroughput:\t" << ot_throughput <<" OTps\tPer OT:\t" << (ot_time / num) << " micro secs" <<endl;

	cout << "Comm: " << comm(ios, threads) / 1e6 << " MB" << endl;

	start = clock_start();
	for (int i = 0; i < 10; i++)
		dorycot->bootstrap();
	timeused = time_from(start);
	std::cout << party << "\tWorst case latency: " << timeused / 10 / 1000 << "ms" << std::endl;

	ios[0]->sync();

	delete dorycot;

	print_profiling();
	print_op_counts();
}

/**
 * Usage:
 * ./bin/test_dory [party] [port] [log(OT num)] [threads] [LPN param index] [is malicious?]
 * 
 * ./bin/test_dory 1 12345 20 1 0 0
 * party 1 (Alice), port: 12345, generate 2**20 OTs, 1 thread, LPN param 0, passive
 */
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
	
	DualLPNParameter param = dory_b13;
	if (argc > 5) {
		int param_idx = atoi(argv[5]);
		if (param_idx == 0)
			param = dory_b13;
		else if (param_idx == 1)
			param = dory_b15;
		else if (param_idx == 2)
			param = dory_b18;
		else if (param_idx == 3)
			param = dory_b23;
	}

	bool is_malicious = false;
	if (argc > 6)
		is_malicious = atoi(argv[6]) > 0;

	// {
	// 	NetIO* ios[threads];
	// 	for(int i = 0; i < threads; ++i)
	// 		ios[i] = new NetIO(party == ALICE?nullptr:"127.0.0.1",port+i);

	// 	test_dory(party, ios, length, false);

	// 	for(int i = 0; i < threads; ++i)
	// 		delete ios[i];
	// }

	{
		NetIO** ios = new NetIO*[threads];
		for(int i = 0; i < threads; ++i)
			ios[i] = new NetIO(party == ALICE?nullptr:"127.0.0.1",port+i);

		test_dory(party, ios, threads, length, is_malicious, param);

		for(int i = 0; i < threads; ++i)
			delete ios[i];
		delete[] ios;
	}
	
}
