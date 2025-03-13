#include <iostream>
#include "emp-ot/dory/ccrh.h"
#include <stdlib.h>
using namespace std;
using namespace emp;

int main(int argc, char** argv) {
	PRG prg;
	int n;
	if (argc >= 2) {
		n = atoi(argv[1]);
	} else {
		n = 20;
	}
	if(n > 30) {
		cout <<"Large test size! comment me if you want to run this size\n";
		exit(1);
	}
	
	block key = zero_block;
	AES_KEY scheduled_key;
	AES_set_encrypt_key(key, &scheduled_key);
	AES_KEYx4_t *key512 = reinterpret_cast<AES_KEYx4_t*>(aligned_alloc(64, sizeof(AES_KEYx4_t)));
	aes_key_to_aes_keyx4(key512, &scheduled_key);

	block * nn = reinterpret_cast<block*>(aligned_alloc(64, sizeof(block) * (1<<n)));
	prg.random_block(nn, 1<<n);


	auto t1 = clock_start();
	AES_ecb_encrypt_blks(nn, 1<<n, key512);
	cout << "V-AES Throughput:\t" << (double)(1<<n) / time_from(t1) * 1e6 <<"\tBlocks/s"<<endl;

	const int batch = 16;

	AES_KEYx4_t *key512s = reinterpret_cast<AES_KEYx4_t*>(aligned_alloc(64, sizeof(AES_KEYx4_t)*batch/4));
	for (int i = 0; i < batch/4; i++)
		aes_key_to_aes_keyx4(&key512s[i], &scheduled_key);

	auto t2 = clock_start();
	for (int i = 0; i < (1<<n)/batch; i++) {
		ParaEnc<batch>(nn+i*batch, key512s);
	}
	cout << "V-AES ParaEnc Throughput:\t" << (double)(1<<n) / time_from(t2) * 1e6 <<"\tBlocks/s"<<endl;

	auto t3 = clock_start();
	AES_ecb_encrypt_blks(nn, 1<<n, &scheduled_key);
	cout << "AES Throughput:\t" << (double)(1<<n) / time_from(t3) * 1e6 <<"\tBlocks/s"<<endl;
	
	block keys[batch] = {zero_block, zero_block, zero_block, zero_block};
	memset(keys, 0, sizeof(keys));
	AES_KEY scheduled_keys[batch];
	AES_opt_key_schedule<batch>(keys, scheduled_keys);

	auto t4 = clock_start();
	for (int i = 0; i < (1<<n)/batch; i++) {
		ParaEnc<batch, 1>(nn+i*batch, scheduled_keys);
	}
	cout << "AES ParaEnc Throughput:\t" << (double)(1<<n) / time_from(t4) * 1e6 <<"\tBlocks/s"<<endl;

	auto t5 = clock_start();
	for (int i = 0; i < (1<<n)/batch; i++) {
		AES_ecb_encrypt_blks<batch>(nn + i*batch, &scheduled_key);
	}
	cout << "AES (Batch) Throughput:\t" << (double)(1<<n) / time_from(t3) * 1e6 <<"\tBlocks/s"<<endl;

	free(key512);
	free(nn);
}
