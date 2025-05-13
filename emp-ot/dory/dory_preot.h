#ifndef _DORY_PRE_OT__
#define _DORY_PRE_OT__
#include "emp-tool/emp-tool.h"
#include "emp-ot/dory/preot.h"
#include "emp-ot/dory/performance.h"
using namespace emp;

/**
 * A refactored pre OT for Dory.
 * Number of 
*/
template<typename IO>
class DoryOTPre { public:
	IO* io;
	block * pre_data = nullptr;
	bool * bits = nullptr;
	int n, unit_length;
	int count;
	block global_delta;

	OTPre<IO>* preot;

	PRG prg;

	DoryOTPre(OTPre<IO>* preot) {
		this->preot = preot;
		this->n = preot->n;
		this->unit_length = preot->unit_length;
		this->io = preot->io;
		pre_data = new block[n];
		bits = new bool[preot->n];
		global_delta = preot->Delta;
		count = 0;
	}

	~DoryOTPre() {
		if (pre_data != nullptr)
			delete[] pre_data;

		if (bits != nullptr)
			delete[] bits;
	}

	void sender_refactor() {
		bool* d = new bool[n];
		io->recv_bool(d, n * sizeof(bool));

		memcpy(pre_data, preot->pre_data, n * sizeof(block));
		for (int i = 0; i < n; i++) {
			if (i % unit_length == 0) continue;
			if (d[i])
				pre_data[i] ^= global_delta;
		}

		delete[] d;
	}

	void receiver_refactor() {
		// Sample new choice bits
		prg.random_bool(bits, n);
		
		bool* d = new bool[n];
		memcpy(pre_data, preot->pre_data, n * sizeof(block));
		for (int i = 0; i < n; i++) {
			if (i % unit_length == 0) {
				// \beta = s[0], M(\beta) = M(s[0])
				bits[i] = preot->bits[i];
			}
			else {
				d[i] = preot->bits[i];
				if (bits[i]) {
					pre_data[i] ^= pre_data[i/unit_length];
					d[i] ^= bits[i/unit_length];
				}
			}
		}
		io->send_bool(d, n * sizeof(bool));
		delete[] d;
	}

	block local_delta(int s) {
		return pre_data[s * unit_length];
	}

	bool local_delta_choice(int s) {
		return bits[s * unit_length];
	}

	void choices_sender(int length) {
		count += length;
	}

	void choices_recver(bool * b, int length) {
		memcpy(b, bits+count+1, length-1);
		count += length;
	}
	
	void reset() {
		count = 0;
	}

	void send(const block* m, int length, IO* io2, int start_unit) {
		block pad;
		int k = start_unit * unit_length + 1;
		for (int i = 0; i < length - 1; ++i) {
			pad = m[i] ^ pre_data[k];
			++k;
			io2->send_block(&pad, 1);
		}
	}

	void recv(block* data, int length, IO* io2, int start_unit) {
		int k = start_unit * unit_length + 1;

		io2->recv_block(data, length - 1);
		for (int i = 0; i < length - 1; ++i) {
			data[i] ^= pre_data[k];
			++k;
		}
	}
};
#endif// _DORY_PRE_OT__
