#ifndef SIMPLE_PRE_OT_H
#define SIMPLE_PRE_OT_H
#include "emp-tool/emp-tool.h"
#include "emp-ot/dory/performance.h"
using namespace emp;

template<typename IO>
class SimpleOTPre { public:
	IO* io;
	block * pre_data = nullptr;
	bool * bits = nullptr;
	int n;

	int unit_length, count;
	block Delta;
	SimpleOTPre(IO* io, int unit_length, int times) {
		this->io = io;
		this->unit_length = unit_length;
		n = unit_length*times;
		pre_data = new block[n];
		bits = new bool[n];
		count = 0;
	}

	~SimpleOTPre() {
		if (pre_data != nullptr)
			delete[] pre_data;

		if (bits != nullptr)
			delete[] bits;
	}

	void send_pre(block * data, block in_Delta) {
		Delta = in_Delta;
		memcpy(pre_data, data, n*sizeof(block));
	}

	void recv_pre(block * data, bool * b) {
		memcpy(bits, b, n);
		memcpy(pre_data, data, n*sizeof(block));
	}

	void recv_pre(block * data) {
		for(int i = 0; i < n; ++i)
			bits[i] = getLSB(data[i]);
		memcpy(pre_data, data, n*sizeof(block));
	}

	void choices_sender(int length) {
		count += length;
	}

	void choices_recver(bool * b, int length) {
		memcpy(b, bits+count, length);
		count += length;
	}
	
	void reset() {
		count = 0;
	}

	void send(const block* m, int length, IO* io2, int start_unit) {
		block pad;
		int k = start_unit * unit_length;
		for (int i = 0; i < length; ++i) {
			pad = m[i] ^ pre_data[k];
			++k;
			io2->send_block(&pad, 1);
		}

		// // [NOTE] The following code is sometimes faster than 
		// // the above one, because NetIO is using TCP_NODELAY which
		// // might send a lot of small packets without waiting, causing
		// // a traffic jam. I have observed this problem on the `recv` side
		// // which waits several seconds to receive a message, even though
		// // the `send` is done in just several milliseconds.
		// // NOTE that `pre_data` is no longer valid for future use.
		// for (int i = 0; i < length; ++i) {
		// 	pre_data[k] ^= m[i];
		// 	++k;
		// }
		// io2->send_block(pre_data + s*length, length);
	}

	void recv(block* data, int length, IO* io2, int start_unit) {
		int k = start_unit * unit_length;

		io2->recv_block(data, length);
		for (int i = 0; i < length; ++i) {
			data[i] ^= pre_data[k];
			++k;
		}
	}
};
#endif// SIMPLE_PRE_OT_H
