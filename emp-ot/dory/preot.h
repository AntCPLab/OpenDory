#ifndef _PRE_OT__
#define  _PRE_OT__
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
using namespace emp;

template<typename IO>
class OTPre { public:
	IO* io;
	block * pre_data = nullptr;
	bool * bits = nullptr;
	int n;
	vector<block*> pointers;
	vector<const bool*> choices;
	vector<const block*> pointers0;
	vector<const block*> pointers1;

	int length, count;
	block Delta;
	OTPre(IO* io, int length, int times) {
		this->io = io;
		this->length = length;
		n = length*times;
		pre_data = new block[n];
		bits = new bool[n];
		count = 0;
	}

	~OTPre() {
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

	void choices_sender() {
		count +=length;
	}

	void choices_recver(bool * b) {
		memcpy(b, bits+count, length);
		count +=length;
	}
	
	void reset() {
		count = 0;
	}

	void send(const block* m, int length, IO* io2, int s) {
		block pad;
		int k = s*length;
		for (int i = 0; i < length; ++i) {
				pad = m[i] ^ pre_data[k];
			++k;
			io2->send_block(&pad, 1);
		}
	}

	void recv(block* data, int length, IO* io2, int s) {
		int k = s*length;
		block pad;
		for (int i = 0; i < length; ++i) {
			io2->recv_block(&pad, 1);
			data[i] = pre_data[k] ^ pad;
			++k;
		}
	}
};
#endif// _PRE_OT__
