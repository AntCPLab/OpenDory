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
	block * unit_offsets;
	bool * unit_choices;

	block * pre_data = nullptr;
	bool * bits = nullptr;
	bool * d = nullptr;

	int n, unit_length, n_units;
	int count;
	block global_delta;

	SimpleOTPre<IO>* preot;

	PRG prg;

	DoryOTPre(SimpleOTPre<IO>* preot) {
		this->preot = preot;
		n_units = preot->n / preot->unit_length;
		unit_length = preot->unit_length - 1;
		n = unit_length * n_units;
		io = preot->io;
		
		unit_offsets = new block[n_units];
		unit_choices = new bool[n_units];

		pre_data = new block[n];
		bits = new bool[n];
		d = new bool[n];

		global_delta = preot->Delta;
		count = 0;
	}

	~DoryOTPre() {
		if (pre_data != nullptr)
			delete[] pre_data;

		if (bits != nullptr)
			delete[] bits;

		if (d != nullptr)
			delete[] d;

		if (unit_offsets != nullptr)
			delete[] unit_offsets;
		
		if (unit_choices != nullptr)
			delete[] unit_choices;
	}

	void sender_refactor() {
		// bool* d = new bool[n];
		io->recv_bool(d, n * sizeof(bool));

		for (int i = 0; i < n_units; i++) {
			unit_offsets[i] = preot->pre_data[i * preot->unit_length];
			for (int j = 0; j < unit_length; j++) {
				pre_data[i * unit_length + j] = preot->pre_data[i * preot->unit_length + 1 + j];
				if (d[i * unit_length + j]) {
					pre_data[i * unit_length + j] ^= global_delta;
				}
			}
		}
		// delete[] d;

		// io->send_block(pre_data, n);
		// io->send_block(unit_offsets, n_units);
	}

	void receiver_refactor() {

		// Sample new choice bits
		prg.random_bool(bits, n);
		
		// bool* d = new bool[n];
		for (int i = 0; i < n_units; i++) {
			unit_choices[i] = preot->bits[i * preot->unit_length];
			unit_offsets[i] = preot->pre_data[i * preot->unit_length];
			for (int j = 0; j < unit_length; j++) {
				d[i * unit_length + j] = preot->bits[i * preot->unit_length + 1 + j];
				pre_data[i * unit_length + j] = preot->pre_data[i * preot->unit_length + 1 + j];
				if (bits[i * unit_length + j]) {
					d[i * unit_length + j] ^= unit_choices[i];
					pre_data[i * unit_length + j] ^= unit_offsets[i];
				}
			}
		}
		io->send_bool(d, n * sizeof(bool));
		io->flush();
		// delete[] d;

		// std::cout << "n=" << n << ", unit length = " << unit_length << std::endl;
		// block* sender_blocks = new block[n];
		// block* sender_offsets = new block[n_units];
		// io->recv_block(sender_blocks, n);
		// io->recv_block(sender_offsets, n_units);
		// for (int i = 0; i < n_units; i++) {
		// 	for (int j = 0; j < unit_length; j++) {
		// 		block sblock = sender_blocks[i * unit_length + j];
		// 		if (bits[i * unit_length + j])
		// 			sblock ^= sender_offsets[i];
		// 		if (!cmpBlock(&pre_data[i * unit_length + j], &sblock, 1)) {
		// 			std::cout << "dory preot data: " << pre_data[i * unit_length + j] << ",\t" << "sblock:\t" << sblock << std::endl;
		// 			error("wrong!\n");
		// 		}
		// 	}
		// }

		// delete[] sender_blocks;
		// delete[] sender_offsets;
	}

	block unit_offset(int s) {
		return unit_offsets[s];
	}

	bool unit_choice(int s) {
		return unit_choices[s];
	}

	// void choices_sender(int length) {
	// 	count += length;
	// }

	// void choices_recver(bool * b, int length) {
	// 	memcpy(b, bits + count, length * sizeof(bool));
	// 	count += length;
	// }

	template<int B>
	void choices_sender() {
		int length = unit_length * B;
		count += length;
	}

	/**
	 * `b` in a view of `unit_length x B`,
	 * `bits` in a view of `B x unit_length`.
	 * Check `send/recv` for further explanation.
	*/
	template<int B>
	void choices_recver(bool * b) {
		int length = unit_length * B;
		for (int i = 0; i < length; i++) {
			int bits_idx = (i % B) * unit_length + (i / B);
			b[i] = bits[count + bits_idx];
		}
		count += length;
	}
	
	void reset() {
		count = 0;
	}

	// void send(const block* m, int length, IO* io2, int start_unit) {
	// 	block pad;
	// 	int k = start_unit * unit_length;
	// 	for (int i = 0; i < length; ++i) {
	// 		pad = m[i] ^ pre_data[k];
	// 		++k;
	// 		io2->send_block(&pad, 1);
	// 	}
	// }

	// void recv(block* data, int length, IO* io2, int start_unit) {
	// 	int k = start_unit * unit_length;

	// 	io2->recv_block(data, length);
	// 	for (int i = 0; i < length; ++i) {
	// 		data[i] ^= pre_data[k];
	// 		++k;
	// 	}
	// }

	/**
	 * View input `m` as a matrix of `unit_length x B`.
	 * Note that `pre_data` stores blocks in a way of `B x unit_length` ,
	 * hence `m` and `pre_data` are representing data in a transposed manner.
	 * 
	 * @param B: Number of units to process, each unit has length of `unit_length`
	*/
	template<int B>
	void send(const block* m, IO* io2, int start_unit) {
		block pad;
		int k = start_unit * unit_length;
		
		// 	for (int i = 0; i < length; ++i) {
		// 		pad = m[i] ^ pre_data[k];
		// 		++k;
		// 		io2->send_block(&pad, 1);
		// 	}
		// }
		// for (int i = 0; i < B; i++) {
		// 	for (int j = 0; j < unit_length; j++) {
		// 		pad = m[j * B + i] ^ pre_data[k + i * unit_length + j];
		// 	}
		// }
		int length = unit_length * B;
		for (int i = 0; i < length; i++) {
			int pre_data_idx = (i % B) * unit_length + (i / B);
			pad = m[i] ^ pre_data[k + pre_data_idx];
			io2->send_block(&pad, 1);
		}
	}

	/**
	 * View output `m` as a matrix of `unit_length x B`.
	 * Note that `pre_data` stores blocks in a way of `B x unit_length` ,
	 * hence `m` and `pre_data` are representing data in a transposed manner.
	 * 
	 * @param B: Number of units to process, each unit has length of `unit_length`
	*/
	template<int B>
	void recv(block* m, IO* io2, int start_unit) {
		int k = start_unit * unit_length;

		// io2->recv_block(data, length);
		// for (int i = 0; i < length; ++i) {
		// 	data[i] ^= pre_data[k];
		// 	++k;
		// }

		int length = unit_length * B;
		io2->recv_block(m, length);
		for (int i = 0; i < length; i++) {
			int pre_data_idx = (i % B) * unit_length + (i / B);
			m[i] ^= pre_data[k + pre_data_idx];
		}
	}
};
#endif// _DORY_PRE_OT__
