#include "emp-ot/dory/cggm_sender.h"
#include "emp-ot/dory/cggm_recver.h"
#include "emp-ot/dory/base_cot.h"
using namespace std;

const static int batch_size = 1;

void print_ggm(block* ggm, int depth) {
    block sum = zero_block;
    for (int i = 0; i < (1 << (depth - 1)); i++) {
        std::cout << "[" << i << "]:\t" << ggm[i] << std::endl;
        sum ^= ggm[i];
    }
    std::cout << "sum: " << sum << std::endl;
    std::cout << std::endl;
}

void test_cggm(int party, NetIO* io) {
    BaseCot<NetIO> base_cot(party,io, false);
    base_cot.cot_gen_pre();
    block secret = base_cot.ot_delta;
    if (party == ALICE)
        std::cout << "Sender's secret: " << secret << std::endl;

    uint32_t depth = 10;
    OTPre<NetIO> pre_ot(io, (depth - 1) * batch_size, 1);
    base_cot.cot_gen(&pre_ot, pre_ot.n);

    if (party == ALICE) {
        CGGM_Sender<NetIO, batch_size> sender(nullptr, depth);
        pre_ot.choices_sender();

        sender.compute(secret);
        sender.send_f2k<OTPre<NetIO>>(&pre_ot, io, 0);

        io->send_block(&secret, 1);
        block acc;
        for (uint32_t w = 0; w < (1 << (depth - 1)); w++) {
            sender.acc_left(acc, 0, w);
            // std::cout << "[" << w << "]:\t" << acc << std::endl;

            io->send_block(&acc, 1);
        }
        std::cout << std::endl;
		io->flush();
    }
    else {
        CGGM_Recver<NetIO, batch_size> recver(nullptr, depth);

        pre_ot.choices_recver(recver.b);
        uint32_t* index = recver.get_index();
        std::cout << "Receiver's index: " << index[0] << std::endl;

        recver.recv_f2k<OTPre<NetIO>>(&pre_ot, io, 0);
        recver.compute();

        block sender_secret;
        io->recv_block(&sender_secret, 1);
        block acc;
        for (uint32_t w = 0; w < (1 << (depth - 1)); w++) {
            recver.acc_left(acc, 0, w);
            // std::cout << "[" << w << "]:\t" << acc << std::endl;

            block sender_acc;
            io->recv_block(&sender_acc, 1);
            if (w < index[0]) {
                if(!cmpBlock(&acc, &sender_acc, 1)) {
                    std::cout << "Inconsistent index: " << w << ",\t" << "Receiver Acc:\t" << acc << ",\tSender Acc:\t" << sender_acc << std::endl;
				    error("wrong!\n"); 
                }
            }
            else {
                sender_acc ^= sender_secret;
                if(!cmpBlock(&acc, &sender_acc, 1)) {
                    std::cout << "Inconsistent index: " << w << ",\t" << "Receiver Acc:\t" << acc <<  ",\tSender Acc:\t" << sender_acc << std::endl;
				    error("wrong!\n");
                }
            }
        }
        std::cout << std::endl;
    }
    
}

int main(int argc, char** argv) {
    int party, port;
    parse_party_and_port(argv, &party, &port);
	NetIO* io;
    io = new NetIO(party == ALICE?nullptr:"127.0.0.1",port);

	test_cggm(party, io);

    delete io;
}