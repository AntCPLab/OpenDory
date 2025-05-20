#ifndef EMP_DORY_CONSTANTS_H__
#define EMP_DORY_CONSTANTS_H__

namespace emp { 
static std::string DORY_PRE_OT_DATA_REG_SEND_FILE = "./data/dory_pre_ot_data_reg_send";
static std::string DORY_PRE_OT_DATA_REG_RECV_FILE = "./data/dory_pre_ot_data_reg_recv";

// class DualLPNParameter { public:
// 	int64_t n, t, log_bin_sz, n_pre, t_pre, log_bin_sz_pre, ell;
// 	DualLPNParameter() {}
// 	DualLPNParameter(int64_t n, int64_t t, int64_t log_bin_sz, int64_t n_pre, int64_t t_pre, int64_t log_bin_sz_pre, int64_t ell)
// 		: n(n), t(t), log_bin_sz(log_bin_sz),
// 		n_pre(n_pre), t_pre(t_pre), log_bin_sz_pre(log_bin_sz_pre), ell(ell) {

// 		if(n != t * (1<<log_bin_sz) ||
// 			n_pre != t_pre * (1<< log_bin_sz_pre) ||
// 			n_pre < t * log_bin_sz + 128 )
// 			error("LPN parameter not matched");	
// 	}
// 	int64_t buf_sz() const {
// 		return n - t * log_bin_sz - 128;
// 	}

// 	int limit() {
// 		return n / 5;
// 	}
// };

// // [TODO] These params need to be checked, especially for the second set of smaller LPN params.
// const static DualLPNParameter dory_b13 = DualLPNParameter(10485760, 1280, 13, 23296, 91, 8, 7);
// const static DualLPNParameter dory_b12 = DualLPNParameter(10268672, 2507, 12, 30720, 120, 8, 7);
// const static DualLPNParameter dory_b11 = DualLPNParameter(10180608, 4971, 11, 55296, 108, 9, 7);

class DualLPNParameter { public:
	int64_t n, t, log_bin_sz, ell;
	DualLPNParameter() {}
	DualLPNParameter(int64_t n, int64_t t, int64_t log_bin_sz, int64_t ell)
		: n(n), t(t), log_bin_sz(log_bin_sz), ell(ell) {

		if(n != t * (1<<log_bin_sz))
			error("LPN parameter not matched");	
	}

	int64_t pre_ot_size() {
		return t * (log_bin_sz + 1) + 128;
	}

	int ot_limit() const {
		return n / 5;
	}
};

// void verify_params_validity(DualLPNParameter large, DualLPNParameter pre) {
// 	if (pre.ot_limit() < large.pre_ot_size())
// 		error("LPN parameter not matched");
// }

const static DualLPNParameter dory_b13 = DualLPNParameter(9781248, 1194, 13, 7);
// const static DualLPNParameter dory_b13_pre = DualLPNParameter(93184, 91, 10, 7);

const static DualLPNParameter dory_b18 = DualLPNParameter(293601280, 1120, 18, 9);
// const static DualLPNParameter dory_b12_pre = DualLPNParameter(30720, 120, 8, 7);

const static DualLPNParameter dory_b23 = DualLPNParameter(8707375104, 1038, 23, 11);
// const static DualLPNParameter dory_b11_pre = DualLPNParameter(55296, 108, 9, 7);


const static DualLPNParameter dory_test_param = DualLPNParameter(128, 16, 3, 7);



}//namespace
#endif //EMP_DORY_CONSTANTS_H__
