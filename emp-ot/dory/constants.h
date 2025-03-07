#ifndef EMP_DORY_CONSTANTS_H__
#define EMP_DORY_CONSTANTS_H__

namespace emp { 
static std::string DORY_PRE_OT_DATA_REG_SEND_FILE = "./data/dory_pre_ot_data_reg_send";
static std::string DORY_PRE_OT_DATA_REG_RECV_FILE = "./data/dory_pre_ot_data_reg_recv";

class DualLPNParameter { public:
	int64_t n, t, log_bin_sz, n_pre, t_pre, log_bin_sz_pre;
	DualLPNParameter() {}
	DualLPNParameter(int64_t n, int64_t t, int64_t log_bin_sz, int64_t n_pre, int64_t t_pre, int64_t log_bin_sz_pre)
		: n(n), t(t), log_bin_sz(log_bin_sz),
		n_pre(n_pre), t_pre(t_pre), log_bin_sz_pre(log_bin_sz_pre) {

		if(n != t * (1<<log_bin_sz) ||
			n_pre != t_pre * (1<< log_bin_sz_pre) ||
			n_pre < t * log_bin_sz + 128 )
			error("LPN parameter not matched");	
	}
	int64_t buf_sz() const {
		return n - t * log_bin_sz - 128;
	}
};

// [TODO] These params need to be checked, especially for the second set of smaller LPN params.
const static DualLPNParameter dory_b13 = DualLPNParameter(10485760, 1280, 13, 23296, 91, 8);
const static DualLPNParameter dory_b12 = DualLPNParameter(10268672, 2507, 12, 30720, 120, 8);
const static DualLPNParameter dory_b11 = DualLPNParameter(10180608, 4971, 11, 55296, 108, 9);

}//namespace
#endif //EMP_DORY_CONSTANTS_H__
