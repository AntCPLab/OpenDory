#ifndef EMP_DORY_UTILS_H__
#define EMP_DORY_UTILS_H__

#include "emp-tool/emp-tool.h"

int comm(NetIO **ios, int threads) {
	int comm = 0;
	for (int i = 0; i < threads; i++) {
		comm += ios[i]->counter;
	}
	return comm;
}

#ifdef __AVX512F__
inline void mul128x4(__m512i a, __m512i b, __m512i *res1, __m512i *res2) {
	__m512i tmp3, tmp4, tmp5, tmp6;
	tmp3 = _mm512_clmulepi64_epi128(a, b, 0x00);
	tmp4 = _mm512_clmulepi64_epi128(a, b, 0x10);
	tmp5 = _mm512_clmulepi64_epi128(a, b, 0x01);
	tmp6 = _mm512_clmulepi64_epi128(a, b, 0x11);

	tmp4 = _mm512_xor_si512(tmp4, tmp5);
	tmp5 = _mm512_bslli_epi128(tmp4, 8);
	tmp4 = _mm512_bsrli_epi128(tmp4, 8);
	tmp3 = _mm512_xor_si512(tmp3, tmp5);
	tmp6 = _mm512_xor_si512(tmp6, tmp4);
	// initial mul now in tmp3, tmp6
	*res1 = tmp3;
	*res2 = tmp6;
}

inline __m512i reducex4(__m512i tmp3, __m512i tmp6) {//3 is low, 6 is high
	__m512i tmp7, tmp8, tmp9, tmp10, tmp11, tmp12;
	__m512i XMMMASK = _mm512_setr_epi32(0xffffffff, 0x0, 0x0, 0x0, 0xffffffff, 0x0, 0x0, 0x0, 0xffffffff, 0x0, 0x0, 0x0, 0xffffffff, 0x0, 0x0, 0x0);
	tmp7 = _mm512_srli_epi32(tmp6, 31); 
	tmp8 = _mm512_srli_epi32(tmp6, 30); 
	tmp9 = _mm512_srli_epi32(tmp6, 25);

	tmp7 = _mm512_xor_si512(tmp7, tmp8); 
	tmp7 = _mm512_xor_si512(tmp7, tmp9);

	tmp8 = _mm512_shuffle_epi32(tmp7, (_MM_PERM_ENUM)147);

	tmp7 = _mm512_and_si512(XMMMASK, tmp8);
	tmp8 = _mm512_andnot_si512(XMMMASK, tmp8);
	tmp3 = _mm512_xor_si512(tmp3, tmp8);
	tmp6 = _mm512_xor_si512(tmp6, tmp7);

	tmp10 = _mm512_slli_epi32(tmp6, 1);
	tmp3 = _mm512_xor_si512(tmp3, tmp10);
	tmp11 = _mm512_slli_epi32(tmp6, 2);
	tmp3 = _mm512_xor_si512(tmp3, tmp11); 
	tmp12 = _mm512_slli_epi32(tmp6, 7);
	tmp3 = _mm512_xor_si512(tmp3, tmp12);
	return _mm512_xor_si512(tmp3, tmp6);
}

inline void gfmulx4 (__m512i a, __m512i b, __m512i *res) {
	__m512i r1, r2;
	mul128x4(a, b, &r1, &r2);
	*res = reducex4(r1, r2);
}

#endif

template<int N>
inline void vector_gfmul (__m128i *res, const __m128i* a, const __m128i* b) {
#ifdef __AVX512F__
	for (int i = 0; i < N; i+=4) {
		__m512i a_pack = _mm512_loadu_si512((__m512i*)&a[i]);
		__m512i b_pack = _mm512_loadu_si512((__m512i*)&b[i]);
		__m512i tmp_res;
		gfmulx4(a_pack, b_pack, &tmp_res);
		_mm512_storeu_si512((__m512i*)&res[i], tmp_res);
	}
#else
	for (int i = 0; i < N; i++) {
		gfmul(a[i], b[i], res+i);
	}
#endif
}

template<int N>
inline void vector_gfmul (__m128i *res, const __m128i* a, __m128i b) {
#ifdef __AVX512F__
	__m512i b_pack = _mm512_setzero_si512();
	b_pack = _mm512_inserti32x4(b_pack, b, 0);
	b_pack = _mm512_inserti32x4(b_pack, b, 1);
	b_pack = _mm512_inserti32x4(b_pack, b, 2);
	b_pack = _mm512_inserti32x4(b_pack, b, 3);
	for (int i = 0; i < N; i+=4) {
		__m512i a_pack = _mm512_loadu_si512((__m512i*)&a[i]);
		__m512i tmp_res;
		gfmulx4(a_pack, b_pack, &tmp_res);
		_mm512_storeu_si512((__m512i*)&res[i], tmp_res);
	}
#else
	for (int i = 0; i < N; i++)
		gfmul(a[i], b, res+i);
#endif
}


#endif