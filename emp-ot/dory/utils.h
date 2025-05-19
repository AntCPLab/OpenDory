#ifndef EMP_DORY_UTILS_H__
#define EMP_DORY_UTILS_H__

#include "emp-tool/emp-tool.h"

template<int N>
inline void vector_gfmul (__m128i *res, const __m128i* a, const __m128i* b) {
	for (int i = 0; i < N; i++)
		gfmul(a[i], b[i], res+i);
}

template<int N>
inline void vector_gfmul (__m128i *res, const __m128i* a, __m128i b) {
	for (int i = 0; i < N; i++)
		gfmul(a[i], b, res+i);
}


#endif