// SPDX-License-Identifier: BSD-3-Clause

// @see:
//   - <https://github.com/lemire/simdcomp>

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <immintrin.h>

namespace riot::bitpack {

namespace detail {

namespace {

inline void pack256_0( std::uint32_t const*, __m256i* ) noexcept {}

/* pack 256 1-bit values, touching 1 256-bit words, using 16
 * bytes */
inline void pack256_1( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  1 256-bit word */
  __m256i w0;
  w0 = _mm256_lddqu_si256( in + 0 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 1 ), 1 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 2 ), 2 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 3 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 4 ), 4 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 5 ), 5 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 6 ), 6 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 7 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 8 ), 8 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 9 ), 9 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 10 ), 10 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 11 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 12 ), 12 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 13 ), 13 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 14 ), 14 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 15 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 16 ), 16 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 17 ), 17 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 18 ), 18 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 19 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 20 ), 20 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 21 ), 21 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 22 ), 22 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 23 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 24 ), 24 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 25 ), 25 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 26 ), 26 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 27 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 28 ), 28 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 29 ), 29 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 30 ), 30 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 31 ) );
  _mm256_storeu_si256( compressed + 0, w0 );
}

/* pack 256 2-bit values, touching 2 256-bit words, using 32
 * bytes */
inline void pack256_2( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  2 256-bit words */
  __m256i w0, w1;
  w0 = _mm256_lddqu_si256( in + 0 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 1 ), 2 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 2 ), 4 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 6 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 4 ), 8 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 5 ), 10 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 6 ), 12 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 14 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 8 ), 16 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 9 ), 18 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 10 ), 20 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 22 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 12 ), 24 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 13 ), 26 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 14 ), 28 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 30 ) );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_lddqu_si256( in + 16 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 17 ), 2 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 18 ), 4 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 6 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 20 ), 8 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 21 ), 10 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 22 ), 12 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 14 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 24 ), 16 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 25 ), 18 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 26 ), 20 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 22 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 28 ), 24 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 29 ), 26 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 30 ), 28 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 30 ) );
  _mm256_storeu_si256( compressed + 1, w1 );
}

/* pack 256 3-bit values, touching 3 256-bit words, using 48
 * bytes */
inline void pack256_3( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  3 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 1 ), 3 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 2 ), 6 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 9 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 4 ), 12 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 5 ), 15 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 6 ), 18 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 21 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 8 ), 24 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 9 ), 27 ) );
  tmp = _mm256_lddqu_si256( in + 10 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 30 ) );
  w1 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 1 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 12 ), 4 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 13 ), 7 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 14 ), 10 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 13 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 16 ), 16 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 17 ), 19 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 18 ), 22 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 25 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 20 ), 28 ) );
  tmp = _mm256_lddqu_si256( in + 21 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 31 ) );
  w0 = _mm256_srli_epi32( tmp, 1 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 22 ), 2 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 5 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 24 ), 8 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 25 ), 11 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 26 ), 14 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 17 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 28 ), 20 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 29 ), 23 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 30 ), 26 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 29 ) );
  _mm256_storeu_si256( compressed + 2, w0 );
}

/* pack 256 4-bit values, touching 4 256-bit words, using 64
 * bytes */
inline void pack256_4( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  4 256-bit words */
  __m256i w0, w1;
  w0 = _mm256_lddqu_si256( in + 0 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 1 ), 4 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 2 ), 8 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 12 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 4 ), 16 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 5 ), 20 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 6 ), 24 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 28 ) );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_lddqu_si256( in + 8 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 9 ), 4 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 10 ), 8 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 12 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 12 ), 16 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 13 ), 20 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 14 ), 24 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 28 ) );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_lddqu_si256( in + 16 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 17 ), 4 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 18 ), 8 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 12 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 20 ), 16 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 21 ), 20 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 22 ), 24 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 28 ) );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_lddqu_si256( in + 24 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 25 ), 4 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 26 ), 8 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 12 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 28 ), 16 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 29 ), 20 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 30 ), 24 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 28 ) );
  _mm256_storeu_si256( compressed + 3, w1 );
}

/* pack 256 5-bit values, touching 5 256-bit words, using 80
 * bytes */
inline void pack256_5( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  5 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 1 ), 5 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 2 ), 10 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 15 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 4 ), 20 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 5 ), 25 ) );
  tmp = _mm256_lddqu_si256( in + 6 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 30 ) );
  w1 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 3 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 8 ), 8 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 9 ), 13 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 10 ), 18 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 23 ) );
  tmp = _mm256_lddqu_si256( in + 12 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 13 ), 1 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 14 ), 6 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 11 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 16 ), 16 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 17 ), 21 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 18 ), 26 ) );
  tmp = _mm256_lddqu_si256( in + 19 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 31 ) );
  w1 = _mm256_srli_epi32( tmp, 1 );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 20 ), 4 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 21 ), 9 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 22 ), 14 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 19 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 24 ), 24 ) );
  tmp = _mm256_lddqu_si256( in + 25 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 29 ) );
  w0 = _mm256_srli_epi32( tmp, 3 );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 26 ), 2 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 7 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 28 ), 12 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 29 ), 17 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 30 ), 22 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 27 ) );
  _mm256_storeu_si256( compressed + 4, w0 );
}

/* pack 256 6-bit values, touching 6 256-bit words, using 96
 * bytes */
inline void pack256_6( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  6 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 1 ), 6 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 2 ), 12 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 18 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 4 ), 24 ) );
  tmp = _mm256_lddqu_si256( in + 5 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 30 ) );
  w1 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 6 ), 4 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 10 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 8 ), 16 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 9 ), 22 ) );
  tmp = _mm256_lddqu_si256( in + 10 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 2 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 12 ), 8 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 13 ), 14 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 14 ), 20 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 26 ) );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_lddqu_si256( in + 16 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 17 ), 6 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 18 ), 12 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 18 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 20 ), 24 ) );
  tmp = _mm256_lddqu_si256( in + 21 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 30 ) );
  w0 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 22 ), 4 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 10 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 24 ), 16 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 25 ), 22 ) );
  tmp = _mm256_lddqu_si256( in + 26 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 2 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 28 ), 8 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 29 ), 14 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 30 ), 20 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 26 ) );
  _mm256_storeu_si256( compressed + 5, w1 );
}

/* pack 256 7-bit values, touching 7 256-bit words, using 112
 * bytes */
inline void pack256_7( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  7 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 1 ), 7 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 2 ), 14 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 21 ) );
  tmp = _mm256_lddqu_si256( in + 4 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 5 ), 3 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 6 ), 10 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 17 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 8 ), 24 ) );
  tmp = _mm256_lddqu_si256( in + 9 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 31 ) );
  w0 = _mm256_srli_epi32( tmp, 1 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 10 ), 6 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 13 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 12 ), 20 ) );
  tmp = _mm256_lddqu_si256( in + 13 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 27 ) );
  w1 = _mm256_srli_epi32( tmp, 5 );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 14 ), 2 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 9 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 16 ), 16 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 17 ), 23 ) );
  tmp = _mm256_lddqu_si256( in + 18 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 30 ) );
  w0 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 5 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 20 ), 12 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 21 ), 19 ) );
  tmp = _mm256_lddqu_si256( in + 22 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 26 ) );
  w1 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 1 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 24 ), 8 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 25 ), 15 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 26 ), 22 ) );
  tmp = _mm256_lddqu_si256( in + 27 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 29 ) );
  w0 = _mm256_srli_epi32( tmp, 3 );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 28 ), 4 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 29 ), 11 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 30 ), 18 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 25 ) );
  _mm256_storeu_si256( compressed + 6, w0 );
}

/* pack 256 8-bit values, touching 8 256-bit words, using 128
 * bytes */
inline void pack256_8( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  8 256-bit words */
  __m256i w0, w1;
  w0 = _mm256_lddqu_si256( in + 0 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 1 ), 8 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 2 ), 16 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 24 ) );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_lddqu_si256( in + 4 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 5 ), 8 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 6 ), 16 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 24 ) );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_lddqu_si256( in + 8 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 9 ), 8 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 10 ), 16 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 24 ) );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_lddqu_si256( in + 12 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 13 ), 8 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 14 ), 16 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 24 ) );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_lddqu_si256( in + 16 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 17 ), 8 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 18 ), 16 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 24 ) );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_lddqu_si256( in + 20 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 21 ), 8 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 22 ), 16 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 24 ) );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_lddqu_si256( in + 24 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 25 ), 8 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 26 ), 16 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 24 ) );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_lddqu_si256( in + 28 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 29 ), 8 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 30 ), 16 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 24 ) );
  _mm256_storeu_si256( compressed + 7, w1 );
}

/* pack 256 9-bit values, touching 9 256-bit words, using 144
 * bytes */
inline void pack256_9( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  9 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 1 ), 9 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 2 ), 18 ) );
  tmp = _mm256_lddqu_si256( in + 3 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 27 ) );
  w1 = _mm256_srli_epi32( tmp, 5 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 4 ), 4 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 5 ), 13 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 6 ), 22 ) );
  tmp = _mm256_lddqu_si256( in + 7 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 31 ) );
  w0 = _mm256_srli_epi32( tmp, 1 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 8 ), 8 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 9 ), 17 ) );
  tmp = _mm256_lddqu_si256( in + 10 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 26 ) );
  w1 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 3 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 12 ), 12 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 13 ), 21 ) );
  tmp = _mm256_lddqu_si256( in + 14 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 30 ) );
  w0 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 7 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 16 ), 16 ) );
  tmp = _mm256_lddqu_si256( in + 17 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 25 ) );
  w1 = _mm256_srli_epi32( tmp, 7 );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 18 ), 2 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 11 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 20 ), 20 ) );
  tmp = _mm256_lddqu_si256( in + 21 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 29 ) );
  w0 = _mm256_srli_epi32( tmp, 3 );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 22 ), 6 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 15 ) );
  tmp = _mm256_lddqu_si256( in + 24 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 25 ), 1 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 26 ), 10 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 19 ) );
  tmp = _mm256_lddqu_si256( in + 28 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 7, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 29 ), 5 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 30 ), 14 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 23 ) );
  _mm256_storeu_si256( compressed + 8, w0 );
}

/* pack 256 10-bit values, touching 10 256-bit words, using 160
 * bytes */
inline void pack256_10( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  10 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 1 ), 10 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 2 ), 20 ) );
  tmp = _mm256_lddqu_si256( in + 3 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 30 ) );
  w1 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 4 ), 8 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 5 ), 18 ) );
  tmp = _mm256_lddqu_si256( in + 6 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 6 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 8 ), 16 ) );
  tmp = _mm256_lddqu_si256( in + 9 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 26 ) );
  w1 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 10 ), 4 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 14 ) );
  tmp = _mm256_lddqu_si256( in + 12 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 13 ), 2 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 14 ), 12 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 22 ) );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_lddqu_si256( in + 16 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 17 ), 10 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 18 ), 20 ) );
  tmp = _mm256_lddqu_si256( in + 19 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 30 ) );
  w0 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 20 ), 8 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 21 ), 18 ) );
  tmp = _mm256_lddqu_si256( in + 22 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 6 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 24 ), 16 ) );
  tmp = _mm256_lddqu_si256( in + 25 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 26 ) );
  w0 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 7, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 26 ), 4 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 14 ) );
  tmp = _mm256_lddqu_si256( in + 28 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 8, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 29 ), 2 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 30 ), 12 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 22 ) );
  _mm256_storeu_si256( compressed + 9, w1 );
}

/* pack 256 11-bit values, touching 11 256-bit words, using 176
 * bytes */
inline void pack256_11( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  11 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 1 ), 11 ) );
  tmp = _mm256_lddqu_si256( in + 2 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 22 ) );
  w1 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 1 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 4 ), 12 ) );
  tmp = _mm256_lddqu_si256( in + 5 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 23 ) );
  w0 = _mm256_srli_epi32( tmp, 9 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 6 ), 2 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 13 ) );
  tmp = _mm256_lddqu_si256( in + 8 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 9 ), 3 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 10 ), 14 ) );
  tmp = _mm256_lddqu_si256( in + 11 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 25 ) );
  w0 = _mm256_srli_epi32( tmp, 7 );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 12 ), 4 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 13 ), 15 ) );
  tmp = _mm256_lddqu_si256( in + 14 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 26 ) );
  w1 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 5 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 16 ), 16 ) );
  tmp = _mm256_lddqu_si256( in + 17 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 27 ) );
  w0 = _mm256_srli_epi32( tmp, 5 );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 18 ), 6 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 17 ) );
  tmp = _mm256_lddqu_si256( in + 20 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 21 ), 7 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 22 ), 18 ) );
  tmp = _mm256_lddqu_si256( in + 23 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 29 ) );
  w0 = _mm256_srli_epi32( tmp, 3 );
  _mm256_storeu_si256( compressed + 7, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 24 ), 8 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 25 ), 19 ) );
  tmp = _mm256_lddqu_si256( in + 26 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 30 ) );
  w1 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 8, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 9 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 28 ), 20 ) );
  tmp = _mm256_lddqu_si256( in + 29 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 31 ) );
  w0 = _mm256_srli_epi32( tmp, 1 );
  _mm256_storeu_si256( compressed + 9, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 30 ), 10 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 21 ) );
  _mm256_storeu_si256( compressed + 10, w0 );
}

/* pack 256 12-bit values, touching 12 256-bit words, using 192
 * bytes */
inline void pack256_12( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  12 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 1 ), 12 ) );
  tmp = _mm256_lddqu_si256( in + 2 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 4 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 4 ), 16 ) );
  tmp = _mm256_lddqu_si256( in + 5 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 6 ), 8 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 20 ) );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_lddqu_si256( in + 8 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 9 ), 12 ) );
  tmp = _mm256_lddqu_si256( in + 10 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 4 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 12 ), 16 ) );
  tmp = _mm256_lddqu_si256( in + 13 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 14 ), 8 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 20 ) );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_lddqu_si256( in + 16 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 17 ), 12 ) );
  tmp = _mm256_lddqu_si256( in + 18 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 4 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 20 ), 16 ) );
  tmp = _mm256_lddqu_si256( in + 21 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 7, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 22 ), 8 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 20 ) );
  _mm256_storeu_si256( compressed + 8, w0 );
  w1 = _mm256_lddqu_si256( in + 24 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 25 ), 12 ) );
  tmp = _mm256_lddqu_si256( in + 26 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 9, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 4 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 28 ), 16 ) );
  tmp = _mm256_lddqu_si256( in + 29 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 10, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 30 ), 8 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 20 ) );
  _mm256_storeu_si256( compressed + 11, w1 );
}

/* pack 256 13-bit values, touching 13 256-bit words, using 208
 * bytes */
inline void pack256_13( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  13 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 1 ), 13 ) );
  tmp = _mm256_lddqu_si256( in + 2 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 26 ) );
  w1 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 7 ) );
  tmp = _mm256_lddqu_si256( in + 4 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 20 ) );
  w0 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 5 ), 1 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 6 ), 14 ) );
  tmp = _mm256_lddqu_si256( in + 7 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 27 ) );
  w1 = _mm256_srli_epi32( tmp, 5 );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 8 ), 8 ) );
  tmp = _mm256_lddqu_si256( in + 9 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 21 ) );
  w0 = _mm256_srli_epi32( tmp, 11 );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 10 ), 2 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 15 ) );
  tmp = _mm256_lddqu_si256( in + 12 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 13 ), 9 ) );
  tmp = _mm256_lddqu_si256( in + 14 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 22 ) );
  w0 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 3 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 16 ), 16 ) );
  tmp = _mm256_lddqu_si256( in + 17 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 29 ) );
  w1 = _mm256_srli_epi32( tmp, 3 );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 18 ), 10 ) );
  tmp = _mm256_lddqu_si256( in + 19 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 23 ) );
  w0 = _mm256_srli_epi32( tmp, 9 );
  _mm256_storeu_si256( compressed + 7, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 20 ), 4 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 21 ), 17 ) );
  tmp = _mm256_lddqu_si256( in + 22 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 30 ) );
  w1 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 8, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 11 ) );
  tmp = _mm256_lddqu_si256( in + 24 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 9, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 25 ), 5 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 26 ), 18 ) );
  tmp = _mm256_lddqu_si256( in + 27 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 31 ) );
  w1 = _mm256_srli_epi32( tmp, 1 );
  _mm256_storeu_si256( compressed + 10, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 28 ), 12 ) );
  tmp = _mm256_lddqu_si256( in + 29 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 25 ) );
  w0 = _mm256_srli_epi32( tmp, 7 );
  _mm256_storeu_si256( compressed + 11, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 30 ), 6 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 19 ) );
  _mm256_storeu_si256( compressed + 12, w0 );
}

/* pack 256 14-bit values, touching 14 256-bit words, using 224
 * bytes */
inline void pack256_14( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  14 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 1 ), 14 ) );
  tmp = _mm256_lddqu_si256( in + 2 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 10 ) );
  tmp = _mm256_lddqu_si256( in + 4 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 5 ), 6 ) );
  tmp = _mm256_lddqu_si256( in + 6 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 20 ) );
  w1 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 2 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 8 ), 16 ) );
  tmp = _mm256_lddqu_si256( in + 9 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 30 ) );
  w0 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 10 ), 12 ) );
  tmp = _mm256_lddqu_si256( in + 11 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 26 ) );
  w1 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 12 ), 8 ) );
  tmp = _mm256_lddqu_si256( in + 13 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 22 ) );
  w0 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 14 ), 4 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 18 ) );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_lddqu_si256( in + 16 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 17 ), 14 ) );
  tmp = _mm256_lddqu_si256( in + 18 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 7, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 10 ) );
  tmp = _mm256_lddqu_si256( in + 20 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 8, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 21 ), 6 ) );
  tmp = _mm256_lddqu_si256( in + 22 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 20 ) );
  w0 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 9, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 2 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 24 ), 16 ) );
  tmp = _mm256_lddqu_si256( in + 25 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 30 ) );
  w1 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 10, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 26 ), 12 ) );
  tmp = _mm256_lddqu_si256( in + 27 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 26 ) );
  w0 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 11, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 28 ), 8 ) );
  tmp = _mm256_lddqu_si256( in + 29 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 22 ) );
  w1 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 12, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 30 ), 4 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 18 ) );
  _mm256_storeu_si256( compressed + 13, w1 );
}

/* pack 256 15-bit values, touching 15 256-bit words, using 240
 * bytes */
inline void pack256_15( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  15 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 1 ), 15 ) );
  tmp = _mm256_lddqu_si256( in + 2 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 30 ) );
  w1 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 13 ) );
  tmp = _mm256_lddqu_si256( in + 4 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 5 ), 11 ) );
  tmp = _mm256_lddqu_si256( in + 6 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 26 ) );
  w1 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 9 ) );
  tmp = _mm256_lddqu_si256( in + 8 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 9 ), 7 ) );
  tmp = _mm256_lddqu_si256( in + 10 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 22 ) );
  w1 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 5 ) );
  tmp = _mm256_lddqu_si256( in + 12 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 20 ) );
  w0 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 13 ), 3 ) );
  tmp = _mm256_lddqu_si256( in + 14 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 18 ) );
  w1 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 1 ) );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 16 ), 16 ) );
  tmp = _mm256_lddqu_si256( in + 17 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 31 ) );
  w0 = _mm256_srli_epi32( tmp, 1 );
  _mm256_storeu_si256( compressed + 7, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 18 ), 14 ) );
  tmp = _mm256_lddqu_si256( in + 19 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 29 ) );
  w1 = _mm256_srli_epi32( tmp, 3 );
  _mm256_storeu_si256( compressed + 8, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 20 ), 12 ) );
  tmp = _mm256_lddqu_si256( in + 21 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 27 ) );
  w0 = _mm256_srli_epi32( tmp, 5 );
  _mm256_storeu_si256( compressed + 9, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 22 ), 10 ) );
  tmp = _mm256_lddqu_si256( in + 23 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 25 ) );
  w1 = _mm256_srli_epi32( tmp, 7 );
  _mm256_storeu_si256( compressed + 10, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 24 ), 8 ) );
  tmp = _mm256_lddqu_si256( in + 25 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 23 ) );
  w0 = _mm256_srli_epi32( tmp, 9 );
  _mm256_storeu_si256( compressed + 11, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 26 ), 6 ) );
  tmp = _mm256_lddqu_si256( in + 27 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 21 ) );
  w1 = _mm256_srli_epi32( tmp, 11 );
  _mm256_storeu_si256( compressed + 12, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 28 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 29 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 19 ) );
  w0 = _mm256_srli_epi32( tmp, 13 );
  _mm256_storeu_si256( compressed + 13, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 30 ), 2 ) );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 17 ) );
  _mm256_storeu_si256( compressed + 14, w0 );
}

/* pack 256 16-bit values, touching 16 256-bit words, using 256
 * bytes */
inline void pack256_16( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  16 256-bit words */
  __m256i w0, w1;
  w0 = _mm256_lddqu_si256( in + 0 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 1 ), 16 ) );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_lddqu_si256( in + 2 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 16 ) );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_lddqu_si256( in + 4 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 5 ), 16 ) );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_lddqu_si256( in + 6 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 16 ) );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_lddqu_si256( in + 8 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 9 ), 16 ) );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_lddqu_si256( in + 10 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 16 ) );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_lddqu_si256( in + 12 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 13 ), 16 ) );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_lddqu_si256( in + 14 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 16 ) );
  _mm256_storeu_si256( compressed + 7, w1 );
  w0 = _mm256_lddqu_si256( in + 16 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 17 ), 16 ) );
  _mm256_storeu_si256( compressed + 8, w0 );
  w1 = _mm256_lddqu_si256( in + 18 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 16 ) );
  _mm256_storeu_si256( compressed + 9, w1 );
  w0 = _mm256_lddqu_si256( in + 20 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 21 ), 16 ) );
  _mm256_storeu_si256( compressed + 10, w0 );
  w1 = _mm256_lddqu_si256( in + 22 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 16 ) );
  _mm256_storeu_si256( compressed + 11, w1 );
  w0 = _mm256_lddqu_si256( in + 24 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 25 ), 16 ) );
  _mm256_storeu_si256( compressed + 12, w0 );
  w1 = _mm256_lddqu_si256( in + 26 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 16 ) );
  _mm256_storeu_si256( compressed + 13, w1 );
  w0 = _mm256_lddqu_si256( in + 28 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 29 ), 16 ) );
  _mm256_storeu_si256( compressed + 14, w0 );
  w1 = _mm256_lddqu_si256( in + 30 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 16 ) );
  _mm256_storeu_si256( compressed + 15, w1 );
}

/* pack 256 17-bit values, touching 17 256-bit words, using 272
 * bytes */
inline void pack256_17( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  17 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  tmp = _mm256_lddqu_si256( in + 1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 17 ) );
  w1 = _mm256_srli_epi32( tmp, 15 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 2 ), 2 ) );
  tmp = _mm256_lddqu_si256( in + 3 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 19 ) );
  w0 = _mm256_srli_epi32( tmp, 13 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 4 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 5 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 21 ) );
  w1 = _mm256_srli_epi32( tmp, 11 );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 6 ), 6 ) );
  tmp = _mm256_lddqu_si256( in + 7 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 23 ) );
  w0 = _mm256_srli_epi32( tmp, 9 );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 8 ), 8 ) );
  tmp = _mm256_lddqu_si256( in + 9 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 25 ) );
  w1 = _mm256_srli_epi32( tmp, 7 );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 10 ), 10 ) );
  tmp = _mm256_lddqu_si256( in + 11 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 27 ) );
  w0 = _mm256_srli_epi32( tmp, 5 );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 12 ), 12 ) );
  tmp = _mm256_lddqu_si256( in + 13 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 29 ) );
  w1 = _mm256_srli_epi32( tmp, 3 );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 14 ), 14 ) );
  tmp = _mm256_lddqu_si256( in + 15 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 31 ) );
  w0 = _mm256_srli_epi32( tmp, 1 );
  _mm256_storeu_si256( compressed + 7, w1 );
  tmp = _mm256_lddqu_si256( in + 16 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 16 ) );
  w1 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 8, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 17 ), 1 ) );
  tmp = _mm256_lddqu_si256( in + 18 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 18 ) );
  w0 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 9, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 3 ) );
  tmp = _mm256_lddqu_si256( in + 20 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 20 ) );
  w1 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 10, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 21 ), 5 ) );
  tmp = _mm256_lddqu_si256( in + 22 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 22 ) );
  w0 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 11, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 7 ) );
  tmp = _mm256_lddqu_si256( in + 24 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 12, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 25 ), 9 ) );
  tmp = _mm256_lddqu_si256( in + 26 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 26 ) );
  w0 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 13, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 11 ) );
  tmp = _mm256_lddqu_si256( in + 28 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 14, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 29 ), 13 ) );
  tmp = _mm256_lddqu_si256( in + 30 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 30 ) );
  w0 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 15, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 15 ) );
  _mm256_storeu_si256( compressed + 16, w0 );
}

/* pack 256 18-bit values, touching 18 256-bit words, using 288
 * bytes */
inline void pack256_18( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  18 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  tmp = _mm256_lddqu_si256( in + 1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 18 ) );
  w1 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 2 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 3 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 22 ) );
  w0 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 4 ), 8 ) );
  tmp = _mm256_lddqu_si256( in + 5 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 26 ) );
  w1 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 6 ), 12 ) );
  tmp = _mm256_lddqu_si256( in + 7 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 30 ) );
  w0 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 3, w1 );
  tmp = _mm256_lddqu_si256( in + 8 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 16 ) );
  w1 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 9 ), 2 ) );
  tmp = _mm256_lddqu_si256( in + 10 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 20 ) );
  w0 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 6 ) );
  tmp = _mm256_lddqu_si256( in + 12 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 13 ), 10 ) );
  tmp = _mm256_lddqu_si256( in + 14 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 7, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 14 ) );
  _mm256_storeu_si256( compressed + 8, w0 );
  w1 = _mm256_lddqu_si256( in + 16 );
  tmp = _mm256_lddqu_si256( in + 17 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 18 ) );
  w0 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 9, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 18 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 19 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 22 ) );
  w1 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 10, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 20 ), 8 ) );
  tmp = _mm256_lddqu_si256( in + 21 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 26 ) );
  w0 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 11, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 22 ), 12 ) );
  tmp = _mm256_lddqu_si256( in + 23 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 30 ) );
  w1 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 12, w0 );
  tmp = _mm256_lddqu_si256( in + 24 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 16 ) );
  w0 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 13, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 25 ), 2 ) );
  tmp = _mm256_lddqu_si256( in + 26 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 20 ) );
  w1 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 14, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 6 ) );
  tmp = _mm256_lddqu_si256( in + 28 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 15, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 29 ), 10 ) );
  tmp = _mm256_lddqu_si256( in + 30 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 16, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 14 ) );
  _mm256_storeu_si256( compressed + 17, w1 );
}

/* pack 256 19-bit values, touching 19 256-bit words, using 304
 * bytes */
inline void pack256_19( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  19 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  tmp = _mm256_lddqu_si256( in + 1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 19 ) );
  w1 = _mm256_srli_epi32( tmp, 13 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 2 ), 6 ) );
  tmp = _mm256_lddqu_si256( in + 3 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 25 ) );
  w0 = _mm256_srli_epi32( tmp, 7 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 4 ), 12 ) );
  tmp = _mm256_lddqu_si256( in + 5 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 31 ) );
  w1 = _mm256_srli_epi32( tmp, 1 );
  _mm256_storeu_si256( compressed + 2, w0 );
  tmp = _mm256_lddqu_si256( in + 6 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 18 ) );
  w0 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 5 ) );
  tmp = _mm256_lddqu_si256( in + 8 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 9 ), 11 ) );
  tmp = _mm256_lddqu_si256( in + 10 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 30 ) );
  w0 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 5, w1 );
  tmp = _mm256_lddqu_si256( in + 11 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 17 ) );
  w1 = _mm256_srli_epi32( tmp, 15 );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 12 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 13 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 23 ) );
  w0 = _mm256_srli_epi32( tmp, 9 );
  _mm256_storeu_si256( compressed + 7, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 14 ), 10 ) );
  tmp = _mm256_lddqu_si256( in + 15 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 29 ) );
  w1 = _mm256_srli_epi32( tmp, 3 );
  _mm256_storeu_si256( compressed + 8, w0 );
  tmp = _mm256_lddqu_si256( in + 16 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 16 ) );
  w0 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 9, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 17 ), 3 ) );
  tmp = _mm256_lddqu_si256( in + 18 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 22 ) );
  w1 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 10, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 9 ) );
  tmp = _mm256_lddqu_si256( in + 20 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 11, w1 );
  tmp = _mm256_lddqu_si256( in + 21 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 15 ) );
  w1 = _mm256_srli_epi32( tmp, 17 );
  _mm256_storeu_si256( compressed + 12, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 22 ), 2 ) );
  tmp = _mm256_lddqu_si256( in + 23 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 21 ) );
  w0 = _mm256_srli_epi32( tmp, 11 );
  _mm256_storeu_si256( compressed + 13, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 24 ), 8 ) );
  tmp = _mm256_lddqu_si256( in + 25 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 27 ) );
  w1 = _mm256_srli_epi32( tmp, 5 );
  _mm256_storeu_si256( compressed + 14, w0 );
  tmp = _mm256_lddqu_si256( in + 26 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 14 ) );
  w0 = _mm256_srli_epi32( tmp, 18 );
  _mm256_storeu_si256( compressed + 15, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 1 ) );
  tmp = _mm256_lddqu_si256( in + 28 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 20 ) );
  w1 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 16, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 29 ), 7 ) );
  tmp = _mm256_lddqu_si256( in + 30 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 26 ) );
  w0 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 17, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 13 ) );
  _mm256_storeu_si256( compressed + 18, w0 );
}

/* pack 256 20-bit values, touching 20 256-bit words, using 320
 * bytes */
inline void pack256_20( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  20 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  tmp = _mm256_lddqu_si256( in + 1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 20 ) );
  w1 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 2 ), 8 ) );
  tmp = _mm256_lddqu_si256( in + 3 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 1, w1 );
  tmp = _mm256_lddqu_si256( in + 4 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 16 ) );
  w1 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 5 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 6 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 12 ) );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_lddqu_si256( in + 8 );
  tmp = _mm256_lddqu_si256( in + 9 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 20 ) );
  w0 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 10 ), 8 ) );
  tmp = _mm256_lddqu_si256( in + 11 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 6, w0 );
  tmp = _mm256_lddqu_si256( in + 12 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 16 ) );
  w0 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 7, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 13 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 14 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 8, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 12 ) );
  _mm256_storeu_si256( compressed + 9, w1 );
  w0 = _mm256_lddqu_si256( in + 16 );
  tmp = _mm256_lddqu_si256( in + 17 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 20 ) );
  w1 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 10, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 18 ), 8 ) );
  tmp = _mm256_lddqu_si256( in + 19 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 11, w1 );
  tmp = _mm256_lddqu_si256( in + 20 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 16 ) );
  w1 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 12, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 21 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 22 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 13, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 12 ) );
  _mm256_storeu_si256( compressed + 14, w0 );
  w1 = _mm256_lddqu_si256( in + 24 );
  tmp = _mm256_lddqu_si256( in + 25 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 20 ) );
  w0 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 15, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 26 ), 8 ) );
  tmp = _mm256_lddqu_si256( in + 27 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 16, w0 );
  tmp = _mm256_lddqu_si256( in + 28 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 16 ) );
  w0 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 17, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 29 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 30 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 18, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 12 ) );
  _mm256_storeu_si256( compressed + 19, w1 );
}

/* pack 256 21-bit values, touching 21 256-bit words, using 336
 * bytes */
inline void pack256_21( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  21 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  tmp = _mm256_lddqu_si256( in + 1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 21 ) );
  w1 = _mm256_srli_epi32( tmp, 11 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 2 ), 10 ) );
  tmp = _mm256_lddqu_si256( in + 3 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 31 ) );
  w0 = _mm256_srli_epi32( tmp, 1 );
  _mm256_storeu_si256( compressed + 1, w1 );
  tmp = _mm256_lddqu_si256( in + 4 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 20 ) );
  w1 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 5 ), 9 ) );
  tmp = _mm256_lddqu_si256( in + 6 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 30 ) );
  w0 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 3, w1 );
  tmp = _mm256_lddqu_si256( in + 7 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 19 ) );
  w1 = _mm256_srli_epi32( tmp, 13 );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 8 ), 8 ) );
  tmp = _mm256_lddqu_si256( in + 9 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 29 ) );
  w0 = _mm256_srli_epi32( tmp, 3 );
  _mm256_storeu_si256( compressed + 5, w1 );
  tmp = _mm256_lddqu_si256( in + 10 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 18 ) );
  w1 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 7 ) );
  tmp = _mm256_lddqu_si256( in + 12 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 7, w1 );
  tmp = _mm256_lddqu_si256( in + 13 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 17 ) );
  w1 = _mm256_srli_epi32( tmp, 15 );
  _mm256_storeu_si256( compressed + 8, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 14 ), 6 ) );
  tmp = _mm256_lddqu_si256( in + 15 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 27 ) );
  w0 = _mm256_srli_epi32( tmp, 5 );
  _mm256_storeu_si256( compressed + 9, w1 );
  tmp = _mm256_lddqu_si256( in + 16 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 16 ) );
  w1 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 10, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 17 ), 5 ) );
  tmp = _mm256_lddqu_si256( in + 18 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 26 ) );
  w0 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 11, w1 );
  tmp = _mm256_lddqu_si256( in + 19 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 15 ) );
  w1 = _mm256_srli_epi32( tmp, 17 );
  _mm256_storeu_si256( compressed + 12, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 20 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 21 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 25 ) );
  w0 = _mm256_srli_epi32( tmp, 7 );
  _mm256_storeu_si256( compressed + 13, w1 );
  tmp = _mm256_lddqu_si256( in + 22 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 14 ) );
  w1 = _mm256_srli_epi32( tmp, 18 );
  _mm256_storeu_si256( compressed + 14, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 3 ) );
  tmp = _mm256_lddqu_si256( in + 24 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 15, w1 );
  tmp = _mm256_lddqu_si256( in + 25 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 13 ) );
  w1 = _mm256_srli_epi32( tmp, 19 );
  _mm256_storeu_si256( compressed + 16, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 26 ), 2 ) );
  tmp = _mm256_lddqu_si256( in + 27 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 23 ) );
  w0 = _mm256_srli_epi32( tmp, 9 );
  _mm256_storeu_si256( compressed + 17, w1 );
  tmp = _mm256_lddqu_si256( in + 28 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 12 ) );
  w1 = _mm256_srli_epi32( tmp, 20 );
  _mm256_storeu_si256( compressed + 18, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 29 ), 1 ) );
  tmp = _mm256_lddqu_si256( in + 30 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 22 ) );
  w0 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 19, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 11 ) );
  _mm256_storeu_si256( compressed + 20, w0 );
}

/* pack 256 22-bit values, touching 22 256-bit words, using 352
 * bytes */
inline void pack256_22( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  22 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  tmp = _mm256_lddqu_si256( in + 1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 22 ) );
  w1 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 0, w0 );
  tmp = _mm256_lddqu_si256( in + 2 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 12 ) );
  w0 = _mm256_srli_epi32( tmp, 20 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 2 ) );
  tmp = _mm256_lddqu_si256( in + 4 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 2, w0 );
  tmp = _mm256_lddqu_si256( in + 5 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 14 ) );
  w0 = _mm256_srli_epi32( tmp, 18 );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 6 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 7 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 26 ) );
  w1 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 4, w0 );
  tmp = _mm256_lddqu_si256( in + 8 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 16 ) );
  w0 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 9 ), 6 ) );
  tmp = _mm256_lddqu_si256( in + 10 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 6, w0 );
  tmp = _mm256_lddqu_si256( in + 11 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 18 ) );
  w0 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 7, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 12 ), 8 ) );
  tmp = _mm256_lddqu_si256( in + 13 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 30 ) );
  w1 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 8, w0 );
  tmp = _mm256_lddqu_si256( in + 14 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 20 ) );
  w0 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 9, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 10 ) );
  _mm256_storeu_si256( compressed + 10, w0 );
  w1 = _mm256_lddqu_si256( in + 16 );
  tmp = _mm256_lddqu_si256( in + 17 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 22 ) );
  w0 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 11, w1 );
  tmp = _mm256_lddqu_si256( in + 18 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 12 ) );
  w1 = _mm256_srli_epi32( tmp, 20 );
  _mm256_storeu_si256( compressed + 12, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 2 ) );
  tmp = _mm256_lddqu_si256( in + 20 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 13, w1 );
  tmp = _mm256_lddqu_si256( in + 21 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 14 ) );
  w1 = _mm256_srli_epi32( tmp, 18 );
  _mm256_storeu_si256( compressed + 14, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 22 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 23 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 26 ) );
  w0 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 15, w1 );
  tmp = _mm256_lddqu_si256( in + 24 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 16 ) );
  w1 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 16, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 25 ), 6 ) );
  tmp = _mm256_lddqu_si256( in + 26 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 17, w1 );
  tmp = _mm256_lddqu_si256( in + 27 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 18 ) );
  w1 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 18, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 28 ), 8 ) );
  tmp = _mm256_lddqu_si256( in + 29 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 30 ) );
  w0 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 19, w1 );
  tmp = _mm256_lddqu_si256( in + 30 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 20 ) );
  w1 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 20, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 10 ) );
  _mm256_storeu_si256( compressed + 21, w1 );
}

/* pack 256 23-bit values, touching 23 256-bit words, using 368
 * bytes */
inline void pack256_23( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  23 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  tmp = _mm256_lddqu_si256( in + 1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 23 ) );
  w1 = _mm256_srli_epi32( tmp, 9 );
  _mm256_storeu_si256( compressed + 0, w0 );
  tmp = _mm256_lddqu_si256( in + 2 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 14 ) );
  w0 = _mm256_srli_epi32( tmp, 18 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 5 ) );
  tmp = _mm256_lddqu_si256( in + 4 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 2, w0 );
  tmp = _mm256_lddqu_si256( in + 5 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 19 ) );
  w0 = _mm256_srli_epi32( tmp, 13 );
  _mm256_storeu_si256( compressed + 3, w1 );
  tmp = _mm256_lddqu_si256( in + 6 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 10 ) );
  w1 = _mm256_srli_epi32( tmp, 22 );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 1 ) );
  tmp = _mm256_lddqu_si256( in + 8 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 5, w1 );
  tmp = _mm256_lddqu_si256( in + 9 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 15 ) );
  w1 = _mm256_srli_epi32( tmp, 17 );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 10 ), 6 ) );
  tmp = _mm256_lddqu_si256( in + 11 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 29 ) );
  w0 = _mm256_srli_epi32( tmp, 3 );
  _mm256_storeu_si256( compressed + 7, w1 );
  tmp = _mm256_lddqu_si256( in + 12 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 20 ) );
  w1 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 8, w0 );
  tmp = _mm256_lddqu_si256( in + 13 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 11 ) );
  w0 = _mm256_srli_epi32( tmp, 21 );
  _mm256_storeu_si256( compressed + 9, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 14 ), 2 ) );
  tmp = _mm256_lddqu_si256( in + 15 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 25 ) );
  w1 = _mm256_srli_epi32( tmp, 7 );
  _mm256_storeu_si256( compressed + 10, w0 );
  tmp = _mm256_lddqu_si256( in + 16 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 16 ) );
  w0 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 11, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 17 ), 7 ) );
  tmp = _mm256_lddqu_si256( in + 18 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 30 ) );
  w1 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 12, w0 );
  tmp = _mm256_lddqu_si256( in + 19 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 21 ) );
  w0 = _mm256_srli_epi32( tmp, 11 );
  _mm256_storeu_si256( compressed + 13, w1 );
  tmp = _mm256_lddqu_si256( in + 20 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 12 ) );
  w1 = _mm256_srli_epi32( tmp, 20 );
  _mm256_storeu_si256( compressed + 14, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 21 ), 3 ) );
  tmp = _mm256_lddqu_si256( in + 22 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 26 ) );
  w0 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 15, w1 );
  tmp = _mm256_lddqu_si256( in + 23 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 17 ) );
  w1 = _mm256_srli_epi32( tmp, 15 );
  _mm256_storeu_si256( compressed + 16, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 24 ), 8 ) );
  tmp = _mm256_lddqu_si256( in + 25 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 31 ) );
  w0 = _mm256_srli_epi32( tmp, 1 );
  _mm256_storeu_si256( compressed + 17, w1 );
  tmp = _mm256_lddqu_si256( in + 26 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 22 ) );
  w1 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 18, w0 );
  tmp = _mm256_lddqu_si256( in + 27 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 13 ) );
  w0 = _mm256_srli_epi32( tmp, 19 );
  _mm256_storeu_si256( compressed + 19, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 28 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 29 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 27 ) );
  w1 = _mm256_srli_epi32( tmp, 5 );
  _mm256_storeu_si256( compressed + 20, w0 );
  tmp = _mm256_lddqu_si256( in + 30 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 18 ) );
  w0 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 21, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 9 ) );
  _mm256_storeu_si256( compressed + 22, w0 );
}

/* pack 256 24-bit values, touching 24 256-bit words, using 384
 * bytes */
inline void pack256_24( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  24 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  tmp = _mm256_lddqu_si256( in + 1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 0, w0 );
  tmp = _mm256_lddqu_si256( in + 2 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 16 ) );
  w0 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 3 ), 8 ) );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_lddqu_si256( in + 4 );
  tmp = _mm256_lddqu_si256( in + 5 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 3, w1 );
  tmp = _mm256_lddqu_si256( in + 6 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 16 ) );
  w1 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 8 ) );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_lddqu_si256( in + 8 );
  tmp = _mm256_lddqu_si256( in + 9 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 6, w0 );
  tmp = _mm256_lddqu_si256( in + 10 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 16 ) );
  w0 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 7, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 11 ), 8 ) );
  _mm256_storeu_si256( compressed + 8, w0 );
  w1 = _mm256_lddqu_si256( in + 12 );
  tmp = _mm256_lddqu_si256( in + 13 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 9, w1 );
  tmp = _mm256_lddqu_si256( in + 14 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 16 ) );
  w1 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 10, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 8 ) );
  _mm256_storeu_si256( compressed + 11, w1 );
  w0 = _mm256_lddqu_si256( in + 16 );
  tmp = _mm256_lddqu_si256( in + 17 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 12, w0 );
  tmp = _mm256_lddqu_si256( in + 18 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 16 ) );
  w0 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 13, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 8 ) );
  _mm256_storeu_si256( compressed + 14, w0 );
  w1 = _mm256_lddqu_si256( in + 20 );
  tmp = _mm256_lddqu_si256( in + 21 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 15, w1 );
  tmp = _mm256_lddqu_si256( in + 22 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 16 ) );
  w1 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 16, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 8 ) );
  _mm256_storeu_si256( compressed + 17, w1 );
  w0 = _mm256_lddqu_si256( in + 24 );
  tmp = _mm256_lddqu_si256( in + 25 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 18, w0 );
  tmp = _mm256_lddqu_si256( in + 26 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 16 ) );
  w0 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 19, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 8 ) );
  _mm256_storeu_si256( compressed + 20, w0 );
  w1 = _mm256_lddqu_si256( in + 28 );
  tmp = _mm256_lddqu_si256( in + 29 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 21, w1 );
  tmp = _mm256_lddqu_si256( in + 30 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 16 ) );
  w1 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 22, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 8 ) );
  _mm256_storeu_si256( compressed + 23, w1 );
}

/* pack 256 25-bit values, touching 25 256-bit words, using 400
 * bytes */
inline void pack256_25( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  25 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  tmp = _mm256_lddqu_si256( in + 1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 25 ) );
  w1 = _mm256_srli_epi32( tmp, 7 );
  _mm256_storeu_si256( compressed + 0, w0 );
  tmp = _mm256_lddqu_si256( in + 2 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 18 ) );
  w0 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 1, w1 );
  tmp = _mm256_lddqu_si256( in + 3 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 11 ) );
  w1 = _mm256_srli_epi32( tmp, 21 );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 4 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 5 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 29 ) );
  w0 = _mm256_srli_epi32( tmp, 3 );
  _mm256_storeu_si256( compressed + 3, w1 );
  tmp = _mm256_lddqu_si256( in + 6 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 22 ) );
  w1 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 4, w0 );
  tmp = _mm256_lddqu_si256( in + 7 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 15 ) );
  w0 = _mm256_srli_epi32( tmp, 17 );
  _mm256_storeu_si256( compressed + 5, w1 );
  tmp = _mm256_lddqu_si256( in + 8 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 8 ) );
  w1 = _mm256_srli_epi32( tmp, 24 );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 9 ), 1 ) );
  tmp = _mm256_lddqu_si256( in + 10 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 26 ) );
  w0 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 7, w1 );
  tmp = _mm256_lddqu_si256( in + 11 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 19 ) );
  w1 = _mm256_srli_epi32( tmp, 13 );
  _mm256_storeu_si256( compressed + 8, w0 );
  tmp = _mm256_lddqu_si256( in + 12 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 12 ) );
  w0 = _mm256_srli_epi32( tmp, 20 );
  _mm256_storeu_si256( compressed + 9, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 13 ), 5 ) );
  tmp = _mm256_lddqu_si256( in + 14 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 30 ) );
  w1 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 10, w0 );
  tmp = _mm256_lddqu_si256( in + 15 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 23 ) );
  w0 = _mm256_srli_epi32( tmp, 9 );
  _mm256_storeu_si256( compressed + 11, w1 );
  tmp = _mm256_lddqu_si256( in + 16 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 16 ) );
  w1 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 12, w0 );
  tmp = _mm256_lddqu_si256( in + 17 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 9 ) );
  w0 = _mm256_srli_epi32( tmp, 23 );
  _mm256_storeu_si256( compressed + 13, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 18 ), 2 ) );
  tmp = _mm256_lddqu_si256( in + 19 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 27 ) );
  w1 = _mm256_srli_epi32( tmp, 5 );
  _mm256_storeu_si256( compressed + 14, w0 );
  tmp = _mm256_lddqu_si256( in + 20 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 20 ) );
  w0 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 15, w1 );
  tmp = _mm256_lddqu_si256( in + 21 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 13 ) );
  w1 = _mm256_srli_epi32( tmp, 19 );
  _mm256_storeu_si256( compressed + 16, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 22 ), 6 ) );
  tmp = _mm256_lddqu_si256( in + 23 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 31 ) );
  w0 = _mm256_srli_epi32( tmp, 1 );
  _mm256_storeu_si256( compressed + 17, w1 );
  tmp = _mm256_lddqu_si256( in + 24 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 18, w0 );
  tmp = _mm256_lddqu_si256( in + 25 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 17 ) );
  w0 = _mm256_srli_epi32( tmp, 15 );
  _mm256_storeu_si256( compressed + 19, w1 );
  tmp = _mm256_lddqu_si256( in + 26 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 10 ) );
  w1 = _mm256_srli_epi32( tmp, 22 );
  _mm256_storeu_si256( compressed + 20, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 27 ), 3 ) );
  tmp = _mm256_lddqu_si256( in + 28 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 21, w1 );
  tmp = _mm256_lddqu_si256( in + 29 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 21 ) );
  w1 = _mm256_srli_epi32( tmp, 11 );
  _mm256_storeu_si256( compressed + 22, w0 );
  tmp = _mm256_lddqu_si256( in + 30 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 14 ) );
  w0 = _mm256_srli_epi32( tmp, 18 );
  _mm256_storeu_si256( compressed + 23, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 7 ) );
  _mm256_storeu_si256( compressed + 24, w0 );
}

/* pack 256 26-bit values, touching 26 256-bit words, using 416
 * bytes */
inline void pack256_26( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  26 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  tmp = _mm256_lddqu_si256( in + 1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 26 ) );
  w1 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 0, w0 );
  tmp = _mm256_lddqu_si256( in + 2 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 20 ) );
  w0 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 1, w1 );
  tmp = _mm256_lddqu_si256( in + 3 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 14 ) );
  w1 = _mm256_srli_epi32( tmp, 18 );
  _mm256_storeu_si256( compressed + 2, w0 );
  tmp = _mm256_lddqu_si256( in + 4 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 8 ) );
  w0 = _mm256_srli_epi32( tmp, 24 );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 5 ), 2 ) );
  tmp = _mm256_lddqu_si256( in + 6 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 4, w0 );
  tmp = _mm256_lddqu_si256( in + 7 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 22 ) );
  w0 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 5, w1 );
  tmp = _mm256_lddqu_si256( in + 8 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 16 ) );
  w1 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 6, w0 );
  tmp = _mm256_lddqu_si256( in + 9 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 10 ) );
  w0 = _mm256_srli_epi32( tmp, 22 );
  _mm256_storeu_si256( compressed + 7, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 10 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 11 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 30 ) );
  w1 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 8, w0 );
  tmp = _mm256_lddqu_si256( in + 12 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 9, w1 );
  tmp = _mm256_lddqu_si256( in + 13 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 18 ) );
  w1 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 10, w0 );
  tmp = _mm256_lddqu_si256( in + 14 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 12 ) );
  w0 = _mm256_srli_epi32( tmp, 20 );
  _mm256_storeu_si256( compressed + 11, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 6 ) );
  _mm256_storeu_si256( compressed + 12, w0 );
  w1 = _mm256_lddqu_si256( in + 16 );
  tmp = _mm256_lddqu_si256( in + 17 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 26 ) );
  w0 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 13, w1 );
  tmp = _mm256_lddqu_si256( in + 18 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 20 ) );
  w1 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 14, w0 );
  tmp = _mm256_lddqu_si256( in + 19 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 14 ) );
  w0 = _mm256_srli_epi32( tmp, 18 );
  _mm256_storeu_si256( compressed + 15, w1 );
  tmp = _mm256_lddqu_si256( in + 20 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 8 ) );
  w1 = _mm256_srli_epi32( tmp, 24 );
  _mm256_storeu_si256( compressed + 16, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 21 ), 2 ) );
  tmp = _mm256_lddqu_si256( in + 22 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 17, w1 );
  tmp = _mm256_lddqu_si256( in + 23 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 22 ) );
  w1 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 18, w0 );
  tmp = _mm256_lddqu_si256( in + 24 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 16 ) );
  w0 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 19, w1 );
  tmp = _mm256_lddqu_si256( in + 25 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 10 ) );
  w1 = _mm256_srli_epi32( tmp, 22 );
  _mm256_storeu_si256( compressed + 20, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 26 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 27 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 30 ) );
  w0 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 21, w1 );
  tmp = _mm256_lddqu_si256( in + 28 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 22, w0 );
  tmp = _mm256_lddqu_si256( in + 29 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 18 ) );
  w0 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 23, w1 );
  tmp = _mm256_lddqu_si256( in + 30 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 12 ) );
  w1 = _mm256_srli_epi32( tmp, 20 );
  _mm256_storeu_si256( compressed + 24, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 6 ) );
  _mm256_storeu_si256( compressed + 25, w1 );
}

/* pack 256 27-bit values, touching 27 256-bit words, using 432
 * bytes */
inline void pack256_27( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  27 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  tmp = _mm256_lddqu_si256( in + 1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 27 ) );
  w1 = _mm256_srli_epi32( tmp, 5 );
  _mm256_storeu_si256( compressed + 0, w0 );
  tmp = _mm256_lddqu_si256( in + 2 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 22 ) );
  w0 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 1, w1 );
  tmp = _mm256_lddqu_si256( in + 3 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 17 ) );
  w1 = _mm256_srli_epi32( tmp, 15 );
  _mm256_storeu_si256( compressed + 2, w0 );
  tmp = _mm256_lddqu_si256( in + 4 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 12 ) );
  w0 = _mm256_srli_epi32( tmp, 20 );
  _mm256_storeu_si256( compressed + 3, w1 );
  tmp = _mm256_lddqu_si256( in + 5 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 7 ) );
  w1 = _mm256_srli_epi32( tmp, 25 );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 6 ), 2 ) );
  tmp = _mm256_lddqu_si256( in + 7 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 29 ) );
  w0 = _mm256_srli_epi32( tmp, 3 );
  _mm256_storeu_si256( compressed + 5, w1 );
  tmp = _mm256_lddqu_si256( in + 8 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 6, w0 );
  tmp = _mm256_lddqu_si256( in + 9 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 19 ) );
  w0 = _mm256_srli_epi32( tmp, 13 );
  _mm256_storeu_si256( compressed + 7, w1 );
  tmp = _mm256_lddqu_si256( in + 10 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 14 ) );
  w1 = _mm256_srli_epi32( tmp, 18 );
  _mm256_storeu_si256( compressed + 8, w0 );
  tmp = _mm256_lddqu_si256( in + 11 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 9 ) );
  w0 = _mm256_srli_epi32( tmp, 23 );
  _mm256_storeu_si256( compressed + 9, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 12 ), 4 ) );
  tmp = _mm256_lddqu_si256( in + 13 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 31 ) );
  w1 = _mm256_srli_epi32( tmp, 1 );
  _mm256_storeu_si256( compressed + 10, w0 );
  tmp = _mm256_lddqu_si256( in + 14 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 26 ) );
  w0 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 11, w1 );
  tmp = _mm256_lddqu_si256( in + 15 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 21 ) );
  w1 = _mm256_srli_epi32( tmp, 11 );
  _mm256_storeu_si256( compressed + 12, w0 );
  tmp = _mm256_lddqu_si256( in + 16 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 16 ) );
  w0 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 13, w1 );
  tmp = _mm256_lddqu_si256( in + 17 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 11 ) );
  w1 = _mm256_srli_epi32( tmp, 21 );
  _mm256_storeu_si256( compressed + 14, w0 );
  tmp = _mm256_lddqu_si256( in + 18 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 6 ) );
  w0 = _mm256_srli_epi32( tmp, 26 );
  _mm256_storeu_si256( compressed + 15, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 19 ), 1 ) );
  tmp = _mm256_lddqu_si256( in + 20 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 16, w0 );
  tmp = _mm256_lddqu_si256( in + 21 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 23 ) );
  w0 = _mm256_srli_epi32( tmp, 9 );
  _mm256_storeu_si256( compressed + 17, w1 );
  tmp = _mm256_lddqu_si256( in + 22 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 18 ) );
  w1 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 18, w0 );
  tmp = _mm256_lddqu_si256( in + 23 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 13 ) );
  w0 = _mm256_srli_epi32( tmp, 19 );
  _mm256_storeu_si256( compressed + 19, w1 );
  tmp = _mm256_lddqu_si256( in + 24 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 8 ) );
  w1 = _mm256_srli_epi32( tmp, 24 );
  _mm256_storeu_si256( compressed + 20, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 25 ), 3 ) );
  tmp = _mm256_lddqu_si256( in + 26 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 30 ) );
  w0 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 21, w1 );
  tmp = _mm256_lddqu_si256( in + 27 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 25 ) );
  w1 = _mm256_srli_epi32( tmp, 7 );
  _mm256_storeu_si256( compressed + 22, w0 );
  tmp = _mm256_lddqu_si256( in + 28 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 20 ) );
  w0 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 23, w1 );
  tmp = _mm256_lddqu_si256( in + 29 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 15 ) );
  w1 = _mm256_srli_epi32( tmp, 17 );
  _mm256_storeu_si256( compressed + 24, w0 );
  tmp = _mm256_lddqu_si256( in + 30 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 10 ) );
  w0 = _mm256_srli_epi32( tmp, 22 );
  _mm256_storeu_si256( compressed + 25, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 5 ) );
  _mm256_storeu_si256( compressed + 26, w0 );
}

/* pack 256 28-bit values, touching 28 256-bit words, using 448
 * bytes */
inline void pack256_28( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  28 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  tmp = _mm256_lddqu_si256( in + 1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 0, w0 );
  tmp = _mm256_lddqu_si256( in + 2 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 1, w1 );
  tmp = _mm256_lddqu_si256( in + 3 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 20 ) );
  w1 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 2, w0 );
  tmp = _mm256_lddqu_si256( in + 4 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 16 ) );
  w0 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 3, w1 );
  tmp = _mm256_lddqu_si256( in + 5 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 12 ) );
  w1 = _mm256_srli_epi32( tmp, 20 );
  _mm256_storeu_si256( compressed + 4, w0 );
  tmp = _mm256_lddqu_si256( in + 6 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 8 ) );
  w0 = _mm256_srli_epi32( tmp, 24 );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 7 ), 4 ) );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_lddqu_si256( in + 8 );
  tmp = _mm256_lddqu_si256( in + 9 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 7, w1 );
  tmp = _mm256_lddqu_si256( in + 10 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 8, w0 );
  tmp = _mm256_lddqu_si256( in + 11 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 20 ) );
  w0 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 9, w1 );
  tmp = _mm256_lddqu_si256( in + 12 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 16 ) );
  w1 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 10, w0 );
  tmp = _mm256_lddqu_si256( in + 13 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 12 ) );
  w0 = _mm256_srli_epi32( tmp, 20 );
  _mm256_storeu_si256( compressed + 11, w1 );
  tmp = _mm256_lddqu_si256( in + 14 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 8 ) );
  w1 = _mm256_srli_epi32( tmp, 24 );
  _mm256_storeu_si256( compressed + 12, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 4 ) );
  _mm256_storeu_si256( compressed + 13, w1 );
  w0 = _mm256_lddqu_si256( in + 16 );
  tmp = _mm256_lddqu_si256( in + 17 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 14, w0 );
  tmp = _mm256_lddqu_si256( in + 18 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 15, w1 );
  tmp = _mm256_lddqu_si256( in + 19 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 20 ) );
  w1 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 16, w0 );
  tmp = _mm256_lddqu_si256( in + 20 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 16 ) );
  w0 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 17, w1 );
  tmp = _mm256_lddqu_si256( in + 21 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 12 ) );
  w1 = _mm256_srli_epi32( tmp, 20 );
  _mm256_storeu_si256( compressed + 18, w0 );
  tmp = _mm256_lddqu_si256( in + 22 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 8 ) );
  w0 = _mm256_srli_epi32( tmp, 24 );
  _mm256_storeu_si256( compressed + 19, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 23 ), 4 ) );
  _mm256_storeu_si256( compressed + 20, w0 );
  w1 = _mm256_lddqu_si256( in + 24 );
  tmp = _mm256_lddqu_si256( in + 25 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 21, w1 );
  tmp = _mm256_lddqu_si256( in + 26 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 22, w0 );
  tmp = _mm256_lddqu_si256( in + 27 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 20 ) );
  w0 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 23, w1 );
  tmp = _mm256_lddqu_si256( in + 28 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 16 ) );
  w1 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 24, w0 );
  tmp = _mm256_lddqu_si256( in + 29 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 12 ) );
  w0 = _mm256_srli_epi32( tmp, 20 );
  _mm256_storeu_si256( compressed + 25, w1 );
  tmp = _mm256_lddqu_si256( in + 30 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 8 ) );
  w1 = _mm256_srli_epi32( tmp, 24 );
  _mm256_storeu_si256( compressed + 26, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 4 ) );
  _mm256_storeu_si256( compressed + 27, w1 );
}

/* pack 256 29-bit values, touching 29 256-bit words, using 464
 * bytes */
inline void pack256_29( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  29 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  tmp = _mm256_lddqu_si256( in + 1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 29 ) );
  w1 = _mm256_srli_epi32( tmp, 3 );
  _mm256_storeu_si256( compressed + 0, w0 );
  tmp = _mm256_lddqu_si256( in + 2 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 26 ) );
  w0 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 1, w1 );
  tmp = _mm256_lddqu_si256( in + 3 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 23 ) );
  w1 = _mm256_srli_epi32( tmp, 9 );
  _mm256_storeu_si256( compressed + 2, w0 );
  tmp = _mm256_lddqu_si256( in + 4 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 20 ) );
  w0 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 3, w1 );
  tmp = _mm256_lddqu_si256( in + 5 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 17 ) );
  w1 = _mm256_srli_epi32( tmp, 15 );
  _mm256_storeu_si256( compressed + 4, w0 );
  tmp = _mm256_lddqu_si256( in + 6 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 14 ) );
  w0 = _mm256_srli_epi32( tmp, 18 );
  _mm256_storeu_si256( compressed + 5, w1 );
  tmp = _mm256_lddqu_si256( in + 7 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 11 ) );
  w1 = _mm256_srli_epi32( tmp, 21 );
  _mm256_storeu_si256( compressed + 6, w0 );
  tmp = _mm256_lddqu_si256( in + 8 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 8 ) );
  w0 = _mm256_srli_epi32( tmp, 24 );
  _mm256_storeu_si256( compressed + 7, w1 );
  tmp = _mm256_lddqu_si256( in + 9 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 5 ) );
  w1 = _mm256_srli_epi32( tmp, 27 );
  _mm256_storeu_si256( compressed + 8, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 10 ), 2 ) );
  tmp = _mm256_lddqu_si256( in + 11 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 31 ) );
  w0 = _mm256_srli_epi32( tmp, 1 );
  _mm256_storeu_si256( compressed + 9, w1 );
  tmp = _mm256_lddqu_si256( in + 12 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 10, w0 );
  tmp = _mm256_lddqu_si256( in + 13 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 25 ) );
  w0 = _mm256_srli_epi32( tmp, 7 );
  _mm256_storeu_si256( compressed + 11, w1 );
  tmp = _mm256_lddqu_si256( in + 14 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 22 ) );
  w1 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 12, w0 );
  tmp = _mm256_lddqu_si256( in + 15 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 19 ) );
  w0 = _mm256_srli_epi32( tmp, 13 );
  _mm256_storeu_si256( compressed + 13, w1 );
  tmp = _mm256_lddqu_si256( in + 16 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 16 ) );
  w1 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 14, w0 );
  tmp = _mm256_lddqu_si256( in + 17 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 13 ) );
  w0 = _mm256_srli_epi32( tmp, 19 );
  _mm256_storeu_si256( compressed + 15, w1 );
  tmp = _mm256_lddqu_si256( in + 18 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 10 ) );
  w1 = _mm256_srli_epi32( tmp, 22 );
  _mm256_storeu_si256( compressed + 16, w0 );
  tmp = _mm256_lddqu_si256( in + 19 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 7 ) );
  w0 = _mm256_srli_epi32( tmp, 25 );
  _mm256_storeu_si256( compressed + 17, w1 );
  tmp = _mm256_lddqu_si256( in + 20 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 4 ) );
  w1 = _mm256_srli_epi32( tmp, 28 );
  _mm256_storeu_si256( compressed + 18, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 21 ), 1 ) );
  tmp = _mm256_lddqu_si256( in + 22 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 30 ) );
  w0 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 19, w1 );
  tmp = _mm256_lddqu_si256( in + 23 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 27 ) );
  w1 = _mm256_srli_epi32( tmp, 5 );
  _mm256_storeu_si256( compressed + 20, w0 );
  tmp = _mm256_lddqu_si256( in + 24 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 21, w1 );
  tmp = _mm256_lddqu_si256( in + 25 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 21 ) );
  w1 = _mm256_srli_epi32( tmp, 11 );
  _mm256_storeu_si256( compressed + 22, w0 );
  tmp = _mm256_lddqu_si256( in + 26 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 18 ) );
  w0 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 23, w1 );
  tmp = _mm256_lddqu_si256( in + 27 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 15 ) );
  w1 = _mm256_srli_epi32( tmp, 17 );
  _mm256_storeu_si256( compressed + 24, w0 );
  tmp = _mm256_lddqu_si256( in + 28 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 12 ) );
  w0 = _mm256_srli_epi32( tmp, 20 );
  _mm256_storeu_si256( compressed + 25, w1 );
  tmp = _mm256_lddqu_si256( in + 29 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 9 ) );
  w1 = _mm256_srli_epi32( tmp, 23 );
  _mm256_storeu_si256( compressed + 26, w0 );
  tmp = _mm256_lddqu_si256( in + 30 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 6 ) );
  w0 = _mm256_srli_epi32( tmp, 26 );
  _mm256_storeu_si256( compressed + 27, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 3 ) );
  _mm256_storeu_si256( compressed + 28, w0 );
}

/* pack 256 30-bit values, touching 30 256-bit words, using 480
 * bytes */
inline void pack256_30( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  30 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  tmp = _mm256_lddqu_si256( in + 1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 30 ) );
  w1 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 0, w0 );
  tmp = _mm256_lddqu_si256( in + 2 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 1, w1 );
  tmp = _mm256_lddqu_si256( in + 3 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 26 ) );
  w1 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 2, w0 );
  tmp = _mm256_lddqu_si256( in + 4 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 3, w1 );
  tmp = _mm256_lddqu_si256( in + 5 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 22 ) );
  w1 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 4, w0 );
  tmp = _mm256_lddqu_si256( in + 6 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 20 ) );
  w0 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 5, w1 );
  tmp = _mm256_lddqu_si256( in + 7 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 18 ) );
  w1 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 6, w0 );
  tmp = _mm256_lddqu_si256( in + 8 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 16 ) );
  w0 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 7, w1 );
  tmp = _mm256_lddqu_si256( in + 9 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 14 ) );
  w1 = _mm256_srli_epi32( tmp, 18 );
  _mm256_storeu_si256( compressed + 8, w0 );
  tmp = _mm256_lddqu_si256( in + 10 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 12 ) );
  w0 = _mm256_srli_epi32( tmp, 20 );
  _mm256_storeu_si256( compressed + 9, w1 );
  tmp = _mm256_lddqu_si256( in + 11 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 10 ) );
  w1 = _mm256_srli_epi32( tmp, 22 );
  _mm256_storeu_si256( compressed + 10, w0 );
  tmp = _mm256_lddqu_si256( in + 12 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 8 ) );
  w0 = _mm256_srli_epi32( tmp, 24 );
  _mm256_storeu_si256( compressed + 11, w1 );
  tmp = _mm256_lddqu_si256( in + 13 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 6 ) );
  w1 = _mm256_srli_epi32( tmp, 26 );
  _mm256_storeu_si256( compressed + 12, w0 );
  tmp = _mm256_lddqu_si256( in + 14 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 4 ) );
  w0 = _mm256_srli_epi32( tmp, 28 );
  _mm256_storeu_si256( compressed + 13, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 15 ), 2 ) );
  _mm256_storeu_si256( compressed + 14, w0 );
  w1 = _mm256_lddqu_si256( in + 16 );
  tmp = _mm256_lddqu_si256( in + 17 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 30 ) );
  w0 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 15, w1 );
  tmp = _mm256_lddqu_si256( in + 18 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 28 ) );
  w1 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 16, w0 );
  tmp = _mm256_lddqu_si256( in + 19 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 26 ) );
  w0 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 17, w1 );
  tmp = _mm256_lddqu_si256( in + 20 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 24 ) );
  w1 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 18, w0 );
  tmp = _mm256_lddqu_si256( in + 21 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 22 ) );
  w0 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 19, w1 );
  tmp = _mm256_lddqu_si256( in + 22 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 20 ) );
  w1 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 20, w0 );
  tmp = _mm256_lddqu_si256( in + 23 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 18 ) );
  w0 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 21, w1 );
  tmp = _mm256_lddqu_si256( in + 24 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 16 ) );
  w1 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 22, w0 );
  tmp = _mm256_lddqu_si256( in + 25 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 14 ) );
  w0 = _mm256_srli_epi32( tmp, 18 );
  _mm256_storeu_si256( compressed + 23, w1 );
  tmp = _mm256_lddqu_si256( in + 26 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 12 ) );
  w1 = _mm256_srli_epi32( tmp, 20 );
  _mm256_storeu_si256( compressed + 24, w0 );
  tmp = _mm256_lddqu_si256( in + 27 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 10 ) );
  w0 = _mm256_srli_epi32( tmp, 22 );
  _mm256_storeu_si256( compressed + 25, w1 );
  tmp = _mm256_lddqu_si256( in + 28 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 8 ) );
  w1 = _mm256_srli_epi32( tmp, 24 );
  _mm256_storeu_si256( compressed + 26, w0 );
  tmp = _mm256_lddqu_si256( in + 29 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 6 ) );
  w0 = _mm256_srli_epi32( tmp, 26 );
  _mm256_storeu_si256( compressed + 27, w1 );
  tmp = _mm256_lddqu_si256( in + 30 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 4 ) );
  w1 = _mm256_srli_epi32( tmp, 28 );
  _mm256_storeu_si256( compressed + 28, w0 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 2 ) );
  _mm256_storeu_si256( compressed + 29, w1 );
}

/* pack 256 31-bit values, touching 31 256-bit words, using 496
 * bytes */
inline void pack256_31( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  31 256-bit words */
  __m256i w0, w1;
  __m256i tmp; /* used to store inputs at word boundary */
  w0 = _mm256_lddqu_si256( in + 0 );
  tmp = _mm256_lddqu_si256( in + 1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 31 ) );
  w1 = _mm256_srli_epi32( tmp, 1 );
  _mm256_storeu_si256( compressed + 0, w0 );
  tmp = _mm256_lddqu_si256( in + 2 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 30 ) );
  w0 = _mm256_srli_epi32( tmp, 2 );
  _mm256_storeu_si256( compressed + 1, w1 );
  tmp = _mm256_lddqu_si256( in + 3 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 29 ) );
  w1 = _mm256_srli_epi32( tmp, 3 );
  _mm256_storeu_si256( compressed + 2, w0 );
  tmp = _mm256_lddqu_si256( in + 4 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 28 ) );
  w0 = _mm256_srli_epi32( tmp, 4 );
  _mm256_storeu_si256( compressed + 3, w1 );
  tmp = _mm256_lddqu_si256( in + 5 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 27 ) );
  w1 = _mm256_srli_epi32( tmp, 5 );
  _mm256_storeu_si256( compressed + 4, w0 );
  tmp = _mm256_lddqu_si256( in + 6 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 26 ) );
  w0 = _mm256_srli_epi32( tmp, 6 );
  _mm256_storeu_si256( compressed + 5, w1 );
  tmp = _mm256_lddqu_si256( in + 7 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 25 ) );
  w1 = _mm256_srli_epi32( tmp, 7 );
  _mm256_storeu_si256( compressed + 6, w0 );
  tmp = _mm256_lddqu_si256( in + 8 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 24 ) );
  w0 = _mm256_srli_epi32( tmp, 8 );
  _mm256_storeu_si256( compressed + 7, w1 );
  tmp = _mm256_lddqu_si256( in + 9 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 23 ) );
  w1 = _mm256_srli_epi32( tmp, 9 );
  _mm256_storeu_si256( compressed + 8, w0 );
  tmp = _mm256_lddqu_si256( in + 10 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 22 ) );
  w0 = _mm256_srli_epi32( tmp, 10 );
  _mm256_storeu_si256( compressed + 9, w1 );
  tmp = _mm256_lddqu_si256( in + 11 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 21 ) );
  w1 = _mm256_srli_epi32( tmp, 11 );
  _mm256_storeu_si256( compressed + 10, w0 );
  tmp = _mm256_lddqu_si256( in + 12 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 20 ) );
  w0 = _mm256_srli_epi32( tmp, 12 );
  _mm256_storeu_si256( compressed + 11, w1 );
  tmp = _mm256_lddqu_si256( in + 13 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 19 ) );
  w1 = _mm256_srli_epi32( tmp, 13 );
  _mm256_storeu_si256( compressed + 12, w0 );
  tmp = _mm256_lddqu_si256( in + 14 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 18 ) );
  w0 = _mm256_srli_epi32( tmp, 14 );
  _mm256_storeu_si256( compressed + 13, w1 );
  tmp = _mm256_lddqu_si256( in + 15 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 17 ) );
  w1 = _mm256_srli_epi32( tmp, 15 );
  _mm256_storeu_si256( compressed + 14, w0 );
  tmp = _mm256_lddqu_si256( in + 16 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 16 ) );
  w0 = _mm256_srli_epi32( tmp, 16 );
  _mm256_storeu_si256( compressed + 15, w1 );
  tmp = _mm256_lddqu_si256( in + 17 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 15 ) );
  w1 = _mm256_srli_epi32( tmp, 17 );
  _mm256_storeu_si256( compressed + 16, w0 );
  tmp = _mm256_lddqu_si256( in + 18 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 14 ) );
  w0 = _mm256_srli_epi32( tmp, 18 );
  _mm256_storeu_si256( compressed + 17, w1 );
  tmp = _mm256_lddqu_si256( in + 19 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 13 ) );
  w1 = _mm256_srli_epi32( tmp, 19 );
  _mm256_storeu_si256( compressed + 18, w0 );
  tmp = _mm256_lddqu_si256( in + 20 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 12 ) );
  w0 = _mm256_srli_epi32( tmp, 20 );
  _mm256_storeu_si256( compressed + 19, w1 );
  tmp = _mm256_lddqu_si256( in + 21 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 11 ) );
  w1 = _mm256_srli_epi32( tmp, 21 );
  _mm256_storeu_si256( compressed + 20, w0 );
  tmp = _mm256_lddqu_si256( in + 22 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 10 ) );
  w0 = _mm256_srli_epi32( tmp, 22 );
  _mm256_storeu_si256( compressed + 21, w1 );
  tmp = _mm256_lddqu_si256( in + 23 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 9 ) );
  w1 = _mm256_srli_epi32( tmp, 23 );
  _mm256_storeu_si256( compressed + 22, w0 );
  tmp = _mm256_lddqu_si256( in + 24 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 8 ) );
  w0 = _mm256_srli_epi32( tmp, 24 );
  _mm256_storeu_si256( compressed + 23, w1 );
  tmp = _mm256_lddqu_si256( in + 25 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 7 ) );
  w1 = _mm256_srli_epi32( tmp, 25 );
  _mm256_storeu_si256( compressed + 24, w0 );
  tmp = _mm256_lddqu_si256( in + 26 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 6 ) );
  w0 = _mm256_srli_epi32( tmp, 26 );
  _mm256_storeu_si256( compressed + 25, w1 );
  tmp = _mm256_lddqu_si256( in + 27 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 5 ) );
  w1 = _mm256_srli_epi32( tmp, 27 );
  _mm256_storeu_si256( compressed + 26, w0 );
  tmp = _mm256_lddqu_si256( in + 28 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 4 ) );
  w0 = _mm256_srli_epi32( tmp, 28 );
  _mm256_storeu_si256( compressed + 27, w1 );
  tmp = _mm256_lddqu_si256( in + 29 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( tmp, 3 ) );
  w1 = _mm256_srli_epi32( tmp, 29 );
  _mm256_storeu_si256( compressed + 28, w0 );
  tmp = _mm256_lddqu_si256( in + 30 );
  w1 = _mm256_or_si256( w1, _mm256_slli_epi32( tmp, 2 ) );
  w0 = _mm256_srli_epi32( tmp, 30 );
  _mm256_storeu_si256( compressed + 29, w1 );
  w0 = _mm256_or_si256( w0, _mm256_slli_epi32( _mm256_lddqu_si256( in + 31 ), 1 ) );
  _mm256_storeu_si256( compressed + 30, w0 );
}

/* pack 256 32-bit values, touching 32 256-bit words, using 512
 * bytes */
inline void pack256_32( std::uint32_t const* pin, __m256i* compressed ) noexcept {
  __m256i const* in = reinterpret_cast<__m256i const*>( pin );
  /* we are going to touch  32 256-bit words */
  __m256i w0, w1;
  w0 = _mm256_lddqu_si256( in + 0 );
  _mm256_storeu_si256( compressed + 0, w0 );
  w1 = _mm256_lddqu_si256( in + 1 );
  _mm256_storeu_si256( compressed + 1, w1 );
  w0 = _mm256_lddqu_si256( in + 2 );
  _mm256_storeu_si256( compressed + 2, w0 );
  w1 = _mm256_lddqu_si256( in + 3 );
  _mm256_storeu_si256( compressed + 3, w1 );
  w0 = _mm256_lddqu_si256( in + 4 );
  _mm256_storeu_si256( compressed + 4, w0 );
  w1 = _mm256_lddqu_si256( in + 5 );
  _mm256_storeu_si256( compressed + 5, w1 );
  w0 = _mm256_lddqu_si256( in + 6 );
  _mm256_storeu_si256( compressed + 6, w0 );
  w1 = _mm256_lddqu_si256( in + 7 );
  _mm256_storeu_si256( compressed + 7, w1 );
  w0 = _mm256_lddqu_si256( in + 8 );
  _mm256_storeu_si256( compressed + 8, w0 );
  w1 = _mm256_lddqu_si256( in + 9 );
  _mm256_storeu_si256( compressed + 9, w1 );
  w0 = _mm256_lddqu_si256( in + 10 );
  _mm256_storeu_si256( compressed + 10, w0 );
  w1 = _mm256_lddqu_si256( in + 11 );
  _mm256_storeu_si256( compressed + 11, w1 );
  w0 = _mm256_lddqu_si256( in + 12 );
  _mm256_storeu_si256( compressed + 12, w0 );
  w1 = _mm256_lddqu_si256( in + 13 );
  _mm256_storeu_si256( compressed + 13, w1 );
  w0 = _mm256_lddqu_si256( in + 14 );
  _mm256_storeu_si256( compressed + 14, w0 );
  w1 = _mm256_lddqu_si256( in + 15 );
  _mm256_storeu_si256( compressed + 15, w1 );
  w0 = _mm256_lddqu_si256( in + 16 );
  _mm256_storeu_si256( compressed + 16, w0 );
  w1 = _mm256_lddqu_si256( in + 17 );
  _mm256_storeu_si256( compressed + 17, w1 );
  w0 = _mm256_lddqu_si256( in + 18 );
  _mm256_storeu_si256( compressed + 18, w0 );
  w1 = _mm256_lddqu_si256( in + 19 );
  _mm256_storeu_si256( compressed + 19, w1 );
  w0 = _mm256_lddqu_si256( in + 20 );
  _mm256_storeu_si256( compressed + 20, w0 );
  w1 = _mm256_lddqu_si256( in + 21 );
  _mm256_storeu_si256( compressed + 21, w1 );
  w0 = _mm256_lddqu_si256( in + 22 );
  _mm256_storeu_si256( compressed + 22, w0 );
  w1 = _mm256_lddqu_si256( in + 23 );
  _mm256_storeu_si256( compressed + 23, w1 );
  w0 = _mm256_lddqu_si256( in + 24 );
  _mm256_storeu_si256( compressed + 24, w0 );
  w1 = _mm256_lddqu_si256( in + 25 );
  _mm256_storeu_si256( compressed + 25, w1 );
  w0 = _mm256_lddqu_si256( in + 26 );
  _mm256_storeu_si256( compressed + 26, w0 );
  w1 = _mm256_lddqu_si256( in + 27 );
  _mm256_storeu_si256( compressed + 27, w1 );
  w0 = _mm256_lddqu_si256( in + 28 );
  _mm256_storeu_si256( compressed + 28, w0 );
  w1 = _mm256_lddqu_si256( in + 29 );
  _mm256_storeu_si256( compressed + 29, w1 );
  w0 = _mm256_lddqu_si256( in + 30 );
  _mm256_storeu_si256( compressed + 30, w0 );
  w1 = _mm256_lddqu_si256( in + 31 );
  _mm256_storeu_si256( compressed + 31, w1 );
}

inline void unpack256_0( [[maybe_unused]] __m256i const*, std::uint32_t* out_ ) noexcept {
  __m256i* out = reinterpret_cast<__m256i*>( out_ );
  __m256i const zero = _mm256_setzero_si256();
  _mm256_storeu_si256( out, zero );
  _mm256_storeu_si256( out + 1, zero );
  _mm256_storeu_si256( out + 2, zero );
  _mm256_storeu_si256( out + 3, zero );
  _mm256_storeu_si256( out + 4, zero );
  _mm256_storeu_si256( out + 5, zero );
  _mm256_storeu_si256( out + 6, zero );
  _mm256_storeu_si256( out + 7, zero );
  _mm256_storeu_si256( out + 8, zero );
  _mm256_storeu_si256( out + 9, zero );
  _mm256_storeu_si256( out + 10, zero );
  _mm256_storeu_si256( out + 11, zero );
  _mm256_storeu_si256( out + 12, zero );
  _mm256_storeu_si256( out + 13, zero );
  _mm256_storeu_si256( out + 14, zero );
  _mm256_storeu_si256( out + 15, zero );
  _mm256_storeu_si256( out + 16, zero );
  _mm256_storeu_si256( out + 17, zero );
  _mm256_storeu_si256( out + 18, zero );
  _mm256_storeu_si256( out + 19, zero );
  _mm256_storeu_si256( out + 20, zero );
  _mm256_storeu_si256( out + 21, zero );
  _mm256_storeu_si256( out + 22, zero );
  _mm256_storeu_si256( out + 23, zero );
  _mm256_storeu_si256( out + 24, zero );
  _mm256_storeu_si256( out + 25, zero );
  _mm256_storeu_si256( out + 26, zero );
  _mm256_storeu_si256( out + 27, zero );
  _mm256_storeu_si256( out + 28, zero );
  _mm256_storeu_si256( out + 29, zero );
  _mm256_storeu_si256( out + 30, zero );
  _mm256_storeu_si256( out + 31, zero );
}

/* we packed 256 1-bit values, touching 1 256-bit words, using 16 bytes */
inline void unpack256_1( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  1 256-bit word */
  __m256i w0;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 1 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 1, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 1 ) ) );
  _mm256_storeu_si256( out + 2, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 2 ) ) );
  _mm256_storeu_si256( out + 3, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 3 ) ) );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  _mm256_storeu_si256( out + 5, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 5 ) ) );
  _mm256_storeu_si256( out + 6, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 6 ) ) );
  _mm256_storeu_si256( out + 7, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 7 ) ) );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  _mm256_storeu_si256( out + 9, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 9 ) ) );
  _mm256_storeu_si256( out + 10, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 10 ) ) );
  _mm256_storeu_si256( out + 11, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 11 ) ) );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 12 ) ) );
  _mm256_storeu_si256( out + 13, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 13 ) ) );
  _mm256_storeu_si256( out + 14, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 14 ) ) );
  _mm256_storeu_si256( out + 15, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 15 ) ) );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 16 ) ) );
  _mm256_storeu_si256( out + 17, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 17 ) ) );
  _mm256_storeu_si256( out + 18, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 18 ) ) );
  _mm256_storeu_si256( out + 19, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 19 ) ) );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 20 ) ) );
  _mm256_storeu_si256( out + 21, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 21 ) ) );
  _mm256_storeu_si256( out + 22, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 22 ) ) );
  _mm256_storeu_si256( out + 23, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 23 ) ) );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 24 ) ) );
  _mm256_storeu_si256( out + 25, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 25 ) ) );
  _mm256_storeu_si256( out + 26, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 26 ) ) );
  _mm256_storeu_si256( out + 27, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 27 ) ) );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 28 ) ) );
  _mm256_storeu_si256( out + 29, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 29 ) ) );
  _mm256_storeu_si256( out + 30, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 30 ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w0, 31 ) );
}

/* we packed 256 2-bit values, touching 2 256-bit words, using 32 bytes */
inline void unpack256_2( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  2 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 3 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 1, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 2 ) ) );
  _mm256_storeu_si256( out + 2, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  _mm256_storeu_si256( out + 3, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 6 ) ) );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  _mm256_storeu_si256( out + 5, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 10 ) ) );
  _mm256_storeu_si256( out + 6, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 12 ) ) );
  _mm256_storeu_si256( out + 7, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 14 ) ) );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 16 ) ) );
  _mm256_storeu_si256( out + 9, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 18 ) ) );
  _mm256_storeu_si256( out + 10, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 20 ) ) );
  _mm256_storeu_si256( out + 11, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 22 ) ) );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 24 ) ) );
  _mm256_storeu_si256( out + 13, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 26 ) ) );
  _mm256_storeu_si256( out + 14, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 28 ) ) );
  _mm256_storeu_si256( out + 15, _mm256_srli_epi32( w0, 30 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 17, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 2 ) ) );
  _mm256_storeu_si256( out + 18, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  _mm256_storeu_si256( out + 19, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 6 ) ) );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  _mm256_storeu_si256( out + 21, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 10 ) ) );
  _mm256_storeu_si256( out + 22, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 12 ) ) );
  _mm256_storeu_si256( out + 23, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 14 ) ) );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 16 ) ) );
  _mm256_storeu_si256( out + 25, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 18 ) ) );
  _mm256_storeu_si256( out + 26, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 20 ) ) );
  _mm256_storeu_si256( out + 27, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 22 ) ) );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 24 ) ) );
  _mm256_storeu_si256( out + 29, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 26 ) ) );
  _mm256_storeu_si256( out + 30, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 28 ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w1, 30 ) );
}

/* we packed 256 3-bit values, touching 3 256-bit words, using 48 bytes */
inline void unpack256_3( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  3 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 7 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 1, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 3 ) ) );
  _mm256_storeu_si256( out + 2, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 6 ) ) );
  _mm256_storeu_si256( out + 3, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 9 ) ) );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 12 ) ) );
  _mm256_storeu_si256( out + 5, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 15 ) ) );
  _mm256_storeu_si256( out + 6, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 18 ) ) );
  _mm256_storeu_si256( out + 7, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 21 ) ) );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 24 ) ) );
  _mm256_storeu_si256( out + 9, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 27 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 10,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 30 ),
                                                          _mm256_slli_epi32( w1, 2 ) ) ) );
  _mm256_storeu_si256( out + 11, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 1 ) ) );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  _mm256_storeu_si256( out + 13, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 7 ) ) );
  _mm256_storeu_si256( out + 14, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 10 ) ) );
  _mm256_storeu_si256( out + 15, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 13 ) ) );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 16 ) ) );
  _mm256_storeu_si256( out + 17, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 19 ) ) );
  _mm256_storeu_si256( out + 18, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 22 ) ) );
  _mm256_storeu_si256( out + 19, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 25 ) ) );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 28 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 21,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 31 ),
                                                          _mm256_slli_epi32( w0, 1 ) ) ) );
  _mm256_storeu_si256( out + 22, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 2 ) ) );
  _mm256_storeu_si256( out + 23, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 5 ) ) );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  _mm256_storeu_si256( out + 25, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 11 ) ) );
  _mm256_storeu_si256( out + 26, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 14 ) ) );
  _mm256_storeu_si256( out + 27, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 17 ) ) );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 20 ) ) );
  _mm256_storeu_si256( out + 29, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 23 ) ) );
  _mm256_storeu_si256( out + 30, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 26 ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w0, 29 ) );
}

/* we packed 256 4-bit values, touching 4 256-bit words, using 64 bytes */
inline void unpack256_4( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  4 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 15 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 1, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  _mm256_storeu_si256( out + 2, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  _mm256_storeu_si256( out + 3, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 12 ) ) );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 16 ) ) );
  _mm256_storeu_si256( out + 5, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 20 ) ) );
  _mm256_storeu_si256( out + 6, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 24 ) ) );
  _mm256_storeu_si256( out + 7, _mm256_srli_epi32( w0, 28 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 9, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  _mm256_storeu_si256( out + 10, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  _mm256_storeu_si256( out + 11, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 12 ) ) );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 16 ) ) );
  _mm256_storeu_si256( out + 13, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 20 ) ) );
  _mm256_storeu_si256( out + 14, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 24 ) ) );
  _mm256_storeu_si256( out + 15, _mm256_srli_epi32( w1, 28 ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 17, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  _mm256_storeu_si256( out + 18, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  _mm256_storeu_si256( out + 19, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 12 ) ) );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 16 ) ) );
  _mm256_storeu_si256( out + 21, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 20 ) ) );
  _mm256_storeu_si256( out + 22, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 24 ) ) );
  _mm256_storeu_si256( out + 23, _mm256_srli_epi32( w0, 28 ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 25, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  _mm256_storeu_si256( out + 26, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  _mm256_storeu_si256( out + 27, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 12 ) ) );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 16 ) ) );
  _mm256_storeu_si256( out + 29, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 20 ) ) );
  _mm256_storeu_si256( out + 30, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 24 ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w1, 28 ) );
}

/* we packed 256 5-bit values, touching 5 256-bit words, using 80 bytes */
inline void unpack256_5( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  5 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 31 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 1, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 5 ) ) );
  _mm256_storeu_si256( out + 2, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 10 ) ) );
  _mm256_storeu_si256( out + 3, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 15 ) ) );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 20 ) ) );
  _mm256_storeu_si256( out + 5, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 25 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 6,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 30 ),
                                                          _mm256_slli_epi32( w1, 2 ) ) ) );
  _mm256_storeu_si256( out + 7, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 3 ) ) );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  _mm256_storeu_si256( out + 9, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 13 ) ) );
  _mm256_storeu_si256( out + 10, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 18 ) ) );
  _mm256_storeu_si256( out + 11, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 23 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 12,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  _mm256_storeu_si256( out + 13, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 1 ) ) );
  _mm256_storeu_si256( out + 14, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 6 ) ) );
  _mm256_storeu_si256( out + 15, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 11 ) ) );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 16 ) ) );
  _mm256_storeu_si256( out + 17, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 21 ) ) );
  _mm256_storeu_si256( out + 18, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 26 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 19,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 31 ),
                                                          _mm256_slli_epi32( w1, 1 ) ) ) );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  _mm256_storeu_si256( out + 21, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 9 ) ) );
  _mm256_storeu_si256( out + 22, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 14 ) ) );
  _mm256_storeu_si256( out + 23, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 19 ) ) );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 24 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 25,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 29 ),
                                                          _mm256_slli_epi32( w0, 3 ) ) ) );
  _mm256_storeu_si256( out + 26, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 2 ) ) );
  _mm256_storeu_si256( out + 27, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 7 ) ) );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 12 ) ) );
  _mm256_storeu_si256( out + 29, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 17 ) ) );
  _mm256_storeu_si256( out + 30, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 22 ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w0, 27 ) );
}

/* we packed 256 6-bit values, touching 6 256-bit words, using 96 bytes */
inline void unpack256_6( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  6 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 63 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 1, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 6 ) ) );
  _mm256_storeu_si256( out + 2, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 12 ) ) );
  _mm256_storeu_si256( out + 3, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 18 ) ) );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 24 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 5,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 30 ),
                                                          _mm256_slli_epi32( w1, 2 ) ) ) );
  _mm256_storeu_si256( out + 6, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  _mm256_storeu_si256( out + 7, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 10 ) ) );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 16 ) ) );
  _mm256_storeu_si256( out + 9, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 22 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 10,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  _mm256_storeu_si256( out + 11, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 2 ) ) );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  _mm256_storeu_si256( out + 13, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 14 ) ) );
  _mm256_storeu_si256( out + 14, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 20 ) ) );
  _mm256_storeu_si256( out + 15, _mm256_srli_epi32( w0, 26 ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 17, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 6 ) ) );
  _mm256_storeu_si256( out + 18, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 12 ) ) );
  _mm256_storeu_si256( out + 19, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 18 ) ) );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 24 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 21,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 30 ),
                                                          _mm256_slli_epi32( w0, 2 ) ) ) );
  _mm256_storeu_si256( out + 22, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  _mm256_storeu_si256( out + 23, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 10 ) ) );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 16 ) ) );
  _mm256_storeu_si256( out + 25, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 22 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 26,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  _mm256_storeu_si256( out + 27, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 2 ) ) );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  _mm256_storeu_si256( out + 29, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 14 ) ) );
  _mm256_storeu_si256( out + 30, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 20 ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w1, 26 ) );
}

/* we packed 256 7-bit values, touching 7 256-bit words, using 112 bytes */
inline void unpack256_7( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  7 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 127 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 1, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 7 ) ) );
  _mm256_storeu_si256( out + 2, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 14 ) ) );
  _mm256_storeu_si256( out + 3, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 21 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 4,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  _mm256_storeu_si256( out + 5, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 3 ) ) );
  _mm256_storeu_si256( out + 6, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 10 ) ) );
  _mm256_storeu_si256( out + 7, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 17 ) ) );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 24 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 9,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 31 ),
                                                          _mm256_slli_epi32( w0, 1 ) ) ) );
  _mm256_storeu_si256( out + 10, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 6 ) ) );
  _mm256_storeu_si256( out + 11, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 13 ) ) );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 20 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 13,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 27 ),
                                                          _mm256_slli_epi32( w1, 5 ) ) ) );
  _mm256_storeu_si256( out + 14, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 2 ) ) );
  _mm256_storeu_si256( out + 15, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 9 ) ) );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 16 ) ) );
  _mm256_storeu_si256( out + 17, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 23 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 18,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 30 ),
                                                          _mm256_slli_epi32( w0, 2 ) ) ) );
  _mm256_storeu_si256( out + 19, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 5 ) ) );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 12 ) ) );
  _mm256_storeu_si256( out + 21, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 19 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 22,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 26 ),
                                                          _mm256_slli_epi32( w1, 6 ) ) ) );
  _mm256_storeu_si256( out + 23, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 1 ) ) );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  _mm256_storeu_si256( out + 25, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 15 ) ) );
  _mm256_storeu_si256( out + 26, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 22 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 27,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 29 ),
                                                          _mm256_slli_epi32( w0, 3 ) ) ) );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  _mm256_storeu_si256( out + 29, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 11 ) ) );
  _mm256_storeu_si256( out + 30, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 18 ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w0, 25 ) );
}

/* we packed 256 8-bit values, touching 8 256-bit words, using 128 bytes */
inline void unpack256_8( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  8 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 255 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 1, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  _mm256_storeu_si256( out + 2, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 16 ) ) );
  _mm256_storeu_si256( out + 3, _mm256_srli_epi32( w0, 24 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 5, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  _mm256_storeu_si256( out + 6, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 16 ) ) );
  _mm256_storeu_si256( out + 7, _mm256_srli_epi32( w1, 24 ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 9, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  _mm256_storeu_si256( out + 10, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 16 ) ) );
  _mm256_storeu_si256( out + 11, _mm256_srli_epi32( w0, 24 ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 13, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  _mm256_storeu_si256( out + 14, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 16 ) ) );
  _mm256_storeu_si256( out + 15, _mm256_srli_epi32( w1, 24 ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 17, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  _mm256_storeu_si256( out + 18, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 16 ) ) );
  _mm256_storeu_si256( out + 19, _mm256_srli_epi32( w0, 24 ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 21, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  _mm256_storeu_si256( out + 22, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 16 ) ) );
  _mm256_storeu_si256( out + 23, _mm256_srli_epi32( w1, 24 ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 25, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  _mm256_storeu_si256( out + 26, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 16 ) ) );
  _mm256_storeu_si256( out + 27, _mm256_srli_epi32( w0, 24 ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 29, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  _mm256_storeu_si256( out + 30, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 16 ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w1, 24 ) );
}

/* we packed 256 9-bit values, touching 9 256-bit words, using 144 bytes */
inline void unpack256_9( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  9 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 511 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 1, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 9 ) ) );
  _mm256_storeu_si256( out + 2, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 18 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 3,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 27 ),
                                                          _mm256_slli_epi32( w1, 5 ) ) ) );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  _mm256_storeu_si256( out + 5, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 13 ) ) );
  _mm256_storeu_si256( out + 6, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 22 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 7,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 31 ),
                                                          _mm256_slli_epi32( w0, 1 ) ) ) );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  _mm256_storeu_si256( out + 9, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 17 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 10,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 26 ),
                                                          _mm256_slli_epi32( w1, 6 ) ) ) );
  _mm256_storeu_si256( out + 11, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 3 ) ) );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 12 ) ) );
  _mm256_storeu_si256( out + 13, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 21 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 14,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 30 ),
                                                          _mm256_slli_epi32( w0, 2 ) ) ) );
  _mm256_storeu_si256( out + 15, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 7 ) ) );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 16 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 17,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 25 ),
                                                          _mm256_slli_epi32( w1, 7 ) ) ) );
  _mm256_storeu_si256( out + 18, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 2 ) ) );
  _mm256_storeu_si256( out + 19, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 11 ) ) );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 20 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 21,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 29 ),
                                                          _mm256_slli_epi32( w0, 3 ) ) ) );
  _mm256_storeu_si256( out + 22, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 6 ) ) );
  _mm256_storeu_si256( out + 23, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 15 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 24,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  _mm256_storeu_si256( out + 25, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 1 ) ) );
  _mm256_storeu_si256( out + 26, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 10 ) ) );
  _mm256_storeu_si256( out + 27, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 19 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 28,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  _mm256_storeu_si256( out + 29, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 5 ) ) );
  _mm256_storeu_si256( out + 30, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 14 ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w0, 23 ) );
}

/* we packed 256 10-bit values, touching 10 256-bit words, using 160 bytes */
inline void unpack256_10( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  10 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 1023 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 1, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 10 ) ) );
  _mm256_storeu_si256( out + 2, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 20 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 3,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 30 ),
                                                          _mm256_slli_epi32( w1, 2 ) ) ) );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  _mm256_storeu_si256( out + 5, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 18 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 6,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  _mm256_storeu_si256( out + 7, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 6 ) ) );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 16 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 9,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 26 ),
                                                          _mm256_slli_epi32( w1, 6 ) ) ) );
  _mm256_storeu_si256( out + 10, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  _mm256_storeu_si256( out + 11, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 14 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 12,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  _mm256_storeu_si256( out + 13, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 2 ) ) );
  _mm256_storeu_si256( out + 14, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 12 ) ) );
  _mm256_storeu_si256( out + 15, _mm256_srli_epi32( w0, 22 ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 17, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 10 ) ) );
  _mm256_storeu_si256( out + 18, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 20 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 19,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 30 ),
                                                          _mm256_slli_epi32( w0, 2 ) ) ) );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  _mm256_storeu_si256( out + 21, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 18 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 22,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  _mm256_storeu_si256( out + 23, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 6 ) ) );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 16 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 25,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 26 ),
                                                          _mm256_slli_epi32( w0, 6 ) ) ) );
  _mm256_storeu_si256( out + 26, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  _mm256_storeu_si256( out + 27, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 14 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 28,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  _mm256_storeu_si256( out + 29, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 2 ) ) );
  _mm256_storeu_si256( out + 30, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 12 ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w1, 22 ) );
}

/* we packed 256 11-bit values, touching 11 256-bit words, using 176 bytes */
inline void unpack256_11( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  11 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 2047 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 1, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 11 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 2,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 22 ),
                                                          _mm256_slli_epi32( w1, 10 ) ) ) );
  _mm256_storeu_si256( out + 3, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 1 ) ) );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 12 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 5,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 23 ),
                                                          _mm256_slli_epi32( w0, 9 ) ) ) );
  _mm256_storeu_si256( out + 6, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 2 ) ) );
  _mm256_storeu_si256( out + 7, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 13 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 8,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  _mm256_storeu_si256( out + 9, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 3 ) ) );
  _mm256_storeu_si256( out + 10, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 14 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 11,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 25 ),
                                                          _mm256_slli_epi32( w0, 7 ) ) ) );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  _mm256_storeu_si256( out + 13, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 15 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 14,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 26 ),
                                                          _mm256_slli_epi32( w1, 6 ) ) ) );
  _mm256_storeu_si256( out + 15, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 5 ) ) );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 16 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 17,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 27 ),
                                                          _mm256_slli_epi32( w0, 5 ) ) ) );
  _mm256_storeu_si256( out + 18, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 6 ) ) );
  _mm256_storeu_si256( out + 19, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 17 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 20,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  _mm256_storeu_si256( out + 21, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 7 ) ) );
  _mm256_storeu_si256( out + 22, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 18 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 23,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 29 ),
                                                          _mm256_slli_epi32( w0, 3 ) ) ) );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  _mm256_storeu_si256( out + 25, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 19 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 26,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 30 ),
                                                          _mm256_slli_epi32( w1, 2 ) ) ) );
  _mm256_storeu_si256( out + 27, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 9 ) ) );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 20 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 29,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 31 ),
                                                          _mm256_slli_epi32( w0, 1 ) ) ) );
  _mm256_storeu_si256( out + 30, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 10 ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w0, 21 ) );
}

/* we packed 256 12-bit values, touching 12 256-bit words, using 192 bytes */
inline void unpack256_12( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  12 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 4095 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 1, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 12 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 2,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  _mm256_storeu_si256( out + 3, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 16 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 5,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  _mm256_storeu_si256( out + 6, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  _mm256_storeu_si256( out + 7, _mm256_srli_epi32( w0, 20 ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 9, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 12 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 10,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  _mm256_storeu_si256( out + 11, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 16 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 13,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  _mm256_storeu_si256( out + 14, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  _mm256_storeu_si256( out + 15, _mm256_srli_epi32( w1, 20 ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 17, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 12 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 18,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  _mm256_storeu_si256( out + 19, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 16 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 21,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  _mm256_storeu_si256( out + 22, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  _mm256_storeu_si256( out + 23, _mm256_srli_epi32( w0, 20 ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 25, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 12 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 26,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  _mm256_storeu_si256( out + 27, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 16 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 29,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  _mm256_storeu_si256( out + 30, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w1, 20 ) );
}

/* we packed 256 13-bit values, touching 13 256-bit words, using 208 bytes */
inline void unpack256_13( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  13 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 8191 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 1, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 13 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 2,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 26 ),
                                                          _mm256_slli_epi32( w1, 6 ) ) ) );
  _mm256_storeu_si256( out + 3, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 7 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 4,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 20 ),
                                                          _mm256_slli_epi32( w0, 12 ) ) ) );
  _mm256_storeu_si256( out + 5, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 1 ) ) );
  _mm256_storeu_si256( out + 6, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 14 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 7,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 27 ),
                                                          _mm256_slli_epi32( w1, 5 ) ) ) );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 9,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 21 ),
                                                          _mm256_slli_epi32( w0, 11 ) ) ) );
  _mm256_storeu_si256( out + 10, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 2 ) ) );
  _mm256_storeu_si256( out + 11, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 15 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 12,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  _mm256_storeu_si256( out + 13, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 9 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 14,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 22 ),
                                                          _mm256_slli_epi32( w0, 10 ) ) ) );
  _mm256_storeu_si256( out + 15, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 3 ) ) );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 16 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 17,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 29 ),
                                                          _mm256_slli_epi32( w1, 3 ) ) ) );
  _mm256_storeu_si256( out + 18, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 10 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 19,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 23 ),
                                                          _mm256_slli_epi32( w0, 9 ) ) ) );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  _mm256_storeu_si256( out + 21, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 17 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 22,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 30 ),
                                                          _mm256_slli_epi32( w1, 2 ) ) ) );
  _mm256_storeu_si256( out + 23, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 11 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 24,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  _mm256_storeu_si256( out + 25, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 5 ) ) );
  _mm256_storeu_si256( out + 26, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 18 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 27,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 31 ),
                                                          _mm256_slli_epi32( w1, 1 ) ) ) );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 12 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 29,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 25 ),
                                                          _mm256_slli_epi32( w0, 7 ) ) ) );
  _mm256_storeu_si256( out + 30, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 6 ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w0, 19 ) );
}

/* we packed 256 14-bit values, touching 14 256-bit words, using 224 bytes */
inline void unpack256_14( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  14 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 16383 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 1, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 14 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 2,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  _mm256_storeu_si256( out + 3, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 10 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 4,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  _mm256_storeu_si256( out + 5, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 6 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 6,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 20 ),
                                                          _mm256_slli_epi32( w1, 12 ) ) ) );
  _mm256_storeu_si256( out + 7, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 2 ) ) );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 16 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 9,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 30 ),
                                                          _mm256_slli_epi32( w0, 2 ) ) ) );
  _mm256_storeu_si256( out + 10, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 12 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 11,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 26 ),
                                                          _mm256_slli_epi32( w1, 6 ) ) ) );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 13,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 22 ),
                                                          _mm256_slli_epi32( w0, 10 ) ) ) );
  _mm256_storeu_si256( out + 14, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  _mm256_storeu_si256( out + 15, _mm256_srli_epi32( w0, 18 ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 17, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 14 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 18,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  _mm256_storeu_si256( out + 19, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 10 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 20,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  _mm256_storeu_si256( out + 21, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 6 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 22,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 20 ),
                                                          _mm256_slli_epi32( w0, 12 ) ) ) );
  _mm256_storeu_si256( out + 23, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 2 ) ) );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 16 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 25,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 30 ),
                                                          _mm256_slli_epi32( w1, 2 ) ) ) );
  _mm256_storeu_si256( out + 26, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 12 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 27,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 26 ),
                                                          _mm256_slli_epi32( w0, 6 ) ) ) );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 29,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 22 ),
                                                          _mm256_slli_epi32( w1, 10 ) ) ) );
  _mm256_storeu_si256( out + 30, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w1, 18 ) );
}

/* we packed 256 15-bit values, touching 15 256-bit words, using 240 bytes */
inline void unpack256_15( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  15 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 32767 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 1, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 15 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 2,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 30 ),
                                                          _mm256_slli_epi32( w1, 2 ) ) ) );
  _mm256_storeu_si256( out + 3, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 13 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 4,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  _mm256_storeu_si256( out + 5, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 11 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 6,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 26 ),
                                                          _mm256_slli_epi32( w1, 6 ) ) ) );
  _mm256_storeu_si256( out + 7, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 9 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 8,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  _mm256_storeu_si256( out + 9, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 7 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 10,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 22 ),
                                                          _mm256_slli_epi32( w1, 10 ) ) ) );
  _mm256_storeu_si256( out + 11, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 5 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 12,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 20 ),
                                                          _mm256_slli_epi32( w0, 12 ) ) ) );
  _mm256_storeu_si256( out + 13, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 3 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 14,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 18 ),
                                                          _mm256_slli_epi32( w1, 14 ) ) ) );
  _mm256_storeu_si256( out + 15, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 1 ) ) );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 16 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 17,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 31 ),
                                                          _mm256_slli_epi32( w0, 1 ) ) ) );
  _mm256_storeu_si256( out + 18, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 14 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 19,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 29 ),
                                                          _mm256_slli_epi32( w1, 3 ) ) ) );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 12 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 21,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 27 ),
                                                          _mm256_slli_epi32( w0, 5 ) ) ) );
  _mm256_storeu_si256( out + 22, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 10 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 23,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 25 ),
                                                          _mm256_slli_epi32( w1, 7 ) ) ) );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 25,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 23 ),
                                                          _mm256_slli_epi32( w0, 9 ) ) ) );
  _mm256_storeu_si256( out + 26, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 6 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 27,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 21 ),
                                                          _mm256_slli_epi32( w1, 11 ) ) ) );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 29,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 19 ),
                                                          _mm256_slli_epi32( w0, 13 ) ) ) );
  _mm256_storeu_si256( out + 30, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 2 ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w0, 17 ) );
}

/* we packed 256 16-bit values, touching 16 256-bit words, using 256 bytes */
inline void unpack256_16( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  16 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 65535 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 1, _mm256_srli_epi32( w0, 16 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 2, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 3, _mm256_srli_epi32( w1, 16 ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 5, _mm256_srli_epi32( w0, 16 ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 6, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 7, _mm256_srli_epi32( w1, 16 ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 9, _mm256_srli_epi32( w0, 16 ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 10, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 11, _mm256_srli_epi32( w1, 16 ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 13, _mm256_srli_epi32( w0, 16 ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 14, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 15, _mm256_srli_epi32( w1, 16 ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 17, _mm256_srli_epi32( w0, 16 ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 18, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 19, _mm256_srli_epi32( w1, 16 ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 21, _mm256_srli_epi32( w0, 16 ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 22, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 23, _mm256_srli_epi32( w1, 16 ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 25, _mm256_srli_epi32( w0, 16 ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 26, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 27, _mm256_srli_epi32( w1, 16 ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, w0 ) );
  _mm256_storeu_si256( out + 29, _mm256_srli_epi32( w0, 16 ) );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 30, _mm256_and_si256( mask, w1 ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w1, 16 ) );
}

/* we packed 256 17-bit values, touching 17 256-bit words, using 272 bytes */
inline void unpack256_17( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  17 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 131071 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 1,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 17 ),
                                                          _mm256_slli_epi32( w1, 15 ) ) ) );
  _mm256_storeu_si256( out + 2, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 2 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 3,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 19 ),
                                                          _mm256_slli_epi32( w0, 13 ) ) ) );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 5,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 21 ),
                                                          _mm256_slli_epi32( w1, 11 ) ) ) );
  _mm256_storeu_si256( out + 6, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 6 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 7,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 23 ),
                                                          _mm256_slli_epi32( w0, 9 ) ) ) );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 9,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 25 ),
                                                          _mm256_slli_epi32( w1, 7 ) ) ) );
  _mm256_storeu_si256( out + 10, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 10 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 11,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 27 ),
                                                          _mm256_slli_epi32( w0, 5 ) ) ) );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 12 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 13,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 29 ),
                                                          _mm256_slli_epi32( w1, 3 ) ) ) );
  _mm256_storeu_si256( out + 14, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 14 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 15,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 31 ),
                                                          _mm256_slli_epi32( w0, 1 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 16,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 16 ),
                                                          _mm256_slli_epi32( w1, 16 ) ) ) );
  _mm256_storeu_si256( out + 17, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 1 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 18,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 18 ),
                                                          _mm256_slli_epi32( w0, 14 ) ) ) );
  _mm256_storeu_si256( out + 19, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 3 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 20,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 20 ),
                                                          _mm256_slli_epi32( w1, 12 ) ) ) );
  _mm256_storeu_si256( out + 21, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 5 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 22,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 22 ),
                                                          _mm256_slli_epi32( w0, 10 ) ) ) );
  _mm256_storeu_si256( out + 23, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 7 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 24,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  _mm256_storeu_si256( out + 25, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 9 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 26,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 26 ),
                                                          _mm256_slli_epi32( w0, 6 ) ) ) );
  _mm256_storeu_si256( out + 27, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 11 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 28,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  _mm256_storeu_si256( out + 29, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 13 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 16 );
  _mm256_storeu_si256( out + 30,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 30 ),
                                                          _mm256_slli_epi32( w0, 2 ) ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w0, 15 ) );
}

/* we packed 256 18-bit values, touching 18 256-bit words, using 288 bytes */
inline void unpack256_18( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  18 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 262143 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 1,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 18 ),
                                                          _mm256_slli_epi32( w1, 14 ) ) ) );
  _mm256_storeu_si256( out + 2, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 3,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 22 ),
                                                          _mm256_slli_epi32( w0, 10 ) ) ) );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 5,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 26 ),
                                                          _mm256_slli_epi32( w1, 6 ) ) ) );
  _mm256_storeu_si256( out + 6, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 12 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 7,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 30 ),
                                                          _mm256_slli_epi32( w0, 2 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 8,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 16 ),
                                                          _mm256_slli_epi32( w1, 16 ) ) ) );
  _mm256_storeu_si256( out + 9, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 2 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 10,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 20 ),
                                                          _mm256_slli_epi32( w0, 12 ) ) ) );
  _mm256_storeu_si256( out + 11, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 6 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 12,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  _mm256_storeu_si256( out + 13, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 10 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 14,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  _mm256_storeu_si256( out + 15, _mm256_srli_epi32( w0, 14 ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, w1 ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 17,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 18 ),
                                                          _mm256_slli_epi32( w0, 14 ) ) ) );
  _mm256_storeu_si256( out + 18, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 19,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 22 ),
                                                          _mm256_slli_epi32( w1, 10 ) ) ) );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 21,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 26 ),
                                                          _mm256_slli_epi32( w0, 6 ) ) ) );
  _mm256_storeu_si256( out + 22, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 12 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 23,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 30 ),
                                                          _mm256_slli_epi32( w1, 2 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 24,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 16 ),
                                                          _mm256_slli_epi32( w0, 16 ) ) ) );
  _mm256_storeu_si256( out + 25, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 2 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 26,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 20 ),
                                                          _mm256_slli_epi32( w1, 12 ) ) ) );
  _mm256_storeu_si256( out + 27, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 6 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 16 );
  _mm256_storeu_si256( out + 28,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  _mm256_storeu_si256( out + 29, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 10 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 17 );
  _mm256_storeu_si256( out + 30,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w1, 14 ) );
}

/* we packed 256 19-bit values, touching 19 256-bit words, using 304 bytes */
inline void unpack256_19( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  19 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 524287 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 1,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 19 ),
                                                          _mm256_slli_epi32( w1, 13 ) ) ) );
  _mm256_storeu_si256( out + 2, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 6 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 3,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 25 ),
                                                          _mm256_slli_epi32( w0, 7 ) ) ) );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 12 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 5,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 31 ),
                                                          _mm256_slli_epi32( w1, 1 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 6,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 18 ),
                                                          _mm256_slli_epi32( w0, 14 ) ) ) );
  _mm256_storeu_si256( out + 7, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 5 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 8,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  _mm256_storeu_si256( out + 9, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 11 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 10,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 30 ),
                                                          _mm256_slli_epi32( w0, 2 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 11,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 17 ),
                                                          _mm256_slli_epi32( w1, 15 ) ) ) );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 13,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 23 ),
                                                          _mm256_slli_epi32( w0, 9 ) ) ) );
  _mm256_storeu_si256( out + 14, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 10 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 15,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 29 ),
                                                          _mm256_slli_epi32( w1, 3 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 16,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 16 ),
                                                          _mm256_slli_epi32( w0, 16 ) ) ) );
  _mm256_storeu_si256( out + 17, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 3 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 18,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 22 ),
                                                          _mm256_slli_epi32( w1, 10 ) ) ) );
  _mm256_storeu_si256( out + 19, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 9 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 20,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 21,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 15 ),
                                                          _mm256_slli_epi32( w1, 17 ) ) ) );
  _mm256_storeu_si256( out + 22, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 2 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 23,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 21 ),
                                                          _mm256_slli_epi32( w0, 11 ) ) ) );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 25,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 27 ),
                                                          _mm256_slli_epi32( w1, 5 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 16 );
  _mm256_storeu_si256( out + 26,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 14 ),
                                                          _mm256_slli_epi32( w0, 18 ) ) ) );
  _mm256_storeu_si256( out + 27, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 1 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 17 );
  _mm256_storeu_si256( out + 28,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 20 ),
                                                          _mm256_slli_epi32( w1, 12 ) ) ) );
  _mm256_storeu_si256( out + 29, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 7 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 18 );
  _mm256_storeu_si256( out + 30,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 26 ),
                                                          _mm256_slli_epi32( w0, 6 ) ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w0, 13 ) );
}

/* we packed 256 20-bit values, touching 20 256-bit words, using 320 bytes */
inline void unpack256_20( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  20 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 1048575 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 1,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 20 ),
                                                          _mm256_slli_epi32( w1, 12 ) ) ) );
  _mm256_storeu_si256( out + 2, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 3,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 4,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 16 ),
                                                          _mm256_slli_epi32( w1, 16 ) ) ) );
  _mm256_storeu_si256( out + 5, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 6,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  _mm256_storeu_si256( out + 7, _mm256_srli_epi32( w0, 12 ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, w1 ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 9,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 20 ),
                                                          _mm256_slli_epi32( w0, 12 ) ) ) );
  _mm256_storeu_si256( out + 10, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 11,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 12,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 16 ),
                                                          _mm256_slli_epi32( w0, 16 ) ) ) );
  _mm256_storeu_si256( out + 13, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 14,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  _mm256_storeu_si256( out + 15, _mm256_srli_epi32( w1, 12 ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 17,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 20 ),
                                                          _mm256_slli_epi32( w1, 12 ) ) ) );
  _mm256_storeu_si256( out + 18, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 19,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 20,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 16 ),
                                                          _mm256_slli_epi32( w1, 16 ) ) ) );
  _mm256_storeu_si256( out + 21, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 22,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  _mm256_storeu_si256( out + 23, _mm256_srli_epi32( w0, 12 ) );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, w1 ) );
  w0 = _mm256_lddqu_si256( compressed + 16 );
  _mm256_storeu_si256( out + 25,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 20 ),
                                                          _mm256_slli_epi32( w0, 12 ) ) ) );
  _mm256_storeu_si256( out + 26, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 17 );
  _mm256_storeu_si256( out + 27,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 18 );
  _mm256_storeu_si256( out + 28,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 16 ),
                                                          _mm256_slli_epi32( w0, 16 ) ) ) );
  _mm256_storeu_si256( out + 29, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 19 );
  _mm256_storeu_si256( out + 30,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w1, 12 ) );
}

/* we packed 256 21-bit values, touching 21 256-bit words, using 336 bytes */
inline void unpack256_21( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  21 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 2097151 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 1,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 21 ),
                                                          _mm256_slli_epi32( w1, 11 ) ) ) );
  _mm256_storeu_si256( out + 2, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 10 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 3,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 31 ),
                                                          _mm256_slli_epi32( w0, 1 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 4,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 20 ),
                                                          _mm256_slli_epi32( w1, 12 ) ) ) );
  _mm256_storeu_si256( out + 5, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 9 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 6,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 30 ),
                                                          _mm256_slli_epi32( w0, 2 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 7,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 19 ),
                                                          _mm256_slli_epi32( w1, 13 ) ) ) );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 9,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 29 ),
                                                          _mm256_slli_epi32( w0, 3 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 10,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 18 ),
                                                          _mm256_slli_epi32( w1, 14 ) ) ) );
  _mm256_storeu_si256( out + 11, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 7 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 12,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 13,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 17 ),
                                                          _mm256_slli_epi32( w1, 15 ) ) ) );
  _mm256_storeu_si256( out + 14, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 6 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 15,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 27 ),
                                                          _mm256_slli_epi32( w0, 5 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 16,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 16 ),
                                                          _mm256_slli_epi32( w1, 16 ) ) ) );
  _mm256_storeu_si256( out + 17, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 5 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 18,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 26 ),
                                                          _mm256_slli_epi32( w0, 6 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 19,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 15 ),
                                                          _mm256_slli_epi32( w1, 17 ) ) ) );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 21,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 25 ),
                                                          _mm256_slli_epi32( w0, 7 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 22,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 14 ),
                                                          _mm256_slli_epi32( w1, 18 ) ) ) );
  _mm256_storeu_si256( out + 23, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 3 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 16 );
  _mm256_storeu_si256( out + 24,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 17 );
  _mm256_storeu_si256( out + 25,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 13 ),
                                                          _mm256_slli_epi32( w1, 19 ) ) ) );
  _mm256_storeu_si256( out + 26, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 2 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 18 );
  _mm256_storeu_si256( out + 27,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 23 ),
                                                          _mm256_slli_epi32( w0, 9 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 19 );
  _mm256_storeu_si256( out + 28,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 12 ),
                                                          _mm256_slli_epi32( w1, 20 ) ) ) );
  _mm256_storeu_si256( out + 29, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 1 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 20 );
  _mm256_storeu_si256( out + 30,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 22 ),
                                                          _mm256_slli_epi32( w0, 10 ) ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w0, 11 ) );
}

/* we packed 256 22-bit values, touching 22 256-bit words, using 352 bytes */
inline void unpack256_22( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  22 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 4194303 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 1,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 22 ),
                                                          _mm256_slli_epi32( w1, 10 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 2,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 12 ),
                                                          _mm256_slli_epi32( w0, 20 ) ) ) );
  _mm256_storeu_si256( out + 3, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 2 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 4,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 5,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 14 ),
                                                          _mm256_slli_epi32( w0, 18 ) ) ) );
  _mm256_storeu_si256( out + 6, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 7,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 26 ),
                                                          _mm256_slli_epi32( w1, 6 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 8,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 16 ),
                                                          _mm256_slli_epi32( w0, 16 ) ) ) );
  _mm256_storeu_si256( out + 9, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 6 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 10,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 11,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 18 ),
                                                          _mm256_slli_epi32( w0, 14 ) ) ) );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 8 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 13,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 30 ),
                                                          _mm256_slli_epi32( w1, 2 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 14,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 20 ),
                                                          _mm256_slli_epi32( w0, 12 ) ) ) );
  _mm256_storeu_si256( out + 15, _mm256_srli_epi32( w0, 10 ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, w1 ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 17,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 22 ),
                                                          _mm256_slli_epi32( w0, 10 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 18,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 12 ),
                                                          _mm256_slli_epi32( w1, 20 ) ) ) );
  _mm256_storeu_si256( out + 19, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 2 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 20,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 21,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 14 ),
                                                          _mm256_slli_epi32( w1, 18 ) ) ) );
  _mm256_storeu_si256( out + 22, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 16 );
  _mm256_storeu_si256( out + 23,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 26 ),
                                                          _mm256_slli_epi32( w0, 6 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 17 );
  _mm256_storeu_si256( out + 24,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 16 ),
                                                          _mm256_slli_epi32( w1, 16 ) ) ) );
  _mm256_storeu_si256( out + 25, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 6 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 18 );
  _mm256_storeu_si256( out + 26,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 19 );
  _mm256_storeu_si256( out + 27,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 18 ),
                                                          _mm256_slli_epi32( w1, 14 ) ) ) );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 20 );
  _mm256_storeu_si256( out + 29,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 30 ),
                                                          _mm256_slli_epi32( w0, 2 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 21 );
  _mm256_storeu_si256( out + 30,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 20 ),
                                                          _mm256_slli_epi32( w1, 12 ) ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w1, 10 ) );
}

/* we packed 256 23-bit values, touching 23 256-bit words, using 368 bytes */
inline void unpack256_23( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  23 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 8388607 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 1,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 23 ),
                                                          _mm256_slli_epi32( w1, 9 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 2,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 14 ),
                                                          _mm256_slli_epi32( w0, 18 ) ) ) );
  _mm256_storeu_si256( out + 3, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 5 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 4,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 5,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 19 ),
                                                          _mm256_slli_epi32( w0, 13 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 6,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 10 ),
                                                          _mm256_slli_epi32( w1, 22 ) ) ) );
  _mm256_storeu_si256( out + 7, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 1 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 8,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 9,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 15 ),
                                                          _mm256_slli_epi32( w1, 17 ) ) ) );
  _mm256_storeu_si256( out + 10, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 6 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 11,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 29 ),
                                                          _mm256_slli_epi32( w0, 3 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 12,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 20 ),
                                                          _mm256_slli_epi32( w1, 12 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 13,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 11 ),
                                                          _mm256_slli_epi32( w0, 21 ) ) ) );
  _mm256_storeu_si256( out + 14, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 2 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 15,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 25 ),
                                                          _mm256_slli_epi32( w1, 7 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 16,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 16 ),
                                                          _mm256_slli_epi32( w0, 16 ) ) ) );
  _mm256_storeu_si256( out + 17, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 7 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 18,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 30 ),
                                                          _mm256_slli_epi32( w1, 2 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 19,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 21 ),
                                                          _mm256_slli_epi32( w0, 11 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 20,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 12 ),
                                                          _mm256_slli_epi32( w1, 20 ) ) ) );
  _mm256_storeu_si256( out + 21, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 3 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 16 );
  _mm256_storeu_si256( out + 22,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 26 ),
                                                          _mm256_slli_epi32( w0, 6 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 17 );
  _mm256_storeu_si256( out + 23,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 17 ),
                                                          _mm256_slli_epi32( w1, 15 ) ) ) );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 8 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 18 );
  _mm256_storeu_si256( out + 25,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 31 ),
                                                          _mm256_slli_epi32( w0, 1 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 19 );
  _mm256_storeu_si256( out + 26,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 22 ),
                                                          _mm256_slli_epi32( w1, 10 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 20 );
  _mm256_storeu_si256( out + 27,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 13 ),
                                                          _mm256_slli_epi32( w0, 19 ) ) ) );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 21 );
  _mm256_storeu_si256( out + 29,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 27 ),
                                                          _mm256_slli_epi32( w1, 5 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 22 );
  _mm256_storeu_si256( out + 30,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 18 ),
                                                          _mm256_slli_epi32( w0, 14 ) ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w0, 9 ) );
}

/* we packed 256 24-bit values, touching 24 256-bit words, using 384 bytes */
inline void unpack256_24( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  24 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 16777215 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 1,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 2,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 16 ),
                                                          _mm256_slli_epi32( w0, 16 ) ) ) );
  _mm256_storeu_si256( out + 3, _mm256_srli_epi32( w0, 8 ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, w1 ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 5,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 6,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 16 ),
                                                          _mm256_slli_epi32( w1, 16 ) ) ) );
  _mm256_storeu_si256( out + 7, _mm256_srli_epi32( w1, 8 ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 9,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 10,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 16 ),
                                                          _mm256_slli_epi32( w0, 16 ) ) ) );
  _mm256_storeu_si256( out + 11, _mm256_srli_epi32( w0, 8 ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, w1 ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 13,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 14,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 16 ),
                                                          _mm256_slli_epi32( w1, 16 ) ) ) );
  _mm256_storeu_si256( out + 15, _mm256_srli_epi32( w1, 8 ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 17,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 18,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 16 ),
                                                          _mm256_slli_epi32( w0, 16 ) ) ) );
  _mm256_storeu_si256( out + 19, _mm256_srli_epi32( w0, 8 ) );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 20, _mm256_and_si256( mask, w1 ) );
  w0 = _mm256_lddqu_si256( compressed + 16 );
  _mm256_storeu_si256( out + 21,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 17 );
  _mm256_storeu_si256( out + 22,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 16 ),
                                                          _mm256_slli_epi32( w1, 16 ) ) ) );
  _mm256_storeu_si256( out + 23, _mm256_srli_epi32( w1, 8 ) );
  w0 = _mm256_lddqu_si256( compressed + 18 );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 19 );
  _mm256_storeu_si256( out + 25,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 20 );
  _mm256_storeu_si256( out + 26,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 16 ),
                                                          _mm256_slli_epi32( w0, 16 ) ) ) );
  _mm256_storeu_si256( out + 27, _mm256_srli_epi32( w0, 8 ) );
  w1 = _mm256_lddqu_si256( compressed + 21 );
  _mm256_storeu_si256( out + 28, _mm256_and_si256( mask, w1 ) );
  w0 = _mm256_lddqu_si256( compressed + 22 );
  _mm256_storeu_si256( out + 29,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 23 );
  _mm256_storeu_si256( out + 30,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 16 ),
                                                          _mm256_slli_epi32( w1, 16 ) ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w1, 8 ) );
}

/* we packed 256 25-bit values, touching 25 256-bit words, using 400 bytes */
inline void unpack256_25( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  25 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 33554431 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 1,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 25 ),
                                                          _mm256_slli_epi32( w1, 7 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 2,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 18 ),
                                                          _mm256_slli_epi32( w0, 14 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 3,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 11 ),
                                                          _mm256_slli_epi32( w1, 21 ) ) ) );
  _mm256_storeu_si256( out + 4, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 5,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 29 ),
                                                          _mm256_slli_epi32( w0, 3 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 6,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 22 ),
                                                          _mm256_slli_epi32( w1, 10 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 7,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 15 ),
                                                          _mm256_slli_epi32( w0, 17 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 8,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 8 ),
                                                          _mm256_slli_epi32( w1, 24 ) ) ) );
  _mm256_storeu_si256( out + 9, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 1 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 10,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 26 ),
                                                          _mm256_slli_epi32( w0, 6 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 11,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 19 ),
                                                          _mm256_slli_epi32( w1, 13 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 12,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 12 ),
                                                          _mm256_slli_epi32( w0, 20 ) ) ) );
  _mm256_storeu_si256( out + 13, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 5 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 14,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 30 ),
                                                          _mm256_slli_epi32( w1, 2 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 15,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 23 ),
                                                          _mm256_slli_epi32( w0, 9 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 16,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 16 ),
                                                          _mm256_slli_epi32( w1, 16 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 17,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 9 ),
                                                          _mm256_slli_epi32( w0, 23 ) ) ) );
  _mm256_storeu_si256( out + 18, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 2 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 19,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 27 ),
                                                          _mm256_slli_epi32( w1, 5 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 16 );
  _mm256_storeu_si256( out + 20,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 20 ),
                                                          _mm256_slli_epi32( w0, 12 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 17 );
  _mm256_storeu_si256( out + 21,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 13 ),
                                                          _mm256_slli_epi32( w1, 19 ) ) ) );
  _mm256_storeu_si256( out + 22, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 6 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 18 );
  _mm256_storeu_si256( out + 23,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 31 ),
                                                          _mm256_slli_epi32( w0, 1 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 19 );
  _mm256_storeu_si256( out + 24,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 20 );
  _mm256_storeu_si256( out + 25,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 17 ),
                                                          _mm256_slli_epi32( w0, 15 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 21 );
  _mm256_storeu_si256( out + 26,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 10 ),
                                                          _mm256_slli_epi32( w1, 22 ) ) ) );
  _mm256_storeu_si256( out + 27, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 3 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 22 );
  _mm256_storeu_si256( out + 28,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 23 );
  _mm256_storeu_si256( out + 29,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 21 ),
                                                          _mm256_slli_epi32( w1, 11 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 24 );
  _mm256_storeu_si256( out + 30,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 14 ),
                                                          _mm256_slli_epi32( w0, 18 ) ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w0, 7 ) );
}

/* we packed 256 26-bit values, touching 26 256-bit words, using 416 bytes */
inline void unpack256_26( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  26 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 67108863 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 1,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 26 ),
                                                          _mm256_slli_epi32( w1, 6 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 2,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 20 ),
                                                          _mm256_slli_epi32( w0, 12 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 3,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 14 ),
                                                          _mm256_slli_epi32( w1, 18 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 4,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 8 ),
                                                          _mm256_slli_epi32( w0, 24 ) ) ) );
  _mm256_storeu_si256( out + 5, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 2 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 6,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 7,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 22 ),
                                                          _mm256_slli_epi32( w0, 10 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 8,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 16 ),
                                                          _mm256_slli_epi32( w1, 16 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 9,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 10 ),
                                                          _mm256_slli_epi32( w0, 22 ) ) ) );
  _mm256_storeu_si256( out + 10, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 11,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 30 ),
                                                          _mm256_slli_epi32( w1, 2 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 12,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 13,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 18 ),
                                                          _mm256_slli_epi32( w1, 14 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 14,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 12 ),
                                                          _mm256_slli_epi32( w0, 20 ) ) ) );
  _mm256_storeu_si256( out + 15, _mm256_srli_epi32( w0, 6 ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, w1 ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 17,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 26 ),
                                                          _mm256_slli_epi32( w0, 6 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 18,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 20 ),
                                                          _mm256_slli_epi32( w1, 12 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 16 );
  _mm256_storeu_si256( out + 19,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 14 ),
                                                          _mm256_slli_epi32( w0, 18 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 17 );
  _mm256_storeu_si256( out + 20,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 8 ),
                                                          _mm256_slli_epi32( w1, 24 ) ) ) );
  _mm256_storeu_si256( out + 21, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 2 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 18 );
  _mm256_storeu_si256( out + 22,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 19 );
  _mm256_storeu_si256( out + 23,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 22 ),
                                                          _mm256_slli_epi32( w1, 10 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 20 );
  _mm256_storeu_si256( out + 24,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 16 ),
                                                          _mm256_slli_epi32( w0, 16 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 21 );
  _mm256_storeu_si256( out + 25,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 10 ),
                                                          _mm256_slli_epi32( w1, 22 ) ) ) );
  _mm256_storeu_si256( out + 26, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 4 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 22 );
  _mm256_storeu_si256( out + 27,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 30 ),
                                                          _mm256_slli_epi32( w0, 2 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 23 );
  _mm256_storeu_si256( out + 28,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 24 );
  _mm256_storeu_si256( out + 29,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 18 ),
                                                          _mm256_slli_epi32( w0, 14 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 25 );
  _mm256_storeu_si256( out + 30,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 12 ),
                                                          _mm256_slli_epi32( w1, 20 ) ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w1, 6 ) );
}

/* we packed 256 27-bit values, touching 27 256-bit words, using 432 bytes */
inline void unpack256_27( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  27 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 134217727 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 1,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 27 ),
                                                          _mm256_slli_epi32( w1, 5 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 2,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 22 ),
                                                          _mm256_slli_epi32( w0, 10 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 3,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 17 ),
                                                          _mm256_slli_epi32( w1, 15 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 4,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 12 ),
                                                          _mm256_slli_epi32( w0, 20 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 5,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 7 ),
                                                          _mm256_slli_epi32( w1, 25 ) ) ) );
  _mm256_storeu_si256( out + 6, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 2 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 7,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 29 ),
                                                          _mm256_slli_epi32( w0, 3 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 8,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 9,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 19 ),
                                                          _mm256_slli_epi32( w0, 13 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 10,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 14 ),
                                                          _mm256_slli_epi32( w1, 18 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 11,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 9 ),
                                                          _mm256_slli_epi32( w0, 23 ) ) ) );
  _mm256_storeu_si256( out + 12, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 4 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 13,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 31 ),
                                                          _mm256_slli_epi32( w1, 1 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 14,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 26 ),
                                                          _mm256_slli_epi32( w0, 6 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 15,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 21 ),
                                                          _mm256_slli_epi32( w1, 11 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 16,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 16 ),
                                                          _mm256_slli_epi32( w0, 16 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 17,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 11 ),
                                                          _mm256_slli_epi32( w1, 21 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 16 );
  _mm256_storeu_si256( out + 18,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 6 ),
                                                          _mm256_slli_epi32( w0, 26 ) ) ) );
  _mm256_storeu_si256( out + 19, _mm256_and_si256( mask, _mm256_srli_epi32( w0, 1 ) ) );
  w1 = _mm256_lddqu_si256( compressed + 17 );
  _mm256_storeu_si256( out + 20,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 18 );
  _mm256_storeu_si256( out + 21,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 23 ),
                                                          _mm256_slli_epi32( w0, 9 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 19 );
  _mm256_storeu_si256( out + 22,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 18 ),
                                                          _mm256_slli_epi32( w1, 14 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 20 );
  _mm256_storeu_si256( out + 23,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 13 ),
                                                          _mm256_slli_epi32( w0, 19 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 21 );
  _mm256_storeu_si256( out + 24,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 8 ),
                                                          _mm256_slli_epi32( w1, 24 ) ) ) );
  _mm256_storeu_si256( out + 25, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 3 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 22 );
  _mm256_storeu_si256( out + 26,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 30 ),
                                                          _mm256_slli_epi32( w0, 2 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 23 );
  _mm256_storeu_si256( out + 27,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 25 ),
                                                          _mm256_slli_epi32( w1, 7 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 24 );
  _mm256_storeu_si256( out + 28,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 20 ),
                                                          _mm256_slli_epi32( w0, 12 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 25 );
  _mm256_storeu_si256( out + 29,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 15 ),
                                                          _mm256_slli_epi32( w1, 17 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 26 );
  _mm256_storeu_si256( out + 30,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 10 ),
                                                          _mm256_slli_epi32( w0, 22 ) ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w0, 5 ) );
}

/* we packed 256 28-bit values, touching 28 256-bit words, using 448 bytes */
inline void unpack256_28( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  28 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 268435455 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 1,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 2,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 3,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 20 ),
                                                          _mm256_slli_epi32( w1, 12 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 4,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 16 ),
                                                          _mm256_slli_epi32( w0, 16 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 5,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 12 ),
                                                          _mm256_slli_epi32( w1, 20 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 6,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 8 ),
                                                          _mm256_slli_epi32( w0, 24 ) ) ) );
  _mm256_storeu_si256( out + 7, _mm256_srli_epi32( w0, 4 ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 8, _mm256_and_si256( mask, w1 ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 9,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 10,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 11,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 20 ),
                                                          _mm256_slli_epi32( w0, 12 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 12,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 16 ),
                                                          _mm256_slli_epi32( w1, 16 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 13,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 12 ),
                                                          _mm256_slli_epi32( w0, 20 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 14,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 8 ),
                                                          _mm256_slli_epi32( w1, 24 ) ) ) );
  _mm256_storeu_si256( out + 15, _mm256_srli_epi32( w1, 4 ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 17,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 16 );
  _mm256_storeu_si256( out + 18,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 17 );
  _mm256_storeu_si256( out + 19,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 20 ),
                                                          _mm256_slli_epi32( w1, 12 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 18 );
  _mm256_storeu_si256( out + 20,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 16 ),
                                                          _mm256_slli_epi32( w0, 16 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 19 );
  _mm256_storeu_si256( out + 21,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 12 ),
                                                          _mm256_slli_epi32( w1, 20 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 20 );
  _mm256_storeu_si256( out + 22,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 8 ),
                                                          _mm256_slli_epi32( w0, 24 ) ) ) );
  _mm256_storeu_si256( out + 23, _mm256_srli_epi32( w0, 4 ) );
  w1 = _mm256_lddqu_si256( compressed + 21 );
  _mm256_storeu_si256( out + 24, _mm256_and_si256( mask, w1 ) );
  w0 = _mm256_lddqu_si256( compressed + 22 );
  _mm256_storeu_si256( out + 25,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 23 );
  _mm256_storeu_si256( out + 26,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 24 );
  _mm256_storeu_si256( out + 27,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 20 ),
                                                          _mm256_slli_epi32( w0, 12 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 25 );
  _mm256_storeu_si256( out + 28,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 16 ),
                                                          _mm256_slli_epi32( w1, 16 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 26 );
  _mm256_storeu_si256( out + 29,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 12 ),
                                                          _mm256_slli_epi32( w0, 20 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 27 );
  _mm256_storeu_si256( out + 30,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 8 ),
                                                          _mm256_slli_epi32( w1, 24 ) ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w1, 4 ) );
}

/* we packed 256 29-bit values, touching 29 256-bit words, using 464 bytes */
inline void unpack256_29( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  29 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 536870911 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 1,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 29 ),
                                                          _mm256_slli_epi32( w1, 3 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 2,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 26 ),
                                                          _mm256_slli_epi32( w0, 6 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 3,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 23 ),
                                                          _mm256_slli_epi32( w1, 9 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 4,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 20 ),
                                                          _mm256_slli_epi32( w0, 12 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 5,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 17 ),
                                                          _mm256_slli_epi32( w1, 15 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 6,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 14 ),
                                                          _mm256_slli_epi32( w0, 18 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 7,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 11 ),
                                                          _mm256_slli_epi32( w1, 21 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 8,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 8 ),
                                                          _mm256_slli_epi32( w0, 24 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 9,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 5 ),
                                                          _mm256_slli_epi32( w1, 27 ) ) ) );
  _mm256_storeu_si256( out + 10, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 2 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 11,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 31 ),
                                                          _mm256_slli_epi32( w0, 1 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 12,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 13,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 25 ),
                                                          _mm256_slli_epi32( w0, 7 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 14,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 22 ),
                                                          _mm256_slli_epi32( w1, 10 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 15,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 19 ),
                                                          _mm256_slli_epi32( w0, 13 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 16,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 16 ),
                                                          _mm256_slli_epi32( w1, 16 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 16 );
  _mm256_storeu_si256( out + 17,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 13 ),
                                                          _mm256_slli_epi32( w0, 19 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 17 );
  _mm256_storeu_si256( out + 18,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 10 ),
                                                          _mm256_slli_epi32( w1, 22 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 18 );
  _mm256_storeu_si256( out + 19,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 7 ),
                                                          _mm256_slli_epi32( w0, 25 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 19 );
  _mm256_storeu_si256( out + 20,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 4 ),
                                                          _mm256_slli_epi32( w1, 28 ) ) ) );
  _mm256_storeu_si256( out + 21, _mm256_and_si256( mask, _mm256_srli_epi32( w1, 1 ) ) );
  w0 = _mm256_lddqu_si256( compressed + 20 );
  _mm256_storeu_si256( out + 22,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 30 ),
                                                          _mm256_slli_epi32( w0, 2 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 21 );
  _mm256_storeu_si256( out + 23,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 27 ),
                                                          _mm256_slli_epi32( w1, 5 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 22 );
  _mm256_storeu_si256( out + 24,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 23 );
  _mm256_storeu_si256( out + 25,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 21 ),
                                                          _mm256_slli_epi32( w1, 11 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 24 );
  _mm256_storeu_si256( out + 26,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 18 ),
                                                          _mm256_slli_epi32( w0, 14 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 25 );
  _mm256_storeu_si256( out + 27,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 15 ),
                                                          _mm256_slli_epi32( w1, 17 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 26 );
  _mm256_storeu_si256( out + 28,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 12 ),
                                                          _mm256_slli_epi32( w0, 20 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 27 );
  _mm256_storeu_si256( out + 29,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 9 ),
                                                          _mm256_slli_epi32( w1, 23 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 28 );
  _mm256_storeu_si256( out + 30,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 6 ),
                                                          _mm256_slli_epi32( w0, 26 ) ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w0, 3 ) );
}

/* we packed 256 30-bit values, touching 30 256-bit words, using 480 bytes */
inline void unpack256_30( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  30 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 1073741823 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 1,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 30 ),
                                                          _mm256_slli_epi32( w1, 2 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 2,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 3,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 26 ),
                                                          _mm256_slli_epi32( w1, 6 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 4,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 5,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 22 ),
                                                          _mm256_slli_epi32( w1, 10 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 6,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 20 ),
                                                          _mm256_slli_epi32( w0, 12 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 7,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 18 ),
                                                          _mm256_slli_epi32( w1, 14 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 8,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 16 ),
                                                          _mm256_slli_epi32( w0, 16 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 9,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 14 ),
                                                          _mm256_slli_epi32( w1, 18 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 10,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 12 ),
                                                          _mm256_slli_epi32( w0, 20 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 11,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 10 ),
                                                          _mm256_slli_epi32( w1, 22 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 12,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 8 ),
                                                          _mm256_slli_epi32( w0, 24 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 13,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 6 ),
                                                          _mm256_slli_epi32( w1, 26 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 14,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 4 ),
                                                          _mm256_slli_epi32( w0, 28 ) ) ) );
  _mm256_storeu_si256( out + 15, _mm256_srli_epi32( w0, 2 ) );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 16, _mm256_and_si256( mask, w1 ) );
  w0 = _mm256_lddqu_si256( compressed + 16 );
  _mm256_storeu_si256( out + 17,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 30 ),
                                                          _mm256_slli_epi32( w0, 2 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 17 );
  _mm256_storeu_si256( out + 18,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 28 ),
                                                          _mm256_slli_epi32( w1, 4 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 18 );
  _mm256_storeu_si256( out + 19,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 26 ),
                                                          _mm256_slli_epi32( w0, 6 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 19 );
  _mm256_storeu_si256( out + 20,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 24 ),
                                                          _mm256_slli_epi32( w1, 8 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 20 );
  _mm256_storeu_si256( out + 21,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 22 ),
                                                          _mm256_slli_epi32( w0, 10 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 21 );
  _mm256_storeu_si256( out + 22,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 20 ),
                                                          _mm256_slli_epi32( w1, 12 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 22 );
  _mm256_storeu_si256( out + 23,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 18 ),
                                                          _mm256_slli_epi32( w0, 14 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 23 );
  _mm256_storeu_si256( out + 24,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 16 ),
                                                          _mm256_slli_epi32( w1, 16 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 24 );
  _mm256_storeu_si256( out + 25,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 14 ),
                                                          _mm256_slli_epi32( w0, 18 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 25 );
  _mm256_storeu_si256( out + 26,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 12 ),
                                                          _mm256_slli_epi32( w1, 20 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 26 );
  _mm256_storeu_si256( out + 27,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 10 ),
                                                          _mm256_slli_epi32( w0, 22 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 27 );
  _mm256_storeu_si256( out + 28,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 8 ),
                                                          _mm256_slli_epi32( w1, 24 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 28 );
  _mm256_storeu_si256( out + 29,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 6 ),
                                                          _mm256_slli_epi32( w0, 26 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 29 );
  _mm256_storeu_si256( out + 30,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 4 ),
                                                          _mm256_slli_epi32( w1, 28 ) ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w1, 2 ) );
}

/* we packed 256 31-bit values, touching 31 256-bit words, using 496 bytes */
inline void unpack256_31( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  31 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  __m256i const mask = _mm256_set1_epi32( 2147483647 );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, _mm256_and_si256( mask, w0 ) );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 1,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 31 ),
                                                          _mm256_slli_epi32( w1, 1 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 2,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 30 ),
                                                          _mm256_slli_epi32( w0, 2 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 3,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 29 ),
                                                          _mm256_slli_epi32( w1, 3 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 4,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 28 ),
                                                          _mm256_slli_epi32( w0, 4 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 5,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 27 ),
                                                          _mm256_slli_epi32( w1, 5 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 6,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 26 ),
                                                          _mm256_slli_epi32( w0, 6 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 7,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 25 ),
                                                          _mm256_slli_epi32( w1, 7 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 8,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 24 ),
                                                          _mm256_slli_epi32( w0, 8 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 9,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 23 ),
                                                          _mm256_slli_epi32( w1, 9 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 10,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 22 ),
                                                          _mm256_slli_epi32( w0, 10 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 11,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 21 ),
                                                          _mm256_slli_epi32( w1, 11 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 12,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 20 ),
                                                          _mm256_slli_epi32( w0, 12 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 13,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 19 ),
                                                          _mm256_slli_epi32( w1, 13 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 14,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 18 ),
                                                          _mm256_slli_epi32( w0, 14 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 15,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 17 ),
                                                          _mm256_slli_epi32( w1, 15 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 16 );
  _mm256_storeu_si256( out + 16,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 16 ),
                                                          _mm256_slli_epi32( w0, 16 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 17 );
  _mm256_storeu_si256( out + 17,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 15 ),
                                                          _mm256_slli_epi32( w1, 17 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 18 );
  _mm256_storeu_si256( out + 18,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 14 ),
                                                          _mm256_slli_epi32( w0, 18 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 19 );
  _mm256_storeu_si256( out + 19,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 13 ),
                                                          _mm256_slli_epi32( w1, 19 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 20 );
  _mm256_storeu_si256( out + 20,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 12 ),
                                                          _mm256_slli_epi32( w0, 20 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 21 );
  _mm256_storeu_si256( out + 21,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 11 ),
                                                          _mm256_slli_epi32( w1, 21 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 22 );
  _mm256_storeu_si256( out + 22,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 10 ),
                                                          _mm256_slli_epi32( w0, 22 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 23 );
  _mm256_storeu_si256( out + 23,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 9 ),
                                                          _mm256_slli_epi32( w1, 23 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 24 );
  _mm256_storeu_si256( out + 24,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 8 ),
                                                          _mm256_slli_epi32( w0, 24 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 25 );
  _mm256_storeu_si256( out + 25,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 7 ),
                                                          _mm256_slli_epi32( w1, 25 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 26 );
  _mm256_storeu_si256( out + 26,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 6 ),
                                                          _mm256_slli_epi32( w0, 26 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 27 );
  _mm256_storeu_si256( out + 27,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 5 ),
                                                          _mm256_slli_epi32( w1, 27 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 28 );
  _mm256_storeu_si256( out + 28,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 4 ),
                                                          _mm256_slli_epi32( w0, 28 ) ) ) );
  w1 = _mm256_lddqu_si256( compressed + 29 );
  _mm256_storeu_si256( out + 29,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w0, 3 ),
                                                          _mm256_slli_epi32( w1, 29 ) ) ) );
  w0 = _mm256_lddqu_si256( compressed + 30 );
  _mm256_storeu_si256( out + 30,
                       _mm256_and_si256( mask,
                                         _mm256_or_si256( _mm256_srli_epi32( w1, 2 ),
                                                          _mm256_slli_epi32( w0, 30 ) ) ) );
  _mm256_storeu_si256( out + 31, _mm256_srli_epi32( w0, 1 ) );
}

/* we packed 256 32-bit values, touching 32 256-bit words, using 512 bytes */
inline void unpack256_32( __m256i const* compressed, std::uint32_t* pout ) noexcept {
  /* we are going to access  32 256-bit words */
  __m256i w0, w1;
  __m256i* out = reinterpret_cast<__m256i*>( pout );
  w0 = _mm256_lddqu_si256( compressed );
  _mm256_storeu_si256( out + 0, w0 );
  w1 = _mm256_lddqu_si256( compressed + 1 );
  _mm256_storeu_si256( out + 1, w1 );
  w0 = _mm256_lddqu_si256( compressed + 2 );
  _mm256_storeu_si256( out + 2, w0 );
  w1 = _mm256_lddqu_si256( compressed + 3 );
  _mm256_storeu_si256( out + 3, w1 );
  w0 = _mm256_lddqu_si256( compressed + 4 );
  _mm256_storeu_si256( out + 4, w0 );
  w1 = _mm256_lddqu_si256( compressed + 5 );
  _mm256_storeu_si256( out + 5, w1 );
  w0 = _mm256_lddqu_si256( compressed + 6 );
  _mm256_storeu_si256( out + 6, w0 );
  w1 = _mm256_lddqu_si256( compressed + 7 );
  _mm256_storeu_si256( out + 7, w1 );
  w0 = _mm256_lddqu_si256( compressed + 8 );
  _mm256_storeu_si256( out + 8, w0 );
  w1 = _mm256_lddqu_si256( compressed + 9 );
  _mm256_storeu_si256( out + 9, w1 );
  w0 = _mm256_lddqu_si256( compressed + 10 );
  _mm256_storeu_si256( out + 10, w0 );
  w1 = _mm256_lddqu_si256( compressed + 11 );
  _mm256_storeu_si256( out + 11, w1 );
  w0 = _mm256_lddqu_si256( compressed + 12 );
  _mm256_storeu_si256( out + 12, w0 );
  w1 = _mm256_lddqu_si256( compressed + 13 );
  _mm256_storeu_si256( out + 13, w1 );
  w0 = _mm256_lddqu_si256( compressed + 14 );
  _mm256_storeu_si256( out + 14, w0 );
  w1 = _mm256_lddqu_si256( compressed + 15 );
  _mm256_storeu_si256( out + 15, w1 );
  w0 = _mm256_lddqu_si256( compressed + 16 );
  _mm256_storeu_si256( out + 16, w0 );
  w1 = _mm256_lddqu_si256( compressed + 17 );
  _mm256_storeu_si256( out + 17, w1 );
  w0 = _mm256_lddqu_si256( compressed + 18 );
  _mm256_storeu_si256( out + 18, w0 );
  w1 = _mm256_lddqu_si256( compressed + 19 );
  _mm256_storeu_si256( out + 19, w1 );
  w0 = _mm256_lddqu_si256( compressed + 20 );
  _mm256_storeu_si256( out + 20, w0 );
  w1 = _mm256_lddqu_si256( compressed + 21 );
  _mm256_storeu_si256( out + 21, w1 );
  w0 = _mm256_lddqu_si256( compressed + 22 );
  _mm256_storeu_si256( out + 22, w0 );
  w1 = _mm256_lddqu_si256( compressed + 23 );
  _mm256_storeu_si256( out + 23, w1 );
  w0 = _mm256_lddqu_si256( compressed + 24 );
  _mm256_storeu_si256( out + 24, w0 );
  w1 = _mm256_lddqu_si256( compressed + 25 );
  _mm256_storeu_si256( out + 25, w1 );
  w0 = _mm256_lddqu_si256( compressed + 26 );
  _mm256_storeu_si256( out + 26, w0 );
  w1 = _mm256_lddqu_si256( compressed + 27 );
  _mm256_storeu_si256( out + 27, w1 );
  w0 = _mm256_lddqu_si256( compressed + 28 );
  _mm256_storeu_si256( out + 28, w0 );
  w1 = _mm256_lddqu_si256( compressed + 29 );
  _mm256_storeu_si256( out + 29, w1 );
  w0 = _mm256_lddqu_si256( compressed + 30 );
  _mm256_storeu_si256( out + 30, w0 );
  w1 = _mm256_lddqu_si256( compressed + 31 );
  _mm256_storeu_si256( out + 31, w1 );
}
} // namespace
} // namespace detail
} // namespace riot::bitpack
