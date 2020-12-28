// SPDX-License-Identifier: BlueOak-1.0.0

#pragma once

#include <libriot/index-builder.hxx>
#include <libriot/index-serializer.hxx>

#include <libriot/compress-bitpack-simd.hxx>
#include <libriot/compress-streamvbyte-simd.hxx>
#include <libriot/compress-streamvqb-simd.hxx>

#include <array>
#include <vector>

namespace riot {

//--streamvbyte---------------------------------------------------------------

template <typename OStream>
struct svb128d1_serializer //
  : compressing_serializer<OStream, compression_method::SVB128D1, streamvbyte::svb128d1_i128, compression_method::SVB128D1,
                           streamvbyte::svb128d1_i128> {};

template <typename OStream>
struct svb256d1_serializer //
  : compressing_serializer<OStream, compression_method::SVB256D1, streamvbyte::svb256d1_i128, compression_method::SVB256D1,
                           streamvbyte::svb256d1_i128> {};

template <typename OStream>
svb128d1_serializer( OStream& ) -> svb128d1_serializer<OStream>;

template <typename OStream>
svb256d1_serializer( OStream& ) -> svb256d1_serializer<OStream>;

//--streamvqb------------------------------------------------------------------

template <typename OStream>
struct svq128d1_serializer //
  : compressing_serializer<OStream, compression_method::SVQ4x0D1, streamvqb::svq128d1, compression_method::SVQ4x0D1,
                           streamvqb::svq128d1> {};

template <typename OStream>
svq128d1_serializer( OStream& ) -> svq128d1_serializer<OStream>;

//--bitpack--------------------------------------------------------------------

template <typename OStream>
struct bp256d1_serializer //
  : compressing_serializer<OStream, compression_method::BP256D1, bitpack::bp256d1, compression_method::BP256D1,
                           bitpack::bp256d1> {};

template <typename OStream>
bp256d1_serializer( OStream& ) -> bp256d1_serializer<OStream>;

template <typename OStream>
struct bp128d1_serializer //
  : compressing_serializer<OStream, compression_method::BP128D1, bitpack::bp128d1, compression_method::BP128D1,
                           bitpack::bp128d1> {};

template <typename OStream>
bp128d1_serializer( OStream& ) -> bp128d1_serializer<OStream>;

} // namespace riot
