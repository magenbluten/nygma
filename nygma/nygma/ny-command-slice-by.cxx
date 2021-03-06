// SPDX-License-Identifier: BlueOak-1.0.0

#include <libnygma/dissect.hxx>
#include <libnygma/pcap-reassembler.hxx>
#include <libnygma/pcap-view.hxx>
#include <libriot/index-view.hxx>
#include <libunclassified/femtolog.hxx>
#include <libunclassified/format-timestamp.hxx>

#include <nygma/ny-command-slice-by.hxx>
#include <nygma/ny-command-support.hxx>

#include <chrono>
#include <cstdint>
#include <map>

extern "C" {
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
}

namespace nygma {

void ny_command_slice_by( slice_config const& config ) {

  auto const d = config._root == "" ? config._path.parent_path() : config._root;
  auto const f = config._path.filename().stem();
  auto const expected_base = d / f;

  flog( lvl::i, "slice.root = ", d );
  flog( lvl::i, "slice.expected_base = ", expected_base );

  index_file_dependencies deps;
  deps.gather( d, expected_base );

  auto data = std::make_unique<block_view_16k>( config._path, block_flags::rd );

  nygma::pcap::with( std::move( data ), [&]( auto& pcap ) {
    if( not pcap.valid() ) {
      flog( lvl::e, "unable to open pcap storage path = ", config._path );
      return;
    }
    // open output pcap or `stdout`
    auto os = config._out == "-" ? nygma::pcap_ostream{ STDOUT_FILENO }
                                 : nygma::pcap_ostream{ config._out };
    pcap::reassemble_begin( pcap, os );

    auto const stream = [&pcap, &os]( auto const& p, auto const key ) {
      flog( lvl::v, "executing query on index file = ", p );
      auto iv = riot::make_poly_index_view( p );
      flog( lvl::v, "@segment offset = ", iv->segment_offset() );
      auto const rs = iv->lookup_forward_32( key );
      flog( lvl::v, "hits = ", rs.values().size() );
      pcap::reassemble_stream( pcap, rs.segment_offset(), rs.cbegin(), rs.cend(), os );
    };

    auto const stream_ex = [&pcap, &os]( auto const& p, auto const key ) {
      flog( lvl::v, "executing query on index file = ", p );
      auto iv = riot::make_poly_index_view( p );
      flog( lvl::v, "@segment offset = ", iv->segment_offset() );
      auto const rs = iv->lookup_forward_128( key );
      flog( lvl::v, "hits = ", rs.values().size() );
      pcap::reassemble_stream( pcap, rs.segment_offset(), rs.cbegin(), rs.cend(), os );
    };

    if( not config._key_i4.empty() ) {
      auto const key = ntohl( ::inet_addr( config._key_i4.c_str() ) );
      flog( lvl::i, "executing query = i4( ", config._key_i4, " ) ( ", key, " )" );
      for( auto& p : deps._i4 ) { stream( p, key ); }
    }

    if( not config._key_i6.empty() ) {
      __uint128_t key;
      if( auto const rc = ::inet_pton( AF_INET6, config._key_i6.c_str(), &key ); rc <= 0 ) {
        flog( lvl::e, "invalid i6 key = ", config._key_i6 );
        throw std::runtime_error( "invalid i6 key" );
      }
      flog( lvl::i, "executing query = i6( ", config._key_i6, " )" );
      for( auto& p : deps._i6 ) { stream_ex( p, key ); }
    }

    if( not config._key_ix.empty() ) {
      auto const key = static_cast<std::uint32_t>( std::stoul( config._key_ix ) );
      flog( lvl::i, "executing query = ix( ", config._key_ix, " ) ( ", key, " )" );
      for( auto& p : deps._ix ) { stream( p, key ); }
    }

    if( not config._key_iy.empty() ) {
      auto const key = static_cast<std::uint32_t>( std::stoul( config._key_iy ) );
      flog( lvl::i, "executing query = iy( ", config._key_iy, " ) ( ", key, " )" );
      for( auto& p : deps._iy ) { stream( p, key ); }
    }
  } );
}

} // namespace nygma
