// SPDX-License-Identifier: BlueOak-1.0.0

#include <libnygma/dissect.hxx>
#include <libnygma/pcap-reassembler.hxx>
#include <libnygma/pcap-view.hxx>
#include <libriot/index-view.hxx>
#include <libunclassified/femtolog.hxx>
#include <libunclassified/format-timestamp.hxx>

#include <nygma/ny-command-reverse-slice-by.hxx>
#include <nygma/ny-command-support.hxx>

#include <chrono>
#include <cstdint>
#include <map>
#include "libriot/index-resultset.hxx"

extern "C" {
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
}

namespace nygma {

void ny_command_reverse_slice_by( reverse_slice_config const& config ) {

  auto const d = config._root == "" ? config._path.parent_path() : config._root;
  auto const f = config._path.filename().stem();
  auto const expected_base = d / f;

  flog( lvl::i, "slice.root = ", d );
  flog( lvl::i, "slice.expected_base = ", expected_base );

  if( config._key_iy.empty() ) {
    flog( lvl::e, "match id is empty; aborting" );
    return;
  }

  index_file_dependencies deps;
  deps.gather( d, expected_base );

  auto data = std::make_unique<block_view_16k>( config._path, block_flags::rd );

  nygma::pcap::with( std::move( data ), [&]( auto& pcap ) {
    using sparse_resultset_type = riot::sparse_resultset<riot::resultset_forward_type>;

    if( not pcap.valid() ) {
      flog( lvl::e, "unable to open pcap storage path = ", config._path );
      return;
    }
    // open output pcap or `stdout`
    auto os = config._out == "-" ? nygma::pcap_ostream{ STDOUT_FILENO }
                                 : nygma::pcap_ostream{ config._out };
    pcap::reassemble_begin( pcap, os );
    auto const key = static_cast<std::uint32_t>( std::stoul( config._key_iy ) );
    flog( lvl::i, "executing query = iy( ", config._key_iy, " ) | { i4, ix }" );
    deps.for_each_y( [&]( auto const index_files ) {
      auto [i4, ix, iy] = index_files;
      flog( lvl::v, "executing query on index files = { ", iy, ", ", i4, ", ", iy, " }" );
      auto const py = riot::make_poly_index_view( iy );
      auto const p4 = riot::make_poly_index_view( i4 );
      auto const px = riot::make_poly_index_view( ix );
      flog( lvl::v, "segment offset = ", py->segment_offset() );
      auto const rs = py->lookup_forward_32( key );
      flog( lvl::v, "forward lookup hits = ", rs.size() );
      auto const rev_rs = sparse_resultset_type::combine<&riot::resultset_forward_type::combine_or<>,
                                                         &riot::resultset_forward_type::combine_and<>>(
          p4->sparse_scan( rs ), px->sparse_scan( rs ) );
      flog( lvl::v, "reverse sparse-scan hits = ", rev_rs.size(), " ( @", rev_rs.segment_offset(), " )" );
      pcap::reassemble_stream( pcap, py->segment_offset(), rev_rs.cbegin(), rev_rs.cend(), os );
    } );
  } );
}
}
