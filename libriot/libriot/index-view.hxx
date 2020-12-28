// SPDX-License-Identifier: BlueOak-1.0.0

#pragma once

#include <libnygma/mmap.hxx>
#include <libriot/compress-bitpack-simd.hxx>
#include <libriot/compress-streamvbyte-simd.hxx>
#include <libriot/compress-vbyte.hxx>
#include <libriot/index-builder.hxx>
#include <libriot/index-resultset.hxx>
#include <libriot/index-serializer.hxx>
#include <libunclassified/bytestring.hxx>

#include <array>
#include <iterator>
#include <ostream>
#include <ratio>
#include <set>
#include <sstream>
#include <unordered_map>
#include <vector>

namespace riot {

namespace unsafe = unclassified::unsafe;
using bytestring_view = unclassified::bytestring_view;
using endianess = unclassified::endianess;

namespace detail {

template <compression_method::type CompressionMethod, std::size_t BlockLen>
struct raw {
  using integer_type = std::uint32_t;
  static constexpr compression_method::type COMPRESSION_METHOD = CompressionMethod;
  static constexpr endianess LE = endianess::LE;
  static constexpr std::size_t BLOCKLEN = BlockLen;
  static constexpr std::size_t estimate_compressed_size() noexcept {
    return sizeof( offset_type ) * BlockLen;
  }

  template <typename OutIt>
  static void decode( std::byte const* const in, std::size_t n, std::size_t m, OutIt out ) noexcept {
    auto const* p = in;
    auto const* const end = p + ( ( n >> 2 ) << 2 );
    auto i = m;
    while( p < end && i-- > 0 ) {
      *out++ = unsafe::rd32<LE>( p );
      p += 4;
    }
  }
};

template <compression_method::type CompressionMethod, std::size_t BlockLen>
struct raw_key128 {
  using integer_type = __uint128_t;
  static constexpr compression_method::type COMPRESSION_METHOD = CompressionMethod;
  static constexpr std::size_t BLOCKLEN = BlockLen;
  static constexpr std::size_t estimate_compressed_size() noexcept {
    return sizeof( offset_type ) * BlockLen;
  }

  template <typename OutIt>
  static void decode( std::byte const* const in, std::size_t n, std::size_t m, OutIt out ) noexcept {
    static_assert( sizeof( integer_type ) == 16 );
    auto const* p = in;
    auto const* const end = p + ( ( n >> 4 ) << 4 );
    auto i = m;
    while( p < end && i-- > 0 ) {
      // TODO: ensure correct endianess
      __uint128_t x;
      std::memcpy( &x, p, 16 );
      *out++ = x;
      p += 16;
    }
  }
};

template <compression_method::type CompressionMethod, typename Decode>
struct decode_wrapper {
  using integer_type = typename Decode::integer_type;
  static constexpr compression_method::type COMPRESSION_METHOD = CompressionMethod;
  static constexpr std::size_t BLOCKLEN = Decode::BLOCKLEN;
  static constexpr std::size_t estimate_compressed_size() noexcept {
    return Decode::estimate_compressed_size();
  }

  template <typename OutIt>
  static void decode( std::byte const* const in, std::size_t n, std::size_t m_, OutIt out ) noexcept {
    auto const m = std::min( m_, BLOCKLEN );
    integer_type tmp_out[BLOCKLEN];
    // the decoder might access 128bit or 256bit beyond `n`. this is ok-ish because the access ends up
    // in the key, offset and meta data section
    Decode::decode( in, n, tmp_out );
    std::copy( tmp_out, tmp_out + m, out );
  }
};

using svb128d1 = decode_wrapper<compression_method::SVB128D1, riot::streamvbyte::svb128d1_i128>;
using svb256d1 = decode_wrapper<compression_method::SVB256D1, riot::streamvbyte::svb256d1_i128>;
using bp128d1 = decode_wrapper<compression_method::BP128D1, riot::bitpack::bp128d1>;
using bp256d1 = decode_wrapper<compression_method::BP256D1, riot::bitpack::bp256d1>;
using raw128 = raw<compression_method::UC128, 128>;
using raw256 = raw<compression_method::UC256, 256>;

} // namespace detail

constexpr std::size_t METASZ = 32;
constexpr std::size_t META_OBLOCK_OFFSET = 20;
constexpr std::size_t META_KBLOCK_OFFSET = 24;
constexpr std::size_t META_KEYTY_OFFSET = 25;
constexpr std::size_t META_KMETHOD_OFFSET = 28;
constexpr std::size_t META_VMETHOD_OFFSET = 27;
constexpr std::size_t META_SEGMENT_OFFSET = 16;
constexpr std::uint32_t MAGIC = 0x13371337u;
constexpr std::uint32_t MAGIC2 = 0x41414141u;
constexpr endianess LE = endianess::LE;

// for forward lookups these are same always the same ...
using resultset_forward_value_type = std::uint32_t;
using resultset_forward_traits = detail::std_vector_traits<resultset_forward_value_type>;
using resultset_forward_type = resultset<resultset_forward_traits, detail::resultset_kind::FORWARD>;

// ... for reverse lookup not so much ...
using resultset_reverse_value_32 = std::uint32_t;
using resultset_reverse_value_64 = std::uint64_t;
using resultset_reverse_value_128 = __uint128_t;
using resultset_reverse_traits_32 = detail::std_vector_traits<resultset_reverse_value_32>;
using resultset_reverse_traits_64 = detail::std_vector_traits<resultset_reverse_value_64>;
using resultset_reverse_traits_128 = detail::std_vector_traits<resultset_reverse_value_128>;
using resultset_reverse_32 = resultset<resultset_reverse_traits_32, detail::resultset_kind::REVERSE>;
using resultset_reverse_64 = resultset<resultset_reverse_traits_64, detail::resultset_kind::REVERSE>;
using resultset_reverse_128 = resultset<resultset_reverse_traits_128, detail::resultset_kind::REVERSE>;

template <typename KeyType, typename VC>
class index_view {
 public:
  using key_type = KeyType;
  using value_type = resultset_forward_value_type;
  using resultset_reverse_traits = detail::std_vector_traits<key_type>;
  using resultset_reverse_type = resultset<resultset_reverse_traits, detail::resultset_kind::REVERSE>;
  using sparse_resulstset_type = sparse_resultset<resultset_forward_type>;
  using inverted_index_type = std::unordered_map<value_type, std::set<key_type>>;

 private:
  bytestring_view const _data;
  std::uint64_t const _segment_offset;
  std::vector<key_type> _keys;
  std::vector<value_type> _offsets;
  inverted_index_type _inverted_index;

 public:
  index_view( bytestring_view const data, std::uint64_t const segment_offset,
              std::vector<key_type>&& keys, std::vector<offset_type>&& offsets ) noexcept
    : _data{ data },
      _segment_offset{ segment_offset },
      _keys{ std::move( keys ) },
      _offsets{ std::move( offsets ) } {
    auto const truncate = std::min( _keys.size(), _offsets.size() );
    _keys.resize( truncate );
    _offsets.resize( truncate );
  }

  index_view( index_view const& ) = delete;
  index_view& operator=( index_view const& ) = delete;

  index_view( index_view&& ) = default;
  index_view& operator=( index_view&& ) = default;

 private:
  template <typename OutIt>
  bool decode( value_type const offset, OutIt out ) const noexcept {
    auto const* p = _data.begin() + offset;
    if( p + 1 + METASZ >= _data.end() ) { return false; }
    auto const* const end = _data.end() - METASZ;
    block_encoding enc{ *p++ };
    if( not ( enc._tag == block_type::CBLOCK and enc._type == block_subtype::CBEGIN ) ) { return false; }
    do {
      auto const n = enc._ulen == 0b11 ? 0u : enc._ulen + 1;
      auto const m = enc._clen + 1u;
      if( p + n + m > end ) { return false; }
      auto const uncompressed_size = enc._ulen == 0b11 ? VC::BLOCKLEN : vbyte::decode( p, enc._ulen );
      auto const compressed_size = vbyte::decode( p + n, enc._clen );
      if( p + n + m + compressed_size > end ) { return false; }
      VC::decode( p + n + m, compressed_size, uncompressed_size, out );
      p += n + m + compressed_size;
      enc._value = *p++;
    } while( p < end and enc._tag == block_type::CBLOCK and enc._type != block_subtype::CBEGIN );
    return true;
  }

 public:
  auto key_count() const noexcept { return _keys.size(); }
  constexpr auto segment_offset() const noexcept { return _segment_offset; }
  constexpr auto compression_method() const noexcept { return VC::COMPRESSION_METHOD; }
  constexpr auto const& keys() const noexcept { return _keys; }
  constexpr auto const& offsets() const noexcept { return _offsets; }

  template <typename OutIt>
  bool lookup_forward( key_type const k, OutIt out ) const noexcept {
    auto it = std::lower_bound( _keys.begin(), _keys.end(), k );
    if( it == _keys.end() || k < *it ) { return false; }
    auto const o = static_cast<std::size_t>( it - _keys.begin() );
    assert( o < _offsets.size() );
    return decode( _offsets[o], out );
  }

  resultset_forward_type lookup_forward( key_type const k ) const noexcept {
    resultset_forward_type::container_type values;
    auto const rc = lookup_forward( k, std::back_inserter( values ) );
    return resultset_forward_type{ _segment_offset, rc, std::move( values ) };
  }

  value_type compressed_size( key_type const k ) const noexcept {
    value_type last_offset = static_cast<value_type>( _data.size() - METASZ );
    auto it = std::lower_bound( _keys.begin(), _keys.end(), k );
    if( it == _keys.end() || k < *it ) { return 0; }
    auto const o = static_cast<std::size_t>( it - _keys.begin() );
    assert( o < _offsets.size() );
    auto const next_offset = o == _keys.size() - 1 ? last_offset : _offsets[o + 1];
    return next_offset - _offsets[o];
  }

  template <typename OutIt>
  void output_keys( OutIt& out ) const {
    value_type last_offset = static_cast<value_type>( _data.size() - METASZ );
    for( std::size_t i = 0; i < _keys.size(); i++ ) {
      std::ostringstream k_and_size;
      auto const next_offset = i == _keys.size() - 1 ? last_offset : _offsets.at( i + 1 );
      k_and_size << _keys[i];
      k_and_size << " : ";
      k_and_size << next_offset - _offsets.at( i );
      out = k_and_size.str();
    }
  }

  template <typename OutIt>
  void output_histogram( OutIt& out ) const {
    value_type last_offset = static_cast<value_type>( _data.size() - METASZ );
    for( std::size_t i = 0; i < _offsets.size(); i++ ) {
      auto const next_offset = i == _offsets.size() - 1 ? last_offset : _offsets[i + 1];
      out = next_offset - _offsets[i];
    }
  }

  //--reverse-lookup-using-scanning-------------------------------------------

  template <auto Combine>
  resultset_forward_type scan( resultset_forward_type const& values ) const noexcept {
    resultset_forward_type result{ _segment_offset, false };
    auto first = true;
    for( auto const o : _offsets ) {
      resultset_forward_type current;
      if( not decode( o, std::back_inserter( current.values() ) ) ) {
        return resultset_forward_type{ 0 };
      }
      // TODO: performance
      //   - no need to compute the actual intersection, a boolean result suffices
      if( auto const intersection = current & values; not intersection.empty() ) {
        if( first ) {
          first = false;
          result = std::move( current );
          continue;
        }
        result = Combine( std::move( result ), std::move( current ) );
      }
    }
    return result;
  }

  sparse_resulstset_type sparse_scan( resultset_forward_type const& values ) const noexcept {
    sparse_resulstset_type result{ _segment_offset };
    resultset_forward_type current;
    for( auto const o : _offsets ) {
      current._values.clear();
      if( not decode( o, std::back_inserter( current._values ) ) ) { return result; }
      auto const intersection = current & values;
      for( auto&& i : intersection.values() ) {
        result.bind<&resultset_forward_type::combine_or<>>( i, current.clone() );
      }
    }
    return result;
  }

  //--reverse-lookup-using-an-inverse-mapping---------------------------------

  // TODO: performance
  //
  void prepare_reverse_lookups() noexcept {
    if( not _inverted_index.empty() ) { return; }
    std::vector<value_type> values;
    for( auto const& k : _keys ) {
      values.clear();
      if( auto const rc = lookup_forward( k, std::back_inserter( values ) ); ! rc ) {
        _inverted_index.clear();
        return;
      }
      for( auto const& v : values ) { _inverted_index[v].insert( k ); }
    }
  }

  template <typename OutIt>
  bool lookup_inverse( value_type const v, OutIt out ) const noexcept {
    auto it = _inverted_index.find( v );
    if( it == _inverted_index.end() ) { return false; }
    std::copy( it->second.cbegin(), it->second.cend(), out );
    return true;
  }

  resultset_reverse_type lookup_inverse( value_type const v ) const noexcept {
    typename resultset_reverse_type::container_type keys;
    auto const rc = lookup_inverse( v, std::back_inserter( keys ) );
    return resultset_reverse_type{ _segment_offset, rc, std::move( keys ) };
  }

  // TODO: performance
  //
  resultset_forward_type lookup_reverse( value_type const v ) const noexcept {
    typename resultset_reverse_type::container_type keys;
    resultset_forward_type rs{ _segment_offset, true };
    if( auto const rc = lookup_inverse( v, std::back_inserter( keys ) ); ! rc ) {
      return resultset_forward_type{ 0, false };
    }
    resultset_forward_type combined{ 0, false };
    bool first = true;
    for( auto const k : keys ) {
      if( first ) {
        first = false;
        combined = std::move( lookup_forward( k ) );
        continue;
      }
      combined = std::move( combined & lookup_forward( k ) );
    }
    return combined;
  }
};

//--type-erasure-of-index_view<>----------------------------------------------

class poly_index_view {
  using key32_t = std::uint32_t;
  using key64_t = std::uint64_t;
  using key128_t = __uint128_t;

  using value_type = resultset_forward_type::value_type;
  using container_type = resultset_forward_traits::container_type;
  using sparse_resultset_type = sparse_resultset<resultset_forward_type>;

  struct base {
    virtual ~base() = default;
    virtual resultset_forward_type lookup_forward_32( key32_t const k ) noexcept = 0;
    virtual resultset_forward_type lookup_forward_64( key64_t const k ) noexcept = 0;
    virtual resultset_forward_type lookup_forward_128( key128_t const k ) noexcept = 0;
    virtual resultset_forward_type lookup_reverse( value_type const v ) noexcept = 0;
    virtual resultset_forward_type scan_and( resultset_forward_type const& v ) noexcept = 0;
    virtual resultset_forward_type scan_or( resultset_forward_type const& v ) noexcept = 0;
    virtual resultset_forward_type scan_complement( resultset_forward_type const& v ) noexcept = 0;
    virtual sparse_resultset_type sparse_scan( resultset_forward_type const& v ) noexcept = 0;
    virtual resultset_reverse_32 lookup_inverse_32( value_type const v ) noexcept = 0;
    virtual resultset_reverse_64 lookup_inverse_64( value_type const v ) noexcept = 0;
    virtual resultset_reverse_128 lookup_inverse_128( value_type const v ) noexcept = 0;
    virtual value_type compressed_size( key64_t const v ) const noexcept = 0;
    virtual value_type compressed_size_128( key128_t const v ) const noexcept = 0;
    virtual void prepare_reverse_lookups() noexcept = 0;
    virtual std::size_t sizeof_domain_value() const noexcept = 0;
    virtual compression_method::type compression_method() const noexcept = 0;
    virtual std::size_t size() const noexcept = 0;
    virtual std::uint64_t segment_offset() const noexcept = 0;
    virtual void output_keys( std::ostream& os ) const noexcept = 0;
    virtual void output_histogram( std::vector<value_type>& sizes ) const noexcept = 0;
  };

  template <typename T, typename VC>
  struct view final : base {
    index_view<T, VC> _view;
    view( index_view<T, VC> iv ) noexcept : _view{ std::move( iv ) } {}
    std::size_t size() const noexcept override { return _view.key_count(); }
    std::uint64_t segment_offset() const noexcept override { return _view.segment_offset(); }
    void prepare_reverse_lookups() noexcept override { return _view.prepare_reverse_lookups(); }
    std::size_t sizeof_domain_value() const noexcept override {
      return sizeof( typename index_view<T, VC>::key_type );
    }
    compression_method::type compression_method() const noexcept override { return _view.compression_method(); }

    void output_keys( std::ostream& os ) const noexcept override {
      // TODO: we want a transformation function
      //   - render keys as ip addresses
      //   - render keys as signature ids
      //   - ...
      if constexpr( sizeof( T ) < 16 ) {
        std::ostream_iterator<std::string> out{ os, "\n" };
        _view.output_keys( out );
      } else {
        os << "<index_view::output_keys: 128bit keys unimplemented>";
      }
    }

    void output_histogram( std::vector<value_type>& sizes ) const noexcept override {
      auto it = std::back_inserter( sizes );
      _view.output_histogram( it );
    }

    //--forward-lookup-wrappers-----------------------------------------------

    resultset_forward_type lookup_forward_32( key32_t const k ) noexcept override {
      if constexpr( std::is_same_v<key32_t, typename index_view<T, VC>::key_type> ) {
        return _view.lookup_forward( k );
      }
      return resultset_forward_type{ 0 };
    }

    resultset_forward_type lookup_forward_64( key64_t const k ) noexcept override {
      if constexpr( std::is_same_v<key64_t, typename index_view<T, VC>::key_type> ) {
        return _view.lookup_forward( k );
      }
      return resultset_forward_type{ 0 };
    }

    resultset_forward_type lookup_forward_128( key128_t const k ) noexcept override {
      if constexpr( std::is_same_v<key128_t, typename index_view<T, VC>::key_type> ) {
        return _view.lookup_forward( k );
      }
      return resultset_forward_type{ 0 };
    }

    value_type compressed_size( key64_t const k ) const noexcept override {
      if constexpr( std::is_same_v<key128_t, typename index_view<T, VC>::key_type> ) { return 0; }
      return _view.compressed_size( static_cast<typename index_view<T, VC>::key_type>( k ) );
    }

    value_type compressed_size_128( key128_t const k ) const noexcept override {
      if constexpr( std::is_same_v<key128_t, typename index_view<T, VC>::key_type> ) {
        return _view.compressed_size( k );
      }
      return 0;
    }

    //--reverse-lookup-wrappers-----------------------------------------------

    resultset_forward_type scan_and( resultset_forward_type const& v ) noexcept override {
      return _view.template scan<&resultset_forward_type::combine_and<>>( v );
    }

    resultset_forward_type scan_or( resultset_forward_type const& v ) noexcept override {
      return _view.template scan<&resultset_forward_type::combine_or<>>( v );
    }

    resultset_forward_type scan_complement( resultset_forward_type const& v ) noexcept override {
      return _view.template scan<&resultset_forward_type::combine_complement<>>( v );
    }

    sparse_resultset_type sparse_scan( resultset_forward_type const& v ) noexcept override {
      return _view.sparse_scan( v );
    }

    // make sure `prepare_reverse_lookups()` has been called before
    resultset_forward_type lookup_reverse( value_type const v ) noexcept override {
      return _view.lookup_reverse( v );
    }

    resultset_reverse_32 lookup_inverse_32( value_type const v ) noexcept override {
      if constexpr( std::is_same_v<resultset_reverse_32,
                                   typename index_view<T, VC>::resultset_reverse_type> ) {
        return _view.lookup_inverse( v );
      }
      return resultset_reverse_32{ 0 };
    }

    resultset_reverse_64 lookup_inverse_64( value_type const v ) noexcept override {
      if constexpr( std::is_same_v<resultset_reverse_64,
                                   typename index_view<T, VC>::resultset_reverse_type> ) {
        return _view.lookup_inverse( v );
      }
      return resultset_reverse_64{ 0 };
    }

    resultset_reverse_128 lookup_inverse_128( value_type const v ) noexcept override {
      if constexpr( std::is_same_v<resultset_reverse_128,
                                   typename index_view<T, VC>::resultset_reverse_type> ) {
        return _view.lookup_inverse( v );
      }
      return resultset_reverse_128{ 0 };
    }
  };

  std::unique_ptr<base> _p;

 public:
  template <typename T, typename VC>
  poly_index_view( index_view<T, VC>&& iv )
    : _p{ std::make_unique<view<T, VC>>( std::forward<index_view<T, VC>>( iv ) ) } {}

  poly_index_view( poly_index_view const& ) = delete;
  poly_index_view& operator=( poly_index_view const& ) = delete;

  poly_index_view( poly_index_view&& ) noexcept = default;
  poly_index_view& operator=( poly_index_view&& ) noexcept = default;

  auto size() const noexcept { return _p->size(); }
  auto key_count() const noexcept { return _p->size(); }
  auto sizeof_domain_value() const noexcept { return _p->sizeof_domain_value(); }
  std::uint64_t segment_offset() const noexcept { return _p->segment_offset(); }
  void prepare_reverse_lookups() noexcept { return _p->prepare_reverse_lookups(); }
  void output_keys( std::ostream& os ) const noexcept { return _p->output_keys( os ); }
  auto compression_method() const noexcept { return _p->compression_method(); }
  void output_histogram( std::vector<value_type>& sizes ) const noexcept {
    return _p->output_histogram( sizes );
  }

  resultset_forward_type scan_and( resultset_forward_type const& values ) const noexcept {
    return _p->scan_and( values );
  }

  resultset_forward_type scan_or( resultset_forward_type const& values ) const noexcept {
    return _p->scan_or( values );
  }

  resultset_forward_type scan_complement( resultset_forward_type const& values ) const noexcept {
    return _p->scan_complement( values );
  }

  sparse_resultset_type sparse_scan( resultset_forward_type const& v ) const noexcept {
    return _p->sparse_scan( v );
  }

  resultset_forward_type lookup_forward_32( key32_t const k ) const noexcept {
    return _p->lookup_forward_32( k );
  }

  resultset_forward_type lookup_forward_64( key64_t const k ) const noexcept {
    return _p->lookup_forward_64( k );
  }

  resultset_forward_type lookup_forward_128( key128_t const k ) const noexcept {
    return _p->lookup_forward_128( k );
  }

  value_type compressed_size_128( key128_t const k ) const noexcept {
    return _p->compressed_size_128( k );
  }

  value_type compressed_size( key64_t const k ) const noexcept { return _p->compressed_size( k ); }

  resultset_forward_type lookup_reverse( value_type const v ) const noexcept {
    return _p->lookup_reverse( v );
  }

  resultset_reverse_32 lookup_inverse_32( value_type const v ) const noexcept {
    return _p->lookup_inverse_32( v );
  }

  resultset_reverse_64 lookup_inverse_64( value_type const v ) const noexcept {
    return _p->lookup_inverse_64( v );
  }

  resultset_reverse_128 lookup_inverse_128( value_type const v ) const noexcept {
    return _p->lookup_inverse_128( v );
  }

#define DISPTACH( type, method, fn )                                                                  \
  do {                                                                                                \
    auto const& index = static_cast<view<type, method> const*>( _p.get() )->_view;                    \
    fn( index );                                                                                      \
  } while( false )

#define DISPATCH_COMPRESSION_METHOD( type, fn )                                                       \
  do {                                                                                                \
    switch( _p->compression_method() ) {                                                              \
      case method::UC128: DISPTACH( type, detail::raw128, fn ); break;                                \
      case method::UC256: DISPTACH( type, detail::raw256, fn ); break;                                \
      case method::SVB128D1: DISPTACH( type, detail::svb128d1, fn ); break;                           \
      case method::SVB256D1: DISPTACH( type, detail::svb256d1, fn ); break;                           \
      case method::BP128D1: DISPTACH( type, detail::bp128d1, fn ); break;                             \
      case method::BP256D1: DISPTACH( type, detail::bp256d1, fn ); break;                             \
      default: break;                                                                                 \
    }                                                                                                 \
  } while( false )

  template <typename Fn>
  void map( Fn const fn ) const {
    switch( _p->sizeof_domain_value() ) {
      case 4: DISPATCH_COMPRESSION_METHOD( key32_t, fn ); break;
      case 16: DISPATCH_COMPRESSION_METHOD( key128_t, fn ); break;
      default: return;
    }
  }
#undef DISPATCH_COMPRESSION_METHOD
#undef DISPTACH
};

//--opening-/-constructing-an-index-view----------------------------------------------------

namespace detail {

template <typename Compressor, typename OutIt>
void build_oblock( bytestring_view const data, OutIt out ) {
  auto const sz = data.size();
  auto const* p = data.data();
  auto const* const end = p + sz - METASZ;
  auto const offset_block = unsafe::rd32<LE>( p + sz - META_OBLOCK_OFFSET );
  if( offset_block + METASZ > sz ) { throw std::runtime_error( "INVALID_OFFSETBLOCK" ); }
  p += offset_block;
  while( p < end ) {
    block_encoding const enc{ p[0] };
    if( enc._tag != block_type::OBLOCK ) { break; }
    p++;
    auto const uncompressed_size = enc._ulen == 0b11 ? Compressor::BLOCKLEN
                                                     : vbyte::decode( p, enc._ulen );
    auto const n = enc._ulen == 0b11 ? 0u : enc._ulen + 1;
    auto const m = enc._clen + 1u;
    auto const compressed_size = vbyte::decode( p + n, enc._clen );
    if( p + n + m + compressed_size > end ) { throw std::runtime_error( "INVALID_OFFSETBLOCK" ); }
    Compressor::decode( p + n + m, compressed_size, uncompressed_size, out );
    p += n + m + compressed_size;
  }
}

template <typename KeyCompressor, typename OutIt>
void build_kblock( bytestring_view const data, OutIt out ) {
  auto const sz = data.size();
  auto const* p = data.data();
  auto const* const end = p + sz - METASZ;
  auto const key_block = unsafe::rd32<LE>( p + sz - META_KBLOCK_OFFSET );
  if( key_block + METASZ > sz ) { throw std::runtime_error( "INVALID_KEYBLOCK" ); }
  p += key_block;
  while( p < end ) {
    block_encoding const enc{ p[0] };
    if( enc._tag != block_type::KBLOCK ) { break; }
    p++;
    auto const uncompressed_size = enc._ulen == 0b11 ? KeyCompressor::BLOCKLEN
                                                     : vbyte::decode( p, enc._ulen );
    auto const n = enc._ulen == 0b11 ? 0u : enc._ulen + 1;
    auto const m = enc._clen + 1u;
    auto const compressed_size = vbyte::decode( p + n, enc._clen );
    if( p + n + m + compressed_size > end ) { throw std::runtime_error( "INVALID_KEYBLOCK" ); }
    KeyCompressor::decode( p + n + m, compressed_size, uncompressed_size, out );
    p += n + m + compressed_size;
  }
}

template <typename KC, typename VC, typename F>
static auto from( bytestring_view const data, std::uint64_t const segment_offset, F const f ) {
  using key_t = typename KC::integer_type;
  std::vector<key_t> keys;
  std::vector<offset_type> offsets;
  detail::build_kblock<KC>( data, std::back_inserter( keys ) );
  detail::build_oblock<VC>( data, std::back_inserter( offsets ) );
  return f( index_view<key_t, VC>( data, segment_offset, std::move( keys ), std::move( offsets ) ) );
}

#define DISPATCH_VALUE_COMPRESSION( m )                                                               \
  do {                                                                                                \
    switch( m ) {                                                                                     \
      case method::UC128: return from<KC, detail::raw128>( data, meta.segment_offset, f );            \
      case method::UC256: return from<KC, detail::raw256>( data, meta.segment_offset, f );            \
      case method::SVB128D1: return from<KC, detail::svb128d1>( data, meta.segment_offset, f );       \
      case method::SVB256D1: return from<KC, detail::svb256d1>( data, meta.segment_offset, f );       \
      case method::BP128D1: return from<KC, detail::bp128d1>( data, meta.segment_offset, f );         \
      case method::BP256D1: return from<KC, detail::bp256d1>( data, meta.segment_offset, f );         \
      default: throw std::runtime_error( "UNSUPPORTED_VALUE_COMPRESSION_METHOD" );                    \
    }                                                                                                 \
  } while( false )

template <typename F>
static auto from( bytestring_view const data, F const f ) {
  auto const sz = data.size();
  if( sz < METASZ ) { throw std::runtime_error( "INVALID_FILESIZE" ); }
  struct meta {
    std::uint32_t magic0;
    std::uint8_t kmethod;
    std::uint8_t vmethod;
    std::uint8_t reserved;
    std::uint8_t keyty;
    std::uint32_t kblock_offset;
    std::uint32_t oblock_voffset;
    std::uint64_t segment_offset;
    std::uint32_t magic1;
    std::uint32_t magic2;
  } meta;

  auto is = data.template istream_at<LE>( sz - METASZ );
  is >> meta.magic0 >> meta.kmethod >> meta.vmethod >> meta.reserved >> meta.keyty >>
      meta.kblock_offset >> meta.oblock_voffset >> meta.segment_offset >> meta.magic1 >> meta.magic2;

  if( meta.magic0 != MAGIC ) { throw std::runtime_error( "INVALID_MAGIC" ); }
  if( meta.keyty != 0b01 && meta.keyty != 0b11 ) { throw std::runtime_error( "INVALID_KEYTYPE" ); }

  // clang-format off
  if( meta.keyty == 0b01 ) {
    switch( meta.kmethod ) {
      case compression_method::UC128: { using KC = detail::raw128; DISPATCH_VALUE_COMPRESSION( meta.vmethod ); }
      case compression_method::UC256: { using KC = detail::raw256; DISPATCH_VALUE_COMPRESSION( meta.vmethod ); }
      case compression_method::SVB128D1: { using KC = detail::svb128d1; DISPATCH_VALUE_COMPRESSION( meta.vmethod ); }
      case compression_method::SVB256D1: { using KC = detail::svb256d1; DISPATCH_VALUE_COMPRESSION( meta.vmethod ); }
      case compression_method::BP128D1: { using KC = detail::bp128d1; DISPATCH_VALUE_COMPRESSION( meta.vmethod ); }
      case compression_method::BP256D1: { using KC = detail::bp256d1; DISPATCH_VALUE_COMPRESSION( meta.vmethod ); }
      default: throw std::runtime_error( "UNSUPPORTED_32BIT_KEY_COMPRESSION_METHOD" );
    }
  } else {
    switch( meta.kmethod ) {
      case compression_method::UC128: { using KC = detail::raw_key128<compression_method::UC128, 128>; DISPATCH_VALUE_COMPRESSION( meta.vmethod ); }
      case compression_method::UC256: { using KC = detail::raw_key128<compression_method::UC256, 256>; DISPATCH_VALUE_COMPRESSION( meta.vmethod ); }
      default: throw std::runtime_error( "UNSUPPORTED_128BIT_KEY_COMPRESSION_METHOD" );
    }
  }
  // clang-format on
}

#undef DISPATCH_VALUE_COMPRESSION

namespace {

inline auto make_poly_index_view( bytestring_view const data ) {
  return detail::from( data, []( auto&& iv ) { return poly_index_view( std::move( iv ) ); } );
}

} // namespace

} // namespace detail

class index_view_handle {

  std::unique_ptr<nygma::mmap_view> _map;
  poly_index_view _index;

 public:
  index_view_handle( std::filesystem::path const& path )
    : _map{ std::make_unique<nygma::mmap_view>( path ) },
      _index{ detail::make_poly_index_view( _map->view() ) } {}

  // the index view wraps `data` non-owning. make sure it outlasts
  // the lifetime of the index view
  //
  index_view_handle( bytestring_view const data ) : _index{ detail::make_poly_index_view( data ) } {}

  index_view_handle( index_view_handle const& ) = delete;
  index_view_handle& operator=( index_view_handle const& ) = delete;

  index_view_handle( index_view_handle&& ) noexcept = default;
  index_view_handle& operator=( index_view_handle&& ) noexcept = default;

  auto const& operator*() const noexcept { return _index; }
  auto const* operator->() const noexcept { return &_index; }
  auto& operator*() noexcept { return _index; }
  auto* operator->() noexcept { return &_index; }
};

namespace {

inline auto make_poly_index_view( std::filesystem::path const& p ) { return index_view_handle{ p }; }

// the index view wraps `data` non-owning. make sure it outlasts
// the lifetime of the index view
//
inline auto make_poly_index_view( bytestring_view const data ) { return index_view_handle{ data }; }

} // namespace

} // namespace riot
