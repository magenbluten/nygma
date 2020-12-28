// License: RoundRobin-1.0.0

#include <imgui/imgui.h>

#include <libnygma/dissect.hxx>
#include <libnygma/pcap-reassembler.hxx>
#include <libnygma/pcap-view.hxx>
#include <libriot/index-view.hxx>
#include <libriot/query-evaluator.hxx>
#include <libriot/query-parser.hxx>
#include <libunclassified/femtolog.hxx>

#include <the-0wls/0wl-command-ui.hxx>
#include <the-0wls/0wl-parse-pdml.hxx>
#include <the-0wls/0wl-vulkan.hxx>

#ifdef __clang__
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif

#include <subprocess/subprocess.h>

#ifdef __clang__
#  pragma clang diagnostic pop
#endif

#include <array>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>

namespace owl {
struct index_file_dependencies {
  std::vector<std::filesystem::path> _i4;
  std::vector<std::filesystem::path> _i6;
  std::vector<std::filesystem::path> _ix;
  std::vector<std::filesystem::path> _iy;

  void gather(std::filesystem::path const& root, std::filesystem::path const& strem);

  template <typename F>
  void
  for_each(F const f){
    auto const sz = _i4.size();
    if(_ix.size() != sz){
      throw std::runtime_error("index_file_dependencies::for_each: number of index files differ");
    }
    for(std::size_t i = 0; i < sz; i++){ f(std::forward_as_tuple(_i4[i], _ix[i])); }
  }

  template <typename F>
  void
  for_each_y(F const f){
    auto const sz = _i4.size();
    if(_ix.size() != sz or _iy.size() != sz){
      throw std::runtime_error("index_file_dependencies::for_each_y: number of index files differ");
    }
    for(std::size_t i = 0; i < sz; i++){ f(std::forward_as_tuple(_i4[i], _ix[i], _iy[i])); }
  }
};

void
index_file_dependencies::gather(std::filesystem::path const& root,
                                std::filesystem::path const& stem){
  auto const prefix = stem.string();
  for(auto& f : std::filesystem::directory_iterator(root)){
    std::error_code ec;
    if(not f.is_regular_file(ec)){ continue; }
    auto const p = f.path();
    flog(lvl::d, "visting file = ", p);
    if(not p.has_extension()){ continue; }
    if(not p.string().starts_with(prefix)){ continue; }
    auto const ext = p.extension();
    if(ext == ".i4"){
      _i4.push_back(p);
    }else if(ext == ".i6"){
      _i6.push_back(p);
    }else if(ext == ".ix"){
      _ix.push_back(p);
    }else if(ext == ".iy"){
      _iy.push_back(p);
    }
  }

  std::sort(_i4.begin(), _i4.end());
  std::sort(_i6.begin(), _i6.end());
  std::sort(_ix.begin(), _ix.end());
  std::sort(_iy.begin(), _iy.end());

  flog(lvl::m, "index_file_dependencies._count_i4 = ", _i4.size());
  flog(lvl::m, "index_file_dependencies._count_i6 = ", _i6.size());
  flog(lvl::m, "index_file_dependencies._count_ix = ", _ix.size());
  flog(lvl::m, "index_file_dependencies._count_iy = ", _iy.size());
}

namespace draw {
struct state {
  using active_object = unclassified::femtolog::detail::aktor;

  static constexpr char const* INITIAL_RULES = R"(

1:/fr\.jpg.*HTTP/i
2:'www.mybusinessdoc.com'
3:'1.web-counter.info'
4:/GET.*HTTP/1/i

###########################################

# regexp patterns for stateless matching:
#   id:/.../
#   1:/GET.*\.exe.*HTTP/1/i

# pure patterns for stateless matching:
#   id:|...|
#   1:|a-mostly-static?string|

# regexp pattern for dns labels:
#   id:~...~
#   1:~.*\.cheez.com~

# pure patterns for dns labels:
#   id:'...'
#   id:'www.icanhazcheez.com'

# patterns for ip addresses ( unimplemented ):
#   id:\127.0.0.1\
#   1:\127.0.0.1\
# ip patterns help for getting direct hits, but of course
# one could just uery the index ...

#4:/GET.*\.exe.*HTTP/1.1/
#5:/GET.*\.swf.*HTTP/1.1/
#6:'www.google.com'
#7:'tracker-95ab7e04.int'
#8:/GET.*\.js.*HTTP/1.1/
#9:/GET.*\.doc.*HTTP/1.1/
)";

  std::mutex _mutex;

  std::array<char, 4096> _rule_editor_buffer;

  int _framebuffer_width;
  int _framebuffer_height;

  ImVec4 _color_clear{ ImVec4(0.45f, 0.55f, 0.60f, 1.00f) };
  ImVec4 _color_summary_1{ ImVec4(0.0f, 0.0f, 0.0f, 1.00f) };
  ImVec4 _color_summary_2{ ImVec4(0.45f, 0.55f, 0.60f, 1.00f) };
  unsigned _query_counter;

  bool _show_sliced_data{ false };
  bool _open_slice_externally{ true };
  bool _show_index_view{ false };
  bool _show_rescan{ false };
  bool _show_query{ false };

  std::string _workspace;
  int _selected_pcap{ -1 };
  int _selected_index_file{ -1 };
  int _selected_query_index_file{ -1 };
  int _selected_result{ -1 };
  std::vector<std::filesystem::path> _pdmls;
  std::vector<std::filesystem::path> _pcaps;
  std::vector<std::filesystem::path> _slices;
  std::vector<index_file_dependencies> _index_file_dependencies;

  std::uint64_t _segment_offset{ 0 };
  std::vector<float> _i4_histogram;
  std::vector<float> _ix_histogram;
  std::vector<float> _iy_histogram;
  std::vector<std::uint32_t> _iy_histogram_pattern_ids;
  std::vector<std::uint32_t> _selected_histogram_ports{
    20, 21, 22, 23, 53, 80, 113, 118, 143, 443, 3389,
  };

  //std::vector<std::filesystem::path> _pdmls;

  std::vector<owl::pdml::packet> _cached_packets;

 private:
  std::string _path;
  // must be last
  std::unique_ptr<active_object> _self;

 public:
  state() : _self{active_object::make()}{
    std::strncpy(_rule_editor_buffer.data(), INITIAL_RULES, std::strlen(INITIAL_RULES));
  }

 public:
  //--cheap-o-async-actor-like-messages---------------------------------------

  void
  send_rescan_workspace(){
    _self->send([this](){ this->rescan_workspace(); });
  }

  void
  send_show_results(std::filesystem::path path){
    _self->send([p = std::move(path), this]() mutable { this->show_results(p); });
  }

  void
  send_index_view(int const selected_index_file){
    _self->send([=, this](){ this->prepare_index_view(selected_index_file); });
  }

  void
  send_index_pcap(std::filesystem::path pcap, std::string patterns){
    _self->send([pcap = std::move(pcap), patterns = std::move(patterns), this]() mutable {
      this->index_pcap(pcap, patterns);
    });
  }

  void
  send_query_index(int const selected_index_file, std::string const& query){
    flog(lvl::m, "state::query: selected-index-file = ", selected_index_file, " query = ( ", query,
         " )");
    _self->send([=, this]{
      std::string q = query;
      this->index_query(selected_index_file, q);
    });
  }

  void
  send_reverse_query(int const selected_index_file, std::string const& query){
    flog(lvl::m, "state::reverse_query: selected-index-file = ", selected_index_file, " query = ( ", query,
         " )");
    _self->send([=, this]{
      std::string q = query;
      this->reverse_query(selected_index_file, q);
    });
  }

  void
  send_parse_slice(std::filesystem::path const& slice){
    flog(lvl::m, "state::send_parse_slice: slice = ", slice);
    if(not _show_sliced_data){
      flog(lvl::m, "state:send_parse_slice: show_sliced_data: disabled");
      this->send_rescan_workspace();
      return;
    }
    std::filesystem::path output{ _workspace };
    std::ostringstream oss;
    oss << slice.stem().string() << ".pdml";
    output /= oss.str();
    flog(lvl::m, "state:send_parse_slice: output = ", output);
    std::thread th([=, this](){
      subprocess_s proc;
      char const* cmd[] = {
        "/bin/tshark", "-2", "-n", "-T", "pdml", "-r", slice.c_str(), nullptr,
      };
      if(auto rc = subprocess_create(cmd, 0, &proc); rc != 0){
        flog(lvl::m, "state::send_parse_slice: unable to spawn tshark process");
        return;
      }
      auto os = std::ofstream{ output };
      auto p_stdout = subprocess_stdout(&proc);
      char buf[512];
      while(not feof(p_stdout)){
        if(auto const rc = fread(buf, 1, 512, p_stdout); rc > 0){
          os.write(buf, static_cast<std::streamsize>(rc));
        }
      }
      int process_rc = -1;
      if(auto rc = subprocess_join(&proc, &process_rc); rc != 0){
        flog(lvl::m, "state::send_parse_slice: waiting for process failed");
      }
      this->send_show_results(output);
      this->send_rescan_workspace();
    });
    th.detach();
  }

  void
  send_open_slice(std::filesystem::path const& slice){
    flog(lvl::m, "state::send_open_slice: slice = ", slice);
    std::filesystem::path output{ "/tmp/0wl" };
    std::thread th([=](){
      subprocess_s proc;
      char const* cmd[] = {
        "/bin/cat", slice.c_str(), nullptr,
      };
      if(auto rc = subprocess_create(cmd, 0, &proc); rc != 0){
        flog(lvl::m, "state::send_parse_slice: unable to spawn wireshark process");
        return;
      }
      auto os = std::ofstream{ output };
      auto p_stdout = subprocess_stdout(&proc);
      char buf[512];
      while(not feof(p_stdout)){
        if(auto const rc = fread(buf, 1, 512, p_stdout); rc > 0){
          os.write(buf, static_cast<std::streamsize>(rc));
        }
      }
      int process_rc = -1;
      if(auto rc = subprocess_join(&proc, &process_rc); rc != 0){
        flog(lvl::m, "state::send_open_slice: waiting for process failed");
      }
    });
    th.detach();
  }

 private:
  std::uint64_t
  index_histogram(std::filesystem::path f, std::vector<float>& out){
    auto const i = riot::make_poly_index_view(f);
    std::vector<std::uint32_t> sizes;
    i->output_histogram(sizes);
    auto const end = sizes.size() < 1000 ? sizes.end() : sizes.begin() + 1000;
    std::transform(sizes.begin(), end, std::back_inserter(out),
                   [](auto s){ return static_cast<float>(s); });
    return i->segment_offset();
  }

  void
  index_histogram_patterns(std::filesystem::path f,
                           std::vector<float>& out,
                           std::vector<std::uint32_t>& pattern_ids){
    auto const i = riot::make_poly_index_view(f);
    std::vector<std::uint32_t> sizes;
    i->output_histogram(sizes);
    std::transform(sizes.begin(), sizes.end(), std::back_inserter(out),
                   [](auto s){ return static_cast<float>(s); });
    i->map([&pattern_ids](auto const& index_view) noexcept {
          using T = std::decay_t<decltype(index_view)>;
          if constexpr(std::is_same_v<T, riot::index_view<std::uint32_t, riot::detail::raw128>> or
                       std::is_same_v<T, riot::index_view<std::uint32_t, riot::detail::raw256>> or
                       std::is_same_v<T, riot::index_view<std::uint32_t, riot::detail::svb128d1>> or
                       std::is_same_v<T, riot::index_view<std::uint32_t, riot::detail::svb256d1>> or
                       std::is_same_v<T, riot::index_view<std::uint32_t, riot::detail::bp128d1>> or
                       std::is_same_v<T, riot::index_view<std::uint32_t, riot::detail::bp256d1>> ){
            std::copy(index_view.keys().begin(), index_view.keys().end(),
                      std::back_inserter(pattern_ids));
          }else{
            flog(lvl::e, "state::index_histogram_patterns: unsupported index_view format");
          }
        });
  }

  void
  index_histogram_ports(std::filesystem::path f, std::vector<float>& out){
    auto const i = riot::make_poly_index_view(f);
    for(auto const port : _selected_histogram_ports){
      auto const size = i->compressed_size(static_cast<std::uint64_t>(port));
      out.push_back(static_cast<float>(size));
    }
  }

  void
  prepare_index_view(int const selected_index_file){
    if(selected_index_file < 0){ return; }
    std::lock_guard<decltype(_mutex)> lck{ _mutex };
    std::vector<float> i4s;
    std::vector<float> ixs;
    std::vector<float> iys;
    std::vector<std::uint32_t> pattern_ids;
    try {
      std::size_t const pcap = static_cast<std::size_t>(selected_index_file) >> 8;
      std::size_t const index = static_cast<std::size_t>(selected_index_file) & 0xff;
      flog(lvl::m, "state::prepare_index_view: pcap = ", pcap, " index = ", index);
      if(pcap < _index_file_dependencies.size()){
        auto const& f4 = _index_file_dependencies.at(pcap)._i4.at(index);
        auto const& fx = _index_file_dependencies.at(pcap)._ix.at(index);
        if(index < _index_file_dependencies.at(pcap)._iy.size()){
          auto const& fy = _index_file_dependencies.at(pcap)._iy.at(index);
          index_histogram_patterns(fy, iys, pattern_ids);
        }
        _segment_offset = index_histogram(f4, i4s);
        index_histogram_ports(fx, ixs);
      }
    } catch(...) {
      flog(lvl::e, "state::prepare_index_view: failed");
    }
    _i4_histogram = std::move(i4s);
    _ix_histogram = std::move(ixs);
    _iy_histogram = std::move(iys);
    _iy_histogram_pattern_ids = std::move(pattern_ids);
  }

  void
  index_query(int const selected_index_file, std::string const& query_string){
    if(selected_index_file < 0){ return; }
    std::filesystem::path output_slice;
    try {
      using namespace nygma;
      std::size_t const pcap_idx = static_cast<std::size_t>(selected_index_file) >> 8;
      std::size_t const index = static_cast<std::size_t>(selected_index_file) & 0xff;
      auto const& storage = _pcaps.at(pcap_idx);
      auto const query = riot::parse(query_string);
      auto data = std::make_unique<block_view_16k>(storage, block_flags::rd);
      nygma::pcap::with(std::move(data), [&](auto& pcap){
        if(not pcap.valid()){
          flog(lvl::e, "unable to open pcap storage path = ", storage);
          return;
        }
        std::ostringstream oss;
        oss << "-" << std::setfill('0') << std::setw(4) << index << ".slice";
        std::filesystem::path output{ storage };
        output += oss.str();
        auto const& f4 = _index_file_dependencies.at(pcap_idx)._i4.at(index);
        auto const& fx = _index_file_dependencies.at(pcap_idx)._ix.at(index);
        auto builder = riot::environment::builder();
        builder.add("i4", f4).add("ix", fx);
        if(index < _index_file_dependencies.at(pcap_idx)._iy.size()){
          flog(lvl::m, "adding pattern index to query environment");
          auto const& fy = _index_file_dependencies.at(pcap_idx)._iy.at(index);
          builder.add("iy", fy);
        }
        auto const env = builder.build();
        auto const rs = query->eval(env);
        flog(lvl::m, "query resultset #offsets = ", rs.size());
        flog(lvl::m, "stitching pcap = ", output);
        auto os = nygma::pcap_ostream{ output };
        pcap::reassemble_begin(pcap, os);
        pcap::reassemble_stream(pcap, rs.segment_offset(), rs.cbegin(), rs.cend(), os);
        output_slice = output;
      });
    } catch(...) {
      flog(lvl::e, "state::index_query: failed");
    }
    flog(lvl::m, "state::index_query: finished");
    if(not output_slice.empty()){ send_parse_slice(output_slice); }
  }

  void
  reverse_query(int const selected_index_file, std::string const& query_string){
    if(selected_index_file < 0){ return; }
    std::filesystem::path output_slice;
    try {
      using namespace nygma;
      using sparse_resultset_type = riot::sparse_resultset<riot::resultset_forward_type>;
      std::size_t const pcap_idx = static_cast<std::size_t>(selected_index_file) >> 8;
      std::size_t const index = static_cast<std::size_t>(selected_index_file) & 0xff;
      auto const& storage = _pcaps.at(pcap_idx);
      auto const query = riot::parse(query_string);
      auto data = std::make_unique<block_view_16k>(storage, block_flags::rd);
      nygma::pcap::with(std::move(data), [&](auto& pcap){
        if(not pcap.valid()){
          flog(lvl::e, "unable to open pcap storage path = ", storage);
          return;
        }
        std::ostringstream oss;
        oss << "-" << std::setfill('0') << std::setw(4) << index << ".slice";
        std::filesystem::path output{ storage };
        output += oss.str();
        auto const& f4 = _index_file_dependencies.at(pcap_idx)._i4.at(index);
        auto const& fx = _index_file_dependencies.at(pcap_idx)._ix.at(index);
        auto builder = riot::environment::builder();
        builder.add("i4", f4).add("ix", fx);
        if(index < _index_file_dependencies.at(pcap_idx)._iy.size()){
          flog(lvl::m, "adding pattern index to query environment");
          auto const& fy = _index_file_dependencies.at(pcap_idx)._iy.at(index);
          builder.add("iy", fy);
        }
        auto const env = builder.build();
        auto const rs = query->eval(env);
        flog(lvl::m, "forward query #hits = ", rs.size());
        flog(lvl::m, "segment offset = ", rs.segment_offset());
        auto const rev_rs = sparse_resultset_type::combine<&riot::resultset_forward_type::combine_or<>,
                                                           &riot::resultset_forward_type::combine_and<>>(env._indices.find("i4")->second->sparse_scan(rs), env._indices.find("ix")->second->sparse_scan(rs));
        flog(lvl::v, "reverse scan #hits = ", rev_rs.size());
        flog(lvl::m, "stitching pcap = ", output);
        auto os = nygma::pcap_ostream{ output };
        pcap::reassemble_begin(pcap, os);
        pcap::reassemble_stream(pcap, rev_rs.segment_offset(), rev_rs.cbegin(), rev_rs.cend(), os);
        output_slice = output;
      });
    } catch(...) {
      flog(lvl::e, "state::reverse_query: failed");
    }
    flog(lvl::m, "state::reverse_query: finished");
    if(not output_slice.empty()){ send_parse_slice(output_slice); }
  }

  void
  show_results(std::filesystem::path& path){
    if(not _show_sliced_data){ return; }
    std::vector<owl::pdml::packet> ps;
    try {
      flog(lvl::m, "parsing: ", path);
      ps = owl::pdml::parse(path);
      flog(lvl::m, "  number of packets: ", ps.size());
      flog(lvl::m, "  pre-computing packet summary ... ");
      std::size_t i = 0;
      for(auto& p : ps){
        p.summary(i);
        ++i;
      }
    } catch(...) {
      flog(lvl::m, "pdml parsing failed");
    }
    std::lock_guard<decltype(_mutex)> lck{ _mutex };
    _cached_packets = std::move(ps);
  }

  void
  index_pcap(std::filesystem::path const& path, std::string const& patterns){
    constexpr char const* PATTERN_FILE = "/tmp/0wl-patterns.ioc";
    flog(lvl::m, "state::index_pacp: path = ", path);
    {
      std::fstream os{ PATTERN_FILE, os.binary | os.out };
      os << patterns;
      os.flush();
    }
    std::thread th([=, this](){
      subprocess_s proc;
      char const* cmd[] = {
        "./build-default/modules/nygma/tetch/tetch/t3",
        "index-pcap",
        "--mode",
        "regexp",
        "--patterns",
        PATTERN_FILE,
        path.c_str(),
        nullptr,
      };
      if(auto rc = subprocess_create(cmd, 0, &proc); rc != 0){
        flog(lvl::m, "state::send_parse_slice: unable to spawn tshark process");
        return;
      }
      int process_rc = -1;
      if(auto rc = subprocess_join(&proc, &process_rc); rc != 0){
        flog(lvl::m, "state::send_parse_slice: waiting for process failed");
      }
      this->send_rescan_workspace();
      std::lock_guard<decltype(_mutex)> lck{ _mutex };
      this->send_index_view(this->_selected_index_file);
    });
    th.detach();
  }

  void
  rescan_workspace(){
    std::lock_guard<decltype(_mutex)> lck{ _mutex };
    _pdmls.clear();
    _pcaps.clear();
    _slices.clear();
    _index_file_dependencies.clear();
    try {
      flog(lvl::m, "state::rescan_workspace: path = ", _workspace);
      std::filesystem::create_directories(_workspace);
      for(auto const& de : std::filesystem::directory_iterator(_workspace)){
        // flog( lvl::m, "rescan_workspace: directory-entry: ", de.path() );
        if(de.path().has_extension()){
          if(de.path().extension() == ".pdml"){
            _pdmls.push_back(de.path());
          }else if(de.path().extension() == ".slice"){
            _slices.push_back(de.path());
          }else if(de.path().extension() == ".en10mb"){
            _pcaps.push_back(de.path());
          }
        }
      }
      std::sort(_pdmls.begin(), _pdmls.end());
      std::sort(_pcaps.begin(), _pcaps.end());
      std::sort(_slices.begin(), _slices.end());
      for(auto const& p : _pcaps){
        _index_file_dependencies.emplace_back();
        auto const f = p.filename().stem();
        auto const root = p.parent_path();
        auto const expected_base = root / f;
        _index_file_dependencies.back().gather(root, expected_base);
      }
    } catch(...) {
      flog(lvl::e, "unable to (re-)scan workspace directory path = ", _workspace);
    }
  }
};

static void
histogram(state& state,
          char const* name,
          std::vector<float>& histogram,
          float const plot_width){
  if(histogram.empty()){ return; }
  auto const max = std::max_element(histogram.cbegin(), histogram.cend());
  ImGui::PlotHistogram(name, histogram.data(), static_cast<int>(histogram.size()), 0, nullptr, 0.0f,
                       *max, ImVec2(plot_width, 80.f));
  if(strcmp(name, "ix") == 0){
    ImGui::BeginChild("ix-histogram-lables-x", ImVec2(plot_width, 30), true);
    auto columns = state._selected_histogram_ports.size();
    auto column_width = (plot_width - ImGui::GetStyle().FramePadding.x) /
                        static_cast<float>(columns);
    ImGui::Columns(static_cast<int>(columns));
    for(std::size_t i = 0; i < columns; i++){
      if(columns > 1){ ImGui::SetColumnWidth(static_cast<int>(i), column_width); }
      ImGui::Text("%u", state._selected_histogram_ports[i]);
      ImGui::NextColumn();
    }
    ImGui::EndChild();
  }else if(strcmp(name, "iy") == 0){
    ImGui::BeginChild("iy-histogram-lables-x", ImVec2(plot_width, 30), true);
    auto columns = state._iy_histogram_pattern_ids.size();
    auto column_width = (plot_width - ImGui::GetStyle().FramePadding.x) /
                        static_cast<float>(columns);
    ImGui::Columns(static_cast<int>(columns));
    for(std::size_t i = 0; i < columns; i++){
      if(columns > 1){ ImGui::SetColumnWidth(static_cast<int>(i), column_width); }
      ImGui::Text("%u", state._iy_histogram_pattern_ids[i]);
      ImGui::NextColumn();
    }
    ImGui::EndChild();
  }
}

static void
index_histograms(state& state){
  if(not state._show_index_view){ return; }
  if(not ImGui::Begin("index histograms ( compressed size per key )", &state._show_index_view)){
    ImGui::End();
    return;
  }
  ImGui::Text("segment-offset = %lu", state._segment_offset);
  auto const plot_width = ImGui::GetWindowSize().x * 0.9f;
  draw::histogram(state, "i4", state._i4_histogram, plot_width);
  draw::histogram(state, "ix", state._ix_histogram, plot_width);
  draw::histogram(state, "iy", state._iy_histogram, plot_width);
  ImGui::End();
}

static void
reindex(state& state){
  if(not state._show_rescan){ return; }
  if((state._selected_pcap < 0)|| (state._selected_pcap >= static_cast<int>(state._pcaps.size()))){
    return;
  }
  // always center this window when appearing
  ImVec2 center(ImGui::GetIO().DisplaySize.x * 0.5f, ImGui::GetIO().DisplaySize.y * 0.5f);
  ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
  if(not ImGui::Begin("re-index for patterns only", &state._show_rescan)){
    ImGui::End();
    return;
  }

  auto const& p = state._pcaps[state._selected_pcap];
  ImGui::Text("(re-)scan pcap = <%s>", p.filename().c_str());
  ImGuiInputTextFlags flags = ImGuiInputTextFlags_AllowTabInput;

  ImGui::InputTextMultiline("##rulez", state._rule_editor_buffer.data(),
                            state._rule_editor_buffer.size(),
                            ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 16), flags);

  if(ImGui::Button(">> (re-)index", ImVec2(120, 0))){
    //state._show_rescan = false;
    state.send_index_pcap(p, std::string{ state._rule_editor_buffer.data() });
  }
  ImGui::SameLine();
  if(ImGui::Button("cancel", ImVec2(120, 0))){ state._show_rescan = false; }

  ImGui::End();
}

static void
query(state& state){
  // always center this window when appearing
  if(state._selected_query_index_file < 0){ return; }
  if(not state._show_query){ return; }

  //ImVec2 center( ImGui::GetIO().DisplaySize.x * 0.5f, ImGui::GetIO().DisplaySize.y * 0.5f );
  //ImGui::SetNextWindowPos( center, ImGuiCond_Appearing, ImVec2( 0.5f, 0.5f ) );
  if(not ImGui::Begin("query-index###query", &state._show_query)){
    ImGui::End();
    return;
  }
  std::size_t const pcap = static_cast<std::size_t>(state._selected_query_index_file) >> 8;
  std::size_t const index = static_cast<std::size_t>(state._selected_query_index_file) & 0xff;

  ImGui::Text("selected indices for pcap = <%s>", state._pcaps.at(pcap).filename().c_str());
  auto const& deps = state._index_file_dependencies.at(pcap);
  if(index < deps._i4.size()){ ImGui::Text("  - <%s>", deps._i4[index].filename().c_str()); }
  if(index < deps._ix.size()){ ImGui::Text("  - <%s>", deps._ix[index].filename().c_str()); }
  if(index < deps._iy.size()){ ImGui::Text("  - <%s>", deps._iy[index].filename().c_str()); }

  ImGui::Separator();

  ImGuiInputTextFlags input_text_flags_prepared = ImGuiInputTextFlags_EnterReturnsTrue |
                                                  ImGuiInputTextFlags_ReadOnly;

  ImGui::Text("Q1: query all hits for pattern with id = 1 ( fr.jpg )");
  static char pq1[128] = "iy( 1 )";
  if(ImGui::InputText("##pq1", pq1, 128, input_text_flags_prepared, nullptr, nullptr)){
    state.send_query_index(state._selected_query_index_file, pq1);
  }
  ImGui::SameLine();
  if(ImGui::Button(">>##pq1")){ state.send_query_index(state._selected_query_index_file, pq1); }

  ImGui::Separator();

  ImGui::Text("Q3: query all dns records for `www.mybusinessdoc.com` (ID=2) and `1.web-counter.info` (ID=3)");
  static char pq2[128] = "iy( 2 ) + iy( 3 )";
  if(ImGui::InputText("##pq2", pq2, 128, input_text_flags_prepared, nullptr, nullptr)){
    state.send_query_index(state._selected_query_index_file, pq2);
  }
  ImGui::SameLine();
  if(ImGui::Button(">>##pq2")){ state.send_query_index(state._selected_query_index_file, pq2); }

  ImGui::Separator();

  ImGuiInputTextFlags input_text_flags = ImGuiInputTextFlags_EnterReturnsTrue;

  //--query-example-1
  //
  static char q1[128] = "i4( 127.0.0.1 )";
  if(ImGui::InputText("##q1", q1, 128, input_text_flags, nullptr, nullptr)){
    state.send_query_index(state._selected_query_index_file, q1);
  }
  ImGui::SameLine();
  if(ImGui::Button(">>##q1")){ state.send_query_index(state._selected_query_index_file, q1); }

  //--query-example-2
  //
  static char q2[128] = "ix( 53 ) & i4( 175.45.176.3 )";
  if(ImGui::InputText("##q2", q2, 128, input_text_flags, nullptr, nullptr)){
    state.send_query_index(state._selected_query_index_file, q2);
  }
  ImGui::SameLine();
  if(ImGui::Button(">>##q2")){ state.send_query_index(state._selected_query_index_file, q2); }

  //--query-example-3
  //
  static char q3[128] = "iy( 1 )";
  if(ImGui::InputText("##q3", q3, 128, input_text_flags, nullptr, nullptr)){
    state.send_query_index(state._selected_query_index_file, q3);
  }
  ImGui::SameLine();
  if(ImGui::Button(">>##q3")){ state.send_query_index(state._selected_query_index_file, q3); }

  ImGui::SameLine();
  if(ImGui::Button("<=>##q3_r")){ state.send_reverse_query(state._selected_query_index_file, q3); }

  ImGui::Separator();

  if(ImGui::Button("cancel", ImVec2(120, 0))){ state._show_query = false; }
  ImGui::End();
}

static void
main(state& state){
  ImGui::SetNextWindowPos(ImVec2(0, 0));
  ImGui::SetNextWindowSize(ImVec2(450, static_cast<float>(state._framebuffer_height)),
                           ImGuiCond_Always);
  ImGui::Begin("the-0wls -- three-penny-imgui --", nullptr, ImGuiWindowFlags_NoMove);

  static int style_idx = -1;
  if(style_idx == -1){
    ImGui::StyleColorsClassic();
    style_idx = 0;
  }
  if(ImGui::Combo("style##selector", &style_idx, "classic\0dark\0light\0")){
    switch(style_idx){
      case 0: ImGui::StyleColorsClassic(); break;
      case 1: ImGui::StyleColorsDark(); break;
      case 2: ImGui::StyleColorsLight(); break;
    }
  }

  ImGui::ColorEdit3("background", reinterpret_cast<float*>(&state._color_clear));

  ImGui::Text("running @ %.1f FPS", ImGui::GetIO().Framerate);

  ImGui::Text("workspace directory: ");
  ImGui::Text("  - <%s>", state._workspace.c_str());
  ImGui::SameLine();
  if(ImGui::Button("rescan-workspace")){ state.send_rescan_workspace(); }
  if(ImGui::Checkbox("show sliced data in pdml view (via tshark)", &state._show_sliced_data)){
    //state._show_sliced_data = not state._show_sliced_data;
  }
  ImGui::BeginChild("workspace", ImVec2(0, 0), false);
  {                                      //--draw-workspace-pcaps
    //
    ImGui::Text("pcaps:");
    ImGui::BeginChild("workspace-pcaps", ImVec2(0, 600), true);

    int id = 0;
    std::array<char, 128> label;
    std::error_code ec;
    auto show_rescan = false;
    auto const old_selected_index_file = state._selected_index_file;
    for(auto const& p : state._pcaps){
      std::snprintf(label.data(), label.size(), "~###%d", id);
      if(ImGui::SmallButton(label.data())){
        state._selected_pcap = id;
        show_rescan = true;
      }
      auto const size = static_cast<double>(std::filesystem::file_size(p, ec)) / (1 << 30);
      std::snprintf(label.data(), label.size(), "%s (%.2fGiB)", p.filename().c_str(), size);
      ImGui::SameLine();
      if(ImGui::TreeNodeEx(label.data(), ImGuiTreeNodeFlags_Framed)){
        auto const& index_deps = state._index_file_dependencies.at(static_cast<unsigned>(id));
        if(ImGui::TreeNode("index-by: patterns (.iy)")){
          auto j = id << 8;
          for(auto& index_file : index_deps._iy){
            ImGui::PushID(j);
            if(ImGui::SmallButton("?")){
              state._show_query = true;
              state._selected_query_index_file = j;
              //state.send_query_index( j, "iy( 1 )" );
            }
            ImGui::PopID();
            ImGui::SameLine();
            auto const isize = static_cast<double>(std::filesystem::file_size(index_file, ec)) /
                               (1 << 10);
            std::snprintf(label.data(), label.size(), "%s (%.2fKiB)", index_file.filename().c_str(),
                          isize);
            if(ImGui::Selectable(label.data(), (state._selected_index_file == j))){
              state._selected_index_file = j;
            }
            j++;
          }
          ImGui::TreePop();
        }
        if(ImGui::TreeNode("index-by: ipv4 addresses (.i4)")){
          auto j = id << 8;
          for(auto& index_file : index_deps._i4){
            ImGui::PushID(j);
            if(ImGui::SmallButton("?")){
              state._show_query = true;
              state._selected_query_index_file = j;
              //state.send_query_index( j, "ix( 80 ) & i4( 127.0.0.1 )" );
            }
            ImGui::PopID();
            ImGui::SameLine();
            auto const isize = static_cast<double>(std::filesystem::file_size(index_file, ec)) /
                               (1 << 20);
            std::snprintf(label.data(), label.size(), "%s (%.2fMiB)", index_file.filename().c_str(),
                          isize);
            if(ImGui::Selectable(label.data(), (state._selected_index_file == j))){
              state._selected_index_file = j;
            }
            j++;
          }
          ImGui::TreePop();
        }
        if(ImGui::TreeNode("index-by: tcp and udp ports (.ix)")){
          auto j = id << 8;
          for(auto& index_file : index_deps._ix){
            ImGui::PushID(j);
            if(ImGui::SmallButton("?")){
              state._show_query = true;
              state._selected_query_index_file = j;
              //state.send_query_index( j, "ix( 80 ) & i4( 127.0.0.1 )" );
            }
            ImGui::PopID();
            ImGui::SameLine();
            auto const isize = static_cast<double>(std::filesystem::file_size(index_file, ec)) /
                               (1 << 20);
            std::snprintf(label.data(), label.size(), "%s (%.2fMiB)", index_file.filename().c_str(),
                          isize);
            if(ImGui::Selectable(label.data(), (state._selected_index_file == j))){
              state._selected_index_file = j;
            }
            j++;
          }
          ImGui::TreePop();
        }
        ImGui::TreePop();
      }
      id++;
    }

    auto const changed = state._selected_index_file != old_selected_index_file;
    state._show_index_view |= changed;
    if(changed){ state.send_index_view(state._selected_index_file); }
    state._show_rescan |= show_rescan;

    ImGui::EndChild();

    //--draw-workspace-slices
    //
    ImGui::Text("sliced pcaps:");
    ImGui::BeginChild("workspace-slices", ImVec2(0, 0), true);

    //ImGui::SetColumnWidth( 0, width );

    id = 0;
    for(auto const& p : state._slices){
      auto const isize = static_cast<double>(std::filesystem::file_size(p, ec)) /
                         (1 << 20);
      std::snprintf(label.data(), label.size(), "%s (%.2fMiB)", p.filename().c_str(), isize);
      //std::snprintf(label.data(), label.size(), "- %s", p.filename().c_str());
      if(ImGui::Selectable(label.data(), false, ImGuiSelectableFlags_AllowDoubleClick)){
        if(ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)){
          //state._selected_result = id;
          //state.send_show_results( p );
          state.send_open_slice(p);
        }
        id++;
      }
    }

    ImGui::EndChild();

    //--draw-workspace-results
    //
    ImGui::Text("results:");
    ImGui::BeginChild("workspace-pdmls", ImVec2(0, 200), true);

    //ImGui::SetColumnWidth( 0, width );

    id = 0;
    for(auto const& p : state._pdmls){
      std::snprintf(label.data(), label.size(), "- %s", p.filename().c_str());
      if(ImGui::Selectable(label.data(), (state._selected_result == id),
                           ImGuiSelectableFlags_AllowDoubleClick)){
        if(ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)){
          state._selected_result = id;
          state.send_show_results(p);
        }
      }
      id++;
    }

    ImGui::EndChild();
  }
  ImGui::EndChild();
  ImGui::End();
}                                        // namespace draw

static void
packets(state& state){
  auto name = std::ostringstream{};
  name << "sliced packets ( #total = " << state._cached_packets.size() << " )###packets";
  ImGui::Begin(name.str().c_str());

  ImGui::ColorEdit3("protocol1##PColor1", reinterpret_cast<float*>(&state._color_summary_1));
  ImGui::ColorEdit3("protocol2##PColor2", reinterpret_cast<float*>(&state._color_summary_2));

  struct show {
    enum class state { START, IN_PROTO };
    state _state{ state::START };
    bool _on{ false };
    std::size_t _node_index{ 0 };
    void
    operator()(owl::pdml::field const& f) const noexcept {
      if(_on){ ImGui::Text("- %*s%s", f._level, "", f._text.c_str()); }
    }
    void
    operator()(owl::pdml::proto const& p) noexcept {
      if((_state != state::START)&& _on){
        ImGui::TreePop();
        _on = false;
      }
      _state = state::IN_PROTO;
      char buf[512]{ '\0' };
      std::snprintf(buf, 511, "* %*s%s###%zu", p._level, "", p._text.c_str(), _node_index);
      if(ImGui::TreeNode(buf)){ _on = true; }
    }

    // reset the render state, needs to called before visiting the nodes of a packet
    //
    void
    reset() noexcept {
      _state = state::START;
      _on = false;
    }
  };

  //--draw-packet-view--------------------------------------------------------

  std::size_t i{ 0 };
  show visitor;
  for(auto const& packet : state._cached_packets){
    visitor.reset();
    auto const& summary = packet.summary();
    auto const open_packet = ImGui::TreeNodeEx(summary[0].c_str(), ImGuiTreeNodeFlags_Framed);
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, state._color_summary_1);
    ImGui::Text(" /// %s /// ", summary[1].c_str());
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, state._color_summary_2);
    ImGui::TextUnformatted(summary[2].c_str());
    ImGui::PopStyleColor(2);
    if(open_packet){
      for(auto const& node : packet._nodes){
        node->accept(visitor);
        visitor._node_index++;
      }
      if(visitor._on){ ImGui::TreePop(); }
      ImGui::TreePop();
    }else{
      visitor._node_index += packet._nodes.size();
    }
    i++;
  }

  ImGui::End();
}
}                                        // namespace draw

void
owl_command_ui(ui_config const& config){
  auto state = draw::state{};
  state._workspace = config._workspace_directory;
  state.send_rescan_workspace();
  auto mouse_clicked = ImColor(0.5f, 0.0f, 0.0f, 0.5f);
  auto mouse_cursor = ImColor(0.0f, 0.5f, 0.0f, 0.5f);

  auto engine = owl::vulkan::build().end();
  int mouse_button_delay = -1;
  engine->run([&](){
    std::lock_guard<decltype(state._mutex)> lck(state._mutex);
    auto[w, h] = engine->frame();
    state._framebuffer_height = h;
    state._framebuffer_width = w;
    auto& style = ImGui::GetStyle();
    style.DisplayWindowPadding = ImVec2(0, 0);
    style.DisplaySafeAreaPadding = ImVec2(0, 0);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, .0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 2.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_GrabRounding, 2.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 2.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 2.0f);

    auto mouse = mouse_cursor;
    if(mouse_button_delay > 0){
      mouse_button_delay--;
      mouse = mouse_clicked;
    }
    if(ImGui::IsMouseClicked(ImGuiMouseButton_Left)){
      mouse_button_delay = 23;
      mouse = mouse_clicked;
    }

    ImGui::GetForegroundDrawList()->AddCircleFilled(ImGui::GetMousePos(), 30.0, mouse, 64);

    draw::main(state);
    draw::index_histograms(state);
    draw::packets(state);
    draw::reindex(state);
    draw::query(state);

    ImGui::Render();

    engine->clear(state._color_clear);
  });
}
}                                        // namespace owl
