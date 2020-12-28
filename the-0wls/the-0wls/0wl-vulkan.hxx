// License: RoundRobin-1.0.0

#pragma once

#include <imgui/imgui.h>

#include <filesystem>
#include <memory>

namespace owl {
struct context;
struct vulkan;
struct builder {
  vulkan* _vulkan;
  builder();
  ~builder();

  builder(builder const&) = delete;
  builder& operator=(builder const&) = delete;

  builder(builder&&) = default;
  builder& operator=(builder&&) = default;

  builder& add_font(std::filesystem::path const& font);
  std::shared_ptr<vulkan> end();
};

struct vulkan {
 private:
  context* _context;

 private:
  vulkan();

  bool on_window_size_changed() noexcept;

 public:
  ~vulkan();

  void init();

 public:
  friend builder;

  vulkan(vulkan const&) = delete;
  vulkan& operator=(vulkan const&) = delete;

  auto& window() noexcept;
  auto const& window() const noexcept;

  // start the dear-imgui frame
  //
  void begin() noexcept;

  bool render() noexcept;
  void present() noexcept;

  bool should_stop() const noexcept;
  void poll() noexcept;

  std::pair<int, int> frame() const noexcept;

  void clear(ImVec4 const clear_color) noexcept;

  template <typename F>
  void
  run(F const f){
    while(not should_stop()){
      poll();
      begin();
      f();
      if(render()){ present(); }
    }
  }

  static builder build();
};
}                                        // namespace owl
