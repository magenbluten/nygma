// License: RoundRobin-1.0.0

#include <libunclassified/femtolog.hxx>

#include <the-0wls/0wl-vulkan.hxx>

#define GLFW_INCLUDE_NONE
#define GLFW_INCLUDE_VULKAN
#include <GLFW/glfw3.h>
#include <vulkan/vulkan.h>

#include <imgui/imgui.h>
#include <imgui/imgui_impl_glfw.h>
#include <imgui/imgui_impl_vulkan.h>

#include <atomic>
#include <cstddef>
#include <cstring>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <type_traits>

namespace owl {
static constexpr auto NULL_HANDLE = nullptr;
static_assert(VK_NULL_HANDLE == 0);

struct resize_callback_info {
  std::atomic<bool> _updated{ false };
  std::atomic<int> _width{ 0 };
  std::atomic<int> _height{ 0 };

 private:
  resize_callback_info(){}

 public:
  static auto&
  instance(){
    static resize_callback_info _instance;
    return _instance;
  }

  void
  update(int const w, int const h) noexcept {
    flog(lvl::m, "resize_callback_info: width = ", w, " height = ", h);
    if(w != _width.load() and h != _height.load()){
      _updated = true;
      _width = w;
      _height = h;
    }
  }

  bool
  updated() const noexcept {
    return _updated.load();
  }
  void
  reset() noexcept {
    _updated = false;
  }
  auto
  get() noexcept {
    return std::pair{ _width.load(), _height.load() };
  }
};

namespace {
void
glfw_error_callback(int error, const char* description){
  flog(lvl::m, "glfw error: id = ", error, " what = ", description);
}

void
glfw_resize_callback(GLFWwindow*, int const w, int const h){
  resize_callback_info::instance().update(w, h);
}

std::runtime_error
vulkan_error(VkResult const err){
  std::ostringstream os;
  os << "vulkan: failed with error = " << err;
  return std::runtime_error(os.str());
}

static std::string_view
vk_result(VkResult const r) noexcept {
  switch(r){
    case VK_SUCCESS: return "VkResult::VK_SUCCESS";
    case VK_ERROR_DEVICE_LOST: return "VkResult::VK_ERROR_DEVICE_LOST";
    case VK_RESULT_MAX_ENUM: return "VkResult::VK_RESULT_MAX_ENUM";
    case VK_ERROR_EXTENSION_NOT_PRESENT: return "VkResult::VK_ERROR_EXTENSION_NOT_PRESENT";
    case VK_ERROR_FEATURE_NOT_PRESENT: return "VkResult::VK_ERROR_FEATURE_NOT_PRESENT";
    case VK_ERROR_FORMAT_NOT_SUPPORTED: return "VkResult::VK_ERROR_FORMAT_NOT_SUPPORTED";
    case VK_ERROR_FRAGMENTATION: return "VkResult::VK_ERROR_FRAGMENTATION";
    case VK_ERROR_FRAGMENTED_POOL: return "VkResult::VK_ERROR_FRAGMENTED_POOL";
    case VK_ERROR_FULL_SCREEN_EXCLUSIVE_MODE_LOST_EXT: return "VkResult::VK_ERROR_FULL_SCREEN_EXCLUSIVE_MODE_LOST_EXT";
    case VK_ERROR_INCOMPATIBLE_DISPLAY_KHR: return "VkResult::VK_ERROR_INCOMPATIBLE_DISPLAY_KHR";
    case VK_ERROR_INCOMPATIBLE_DRIVER: return "VkResult::VK_ERROR_INCOMPATIBLE_DRIVER";
    //case VK_ERROR_INCOMPATIBLE_VERSION_KHR: return "VkResult::VK_ERROR_INCOMPATIBLE_VERSION_KHR";
    case VK_ERROR_INITIALIZATION_FAILED: return "VkResult::VK_ERROR_INITIALIZATION_FAILED";
    case VK_ERROR_INVALID_DRM_FORMAT_MODIFIER_PLANE_LAYOUT_EXT: return "VkResult::VK_ERROR_INVALID_DRM_FORMAT_MODIFIER_PLANE_LAYOUT_EXT";
    case VK_ERROR_INVALID_EXTERNAL_HANDLE: return "VkResult::VK_ERROR_INVALID_EXTERNAL_HANDLE";
    case VK_ERROR_INVALID_OPAQUE_CAPTURE_ADDRESS: return "VkResult::VK_ERROR_INVALID_OPAQUE_CAPTURE_ADDRESS";
    case VK_ERROR_INVALID_SHADER_NV: return "VkResult::VK_ERROR_INVALID_SHADER_NV";
    case VK_ERROR_LAYER_NOT_PRESENT: return "VkResult::VK_ERROR_LAYER_NOT_PRESENT";
    case VK_ERROR_MEMORY_MAP_FAILED: return "VkResult::VK_ERROR_MEMORY_MAP_FAILED";
    case VK_ERROR_NATIVE_WINDOW_IN_USE_KHR: return "VkResult::VK_ERROR_NATIVE_WINDOW_IN_USE_KHR";
    case VK_ERROR_NOT_PERMITTED_EXT: return "VkResult::VK_ERROR_NOT_PERMITTED_EXT";
    case VK_ERROR_OUT_OF_DATE_KHR: return "VkResult::VK_ERROR_OUT_OF_DATE_KHR";
    case VK_ERROR_OUT_OF_DEVICE_MEMORY: return "VkResult::VK_ERROR_OUT_OF_DEVICE_MEMORY";
    case VK_ERROR_OUT_OF_HOST_MEMORY: return "VK_ERROR_OUT_OF_HOST_MEMORY";
    case VK_ERROR_OUT_OF_POOL_MEMORY: return "VkResult::VK_ERROR_OUT_OF_POOL_MEMORY";
    case VK_ERROR_SURFACE_LOST_KHR: return "VkResult::VK_ERROR_SURFACE_LOST_KHR";
    case VK_ERROR_TOO_MANY_OBJECTS: return "VkResult::VK_ERROR_TOO_MANY_OBJECTS";
    case VK_ERROR_UNKNOWN: return "VkResult::VK_ERROR_UNKNOWN";
    case VK_ERROR_VALIDATION_FAILED_EXT: return "VkResult::VK_ERROR_VALIDATION_FAILED_EXT";
    case VK_EVENT_RESET: return "VkResult::VK_EVENT_RESET";
    case VK_EVENT_SET: return "VkResult::VK_EVENT_SET";
    case VK_INCOMPLETE: return "VkResult::VK_INCOMPLETE";
    case VK_NOT_READY: return "VkResult::VK_NOT_READY";
    case VK_OPERATION_DEFERRED_KHR: return "VkResult::VK_OPERATION_DEFERRED_KHR";
    case VK_OPERATION_NOT_DEFERRED_KHR: return "VkResult::VK_OPERATION_NOT_DEFERRED_KHR";
    case VK_PIPELINE_COMPILE_REQUIRED_EXT: return "VkResult::VK_PIPELINE_COMPILE_REQUIRED_EXT";
    case VK_SUBOPTIMAL_KHR: return "VkResult::VK_SUBOPTIMAL_KHR";
    case VK_THREAD_DONE_KHR: return "VkResult::VK_THREAD_DONE_KHR";
    case VK_THREAD_IDLE_KHR: return "VkResult::VK_THREAD_IDLE_KHR";
    case VK_TIMEOUT: return "VkResult::VK_TIMEOUT";
      //default: return "VkResult::UNKNOWN";
  }
}

std::runtime_error
vulkan_error(std::string_view const what, VkResult const err){
  std::ostringstream os;
  os << "vulkan::" << what << ": failed with error = " << vk_result(err);
  return std::runtime_error(os.str());
}

template <auto VkOp, typename... Args>
static void
vk(std::string_view const prefix, Args&&... args){
  if(auto const rc = VkOp(std::forward<Args>(args)...); rc != 0){
    throw vulkan_error(prefix, rc);
  }
}

template <auto VkOp, typename... Args>
static auto
vk0(std::string_view const prefix, Args&&... args){
  auto const rc = VkOp(std::forward<Args>(args)...);
  if(rc != 0){ flog(lvl::e, "vulkan::", prefix, ": ", vk_result(rc)); }
  return rc;
}
}                                        // namespace

struct context {
  VkAllocationCallbacks* _allocator = nullptr;
  VkInstance _instance = NULL_HANDLE;

  VkPhysicalDevice _physical_device = NULL_HANDLE;
  VkDevice _device = NULL_HANDLE;
  uint32_t _queue_family = static_cast<std::uint32_t>(-1);
  VkQueue _queue = NULL_HANDLE;
  VkPipelineCache g_PipelineCache = NULL_HANDLE;
  VkDescriptorPool _descriptor_pool = NULL_HANDLE;
  std::uint32_t _min_image_count = 2;

  VkSurfaceKHR _surface;
  GLFWwindow* _window = nullptr;

  int _framebuffer_width = 0;
  int _framebuffer_height = 0;

  ImGui_ImplVulkanH_Window _imgui_window;

  ~context(){
    flog(lvl::m, "vulkan::context: destructor");
    ImGui_ImplVulkan_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    if(_instance != nullptr and _device != nullptr){
      flog(lvl::m, "vulkan::ImGui_ImplVulkanH_DestroyWindow");
      ImGui_ImplVulkanH_DestroyWindow(_instance, _device, &_imgui_window, _allocator);
    }
    if(_descriptor_pool != nullptr){
      flog(lvl::m, "vulkan::vkDestroyDescriptorPool");
      vkDestroyDescriptorPool(_device, _descriptor_pool, _allocator);
    }
    if(_device != nullptr){
      flog(lvl::m, "vulkan::vkDestroyDevice");
      vkDestroyDevice(_device, _allocator);
    }
    if(_instance != nullptr){
      flog(lvl::m, "vulkan::vkDestroyInstance");
      vkDestroyInstance(_instance, _allocator);
    }
    if(_window != nullptr){
      flog(lvl::m, "glfw::glfwDestroyWindow");
      glfwDestroyWindow(_window);
    }
    flog(lvl::m, "gflw::glfwTerminate");
    glfwTerminate();
  }

  void
  setup_vulkan(){
    {                                    //--create-vulkan-instance-without-any-debug-feature--------------------
      std::uint32_t extensions_count = 0;
      const char** extensions = glfwGetRequiredInstanceExtensions(&extensions_count);
      VkInstanceCreateInfo create_info = {};
      create_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
      create_info.enabledExtensionCount = extensions_count;
      create_info.ppEnabledExtensionNames = extensions;
      vk<&vkCreateInstance>("vkCreateInstance", &create_info, _allocator, &_instance);
    }

    {                                    //--select-gpu----------------------------------------------------------
      std::uint32_t gpu_count;
      vk<&vkEnumeratePhysicalDevices>("vkEnumeratePhysicalDevices", _instance, &gpu_count, nullptr);
      if(gpu_count <= 0){
        throw std::runtime_error("vulkan::vkEnumeratePhysicalDevices: invalid gpu count");
      }

      flog(lvl::m, "vulkan::setup: gpu_count = ", gpu_count);
      auto* gpus = static_cast<VkPhysicalDevice*>(malloc(sizeof(VkPhysicalDevice) * gpu_count));
      vk<&vkEnumeratePhysicalDevices>("vkEnumeratePhysicalDevices", _instance, &gpu_count, gpus);

      // If a number >1 of GPUs got reported, you should find the best fit GPU for your purpose e.g.
      // VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU if available, or with the greatest memory available, etc.
      // for sake of simplicity we'll just take the first one, assuming it has a graphics queue family.
      //
      _physical_device = gpus[0];
      free(gpus);
    }

    {                                    //--select-graphics-queue-family----------------------------------------
      std::uint32_t count;
      vkGetPhysicalDeviceQueueFamilyProperties(_physical_device, &count, nullptr);
      auto* queues = static_cast<VkQueueFamilyProperties*>(
        malloc(sizeof(VkQueueFamilyProperties) * count));
      vkGetPhysicalDeviceQueueFamilyProperties(_physical_device, &count, queues);
      for(std::uint32_t i = 0; i < count; i++){
        if(queues[i].queueFlags & VK_QUEUE_GRAPHICS_BIT){
          flog(lvl::m, "vulkan::vkGetPhysicalDeviceQueueFamilyProperties: queue_family_idx = ", i);
          _queue_family = i;
          break;
        }
      }
      free(queues);
      if(_queue_family == static_cast<std::uint32_t>(-1)){
        throw std::runtime_error("vulkan: unable to setup graphics queue familiy");
      }
    }

    {                                    //--create-logical-device-(-with-one-queue-)----------------------------
      std::uint32_t device_extension_count = 1;
      char const* device_extensions[] = { "VK_KHR_swapchain" };
      float const queue_priority[] = { 1.0f };
      VkDeviceQueueCreateInfo queue_info[1] = {};
      queue_info[0].sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
      queue_info[0].queueFamilyIndex = _queue_family;
      queue_info[0].queueCount = 1;
      queue_info[0].pQueuePriorities = queue_priority;
      VkDeviceCreateInfo create_info = {};
      create_info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
      create_info.queueCreateInfoCount = sizeof(queue_info) / sizeof(queue_info[0]);
      create_info.pQueueCreateInfos = queue_info;
      create_info.enabledExtensionCount = device_extension_count;
      create_info.ppEnabledExtensionNames = device_extensions;
      vk<&vkCreateDevice>("vkCreateDevice", _physical_device, &create_info, _allocator, &_device);
      vkGetDeviceQueue(_device, _queue_family, 0, &_queue);
    }

    {                                    //--create-descriptor-pool----------------------------------------------
      VkDescriptorPoolSize pool_sizes[] = { { VK_DESCRIPTOR_TYPE_SAMPLER, 1000 },
        { VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, 1000 },
        { VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE, 1000 },
        { VK_DESCRIPTOR_TYPE_STORAGE_IMAGE, 1000 },
        { VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER, 1000 },
        { VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER, 1000 },
        { VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER, 1000 },
        { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1000 },
        { VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC, 1000 },
        { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC, 1000 },
        { VK_DESCRIPTOR_TYPE_INPUT_ATTACHMENT, 1000 } };
      VkDescriptorPoolCreateInfo pool_info = {};
      pool_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
      pool_info.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
      pool_info.maxSets = 1000 * IM_ARRAYSIZE(pool_sizes);
      pool_info.poolSizeCount = static_cast<std::uint32_t>(IM_ARRAYSIZE(pool_sizes));
      pool_info.pPoolSizes = pool_sizes;
      vk<&vkCreateDescriptorPool>("vkCreateDescriptorPool", _device, &pool_info, _allocator,
                                  &_descriptor_pool);
    }
  }

  void
  setup_window(){
    glfwWindowHint(GLFW_CLIENT_API, GLFW_NO_API);
    _window = glfwCreateWindow(1920/2, 1080, "the-0wls ( on vulkan )", nullptr, nullptr);
    if(_window == nullptr){ throw std::runtime_error("glfw: unable to create window"); }
  }

  void
  setup_surface(){
    auto const err = glfwCreateWindowSurface(_instance, _window, _allocator, &_surface);
    if(err != 0){ throw vulkan_error(err); }
  }

  void
  setup_framebuffer(){
    glfwGetFramebufferSize(_window, &_framebuffer_width, &_framebuffer_height);
    glfwSetFramebufferSizeCallback(_window, glfw_resize_callback);
    flog(lvl::m, "vulkan::window: width = ", _framebuffer_width, " height = ", _framebuffer_height);
  }

  void
  setup_imgui_window(){
    _imgui_window.Surface = _surface;
    VkBool32 res;
    vkGetPhysicalDeviceSurfaceSupportKHR(_physical_device, _queue_family, _surface, &res);
    if(res != VK_TRUE){ throw std::runtime_error("vulkan: no WSI support on physical device"); }

    // select surface format
    VkFormat const format[] = { VK_FORMAT_B8G8R8A8_UNORM, VK_FORMAT_R8G8B8A8_UNORM,
                                VK_FORMAT_B8G8R8_UNORM, VK_FORMAT_R8G8B8_UNORM };
    VkColorSpaceKHR const colorspace = VK_COLORSPACE_SRGB_NONLINEAR_KHR;
    _imgui_window.SurfaceFormat = ImGui_ImplVulkanH_SelectSurfaceFormat(_physical_device, _surface, format, static_cast<std::size_t>(IM_ARRAYSIZE(format)),
                                                                        colorspace);

    // select present mode
    VkPresentModeKHR present_modes[] = { VK_PRESENT_MODE_FIFO_KHR };
    _imgui_window.PresentMode = ImGui_ImplVulkanH_SelectPresentMode(_physical_device, _surface,
                                                                    present_modes,
                                                                    IM_ARRAYSIZE(present_modes));
    flog(lvl::m, "ImGui_ImplVulkanH_SelectPresentMode: mode = ", _imgui_window.PresentMode);

    // create SwapChain, RenderPass, Framebuffer, etc.
    IM_ASSERT(_min_image_count >= 2);
    create_or_resize();
  }

  void
  create_or_resize(){
    ImGui_ImplVulkanH_CreateOrResizeWindow(_instance, _physical_device, _device, &_imgui_window,
                                           _queue_family, _allocator, _framebuffer_width,
                                           _framebuffer_height, _min_image_count);
  }

  void
  setup_imgui_context(){
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    (void)io;
    ImGui::StyleColorsLight();
    ImGui_ImplGlfw_InitForVulkan(_window, true);
    ImGui_ImplVulkan_InitInfo init_info = {};
    init_info.Instance = _instance;
    init_info.PhysicalDevice = _physical_device;
    init_info.Device = _device;
    init_info.QueueFamily = _queue_family;
    init_info.Queue = _queue;
    init_info.PipelineCache = g_PipelineCache;
    init_info.DescriptorPool = _descriptor_pool;
    init_info.Allocator = _allocator;
    init_info.MinImageCount = _min_image_count;
    init_info.ImageCount = _imgui_window.ImageCount;
    init_info.CheckVkResultFn = +[] (VkResult const result){
      if(result != 0){ throw vulkan_error(result); }
    };
    ImGui_ImplVulkan_Init(&init_info, _imgui_window.RenderPass);
  }

  void
  upload_fonts(){
    // use any command queue
    //
    VkCommandPool command_pool = _imgui_window.Frames[_imgui_window.FrameIndex].CommandPool;
    VkCommandBuffer command_buffer = _imgui_window.Frames[_imgui_window.FrameIndex].CommandBuffer;
    vk<&vkResetCommandPool>("vkResetCommandPool", _device, command_pool, 0u);

    VkCommandBufferBeginInfo begin_info = {};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags |= VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vk<&vkBeginCommandBuffer>("vkBeginCommandBuffer", command_buffer, &begin_info);

    flog(lvl::m, "ImGui_ImplVulkan_CreateFontsTexture");
    ImGui_ImplVulkan_CreateFontsTexture(command_buffer);

    VkSubmitInfo end_info = {};
    end_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    end_info.commandBufferCount = 1;
    end_info.pCommandBuffers = &command_buffer;
    vk<&vkEndCommandBuffer>("vkEndCommandBuffer", command_buffer);
    vk<&vkQueueSubmit>("vkQueueSubmit", _queue, 1u, &end_info, NULL_HANDLE);
    vk<&vkDeviceWaitIdle>("vkDeviceWaitIdle", _device);

    flog(lvl::m, "ImGui_ImplVulkan_DestroyFontUploadObjects");
    ImGui_ImplVulkan_DestroyFontUploadObjects();
  }

  bool
  on_window_size_changed(){
    //auto [w, h] = resize_callback_info::instance().get();
    //_framebuffer_width = w;
    //_framebuffer_height = h;
    int width = 0, height = 0;
    glfwGetFramebufferSize(_window, &width, &height);
    while(width == 0 || height == 0){
      glfwGetFramebufferSize(_window, &width, &height);
      glfwWaitEvents();
    }
    flog(lvl::m, "vulkan::context: width = ", width, " height = ", height);
    vkDeviceWaitIdle(_device);
    _framebuffer_width = width;
    _framebuffer_height = height;
    //ImGui_ImplVulkan_SetMinImageCount( _min_image_count );
    create_or_resize();
    //_imgui_window.FrameIndex = 0;
    return true;
  }
};

vulkan::vulkan(){
  _context = new context;
}
vulkan::~vulkan(){
  if(_context != nullptr){
    try {
      vk<&vkDeviceWaitIdle>("vkDeviceWaitIdle", _context->_device);
    } catch(...) {
      flog(lvl::e, "vulkan::vkDeviceWaitIdle failed");
    }
    delete _context;
  }
}

void
vulkan::init(){
  flog(lvl::m, "vulkan::init");
  glfwSetErrorCallback(glfw_error_callback);
  if(not glfwInit()){ throw std::runtime_error("unable to initialize glfw"); }
  if(not glfwVulkanSupported()){ throw std::runtime_error("vulkan unsupported"); }
  _context->setup_window();
  _context->setup_vulkan();
  _context->setup_surface();
  _context->setup_framebuffer();
  _context->setup_imgui_window();
  _context->setup_imgui_context();
}

bool
vulkan::on_window_size_changed() noexcept {
  flog(lvl::m, "vulkan: on_window_size_changed()");
  return _context->on_window_size_changed();
}

auto&
vulkan::window() noexcept {
  return _context->_imgui_window;
}
auto const&
vulkan::window() const noexcept {
  return _context->_imgui_window;
}

bool
vulkan::should_stop() const noexcept {
  return glfwWindowShouldClose(_context->_window);
}
void
vulkan::poll() noexcept {
  glfwPollEvents();
}

std::pair<int, int>
vulkan::frame() const noexcept {
  return std::pair{ _context->_framebuffer_width, _context->_framebuffer_height };
}

void
vulkan::begin() noexcept {
  if(resize_callback_info::instance().updated()){
    resize_callback_info::instance().reset();
    on_window_size_changed();
  }
  ImGui_ImplVulkan_NewFrame();
  ImGui_ImplGlfw_NewFrame();
  ImGui::NewFrame();
}

bool
vulkan::render() noexcept {
  constexpr auto MAX = std::numeric_limits<std::uint64_t>::max();
  auto& w = window();
  VkSemaphore image_acquired_semaphore = w.FrameSemaphores[w.SemaphoreIndex].ImageAcquiredSemaphore;
  VkSemaphore render_complete_semaphore = w.FrameSemaphores[w.SemaphoreIndex].RenderCompleteSemaphore;

  auto const rc = vk0<&vkAcquireNextImageKHR>("vkAcquireNextImageKHR", _context->_device, w.Swapchain,
                                              MAX, image_acquired_semaphore, nullptr, &w.FrameIndex);

  if(rc == VK_ERROR_OUT_OF_DATE_KHR){
    on_window_size_changed();
    return false;
  }else if(rc != VK_SUCCESS){
    return false;
  }

  ImGui_ImplVulkanH_Frame* fd = &w.Frames[w.FrameIndex];

  // wait indefinitely instead of periodically checking
  vk0<&vkWaitForFences>("vkWaitForFences", _context->_device, 1u, &fd->Fence, 1u, MAX);
  vk0<&vkResetFences>("vkResetFences", _context->_device, 1u, &fd->Fence);
  vk0<&vkResetCommandPool>("vkResetCommandPool", _context->_device, fd->CommandPool, 0u);

  {                                      //--begin-command-buffer--------------------------------------------------
    VkCommandBufferBeginInfo info = {};
    info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    info.flags |= VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vk0<&vkBeginCommandBuffer>("vkResetCommandPool", fd->CommandBuffer, &info);
  }

  {                                      //--begin-render-pass-----------------------------------------------------
    VkRenderPassBeginInfo info = {};
    info.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
    info.renderPass = w.RenderPass;
    info.framebuffer = fd->Framebuffer;
    info.renderArea.extent.width = static_cast<unsigned>(w.Width);
    info.renderArea.extent.height = static_cast<unsigned>(w.Height);
    info.clearValueCount = 1;
    info.pClearValues = &w.ClearValue;
    vkCmdBeginRenderPass(fd->CommandBuffer, &info, VK_SUBPASS_CONTENTS_INLINE);
  }

  // record imgui draw data and draw functions into command buffer
  ImGui_ImplVulkan_RenderDrawData(ImGui::GetDrawData(), fd->CommandBuffer);

  vkCmdEndRenderPass(fd->CommandBuffer);
  {                                      //--end-command-buffer-and-submit-queue-----------------------------------
    VkPipelineStageFlags wait_stage = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    VkSubmitInfo info = {};
    info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    info.waitSemaphoreCount = 1;
    info.pWaitSemaphores = &image_acquired_semaphore;
    info.pWaitDstStageMask = &wait_stage;
    info.commandBufferCount = 1;
    info.pCommandBuffers = &fd->CommandBuffer;
    info.signalSemaphoreCount = 1;
    info.pSignalSemaphores = &render_complete_semaphore;
    vk0<&vkEndCommandBuffer>("vkEndCommandBuffer", fd->CommandBuffer);
    vk0<&vkQueueSubmit>("vkQueueSubmit", _context->_queue, 1u, &info, fd->Fence);
  }
  return true;
}

void
vulkan::clear(ImVec4 const clear_color) noexcept {
  std::memcpy(&window().ClearValue.color.float32[0], &clear_color, 4 * sizeof(float));
}

void
vulkan::present() noexcept {
  auto& w = window();
  VkSemaphore render_complete_semaphore = w.FrameSemaphores[w.SemaphoreIndex].RenderCompleteSemaphore;
  VkPresentInfoKHR info = {};
  info.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
  info.waitSemaphoreCount = 1;
  info.pWaitSemaphores = &render_complete_semaphore;
  info.swapchainCount = 1;
  info.pSwapchains = &w.Swapchain;
  info.pImageIndices = &w.FrameIndex;
  auto const rc = vk0<&vkQueuePresentKHR>("vkQueuePresentKHR", _context->_queue, &info);
  if(rc == VK_ERROR_OUT_OF_DATE_KHR){ on_window_size_changed(); }
  // now we can use the next set of semaphores
  w.SemaphoreIndex = (w.SemaphoreIndex + 1) % w.ImageCount;
}

builder
vulkan::build(){
  builder b;
  b._vulkan->init();
  return b;
}

builder::builder(){
  _vulkan = new vulkan;
}

builder::~builder(){
  if(_vulkan != nullptr){
    flog(lvl::e, "vulkan::builder: unfinished builder detected");
    delete _vulkan;
  }
}

builder&
builder::add_font(std::filesystem::path const& path){
  flog(lvl::m, "vulkan::add_font path = ", path);
  return *this;
}

std::shared_ptr<vulkan>
builder::end(){
  auto* capture = _vulkan;
  capture->_context->upload_fonts();
  _vulkan = nullptr;
  return std::shared_ptr<vulkan>(capture);
}
}
