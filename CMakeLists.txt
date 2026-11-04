cmake_minimum_required(VERSION 3.16)
project(rar3crack LANGUAGES CXX)

# Objective-C++ on Apple for the Metal backend
if(APPLE)
  enable_language(OBJCXX)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O3")

# ---- core (portable) ----
add_library(rar3core STATIC
  src/rar3.cpp
)
target_include_directories(rar3core PUBLIC include)
target_compile_definitions(rar3core PUBLIC RAR3_VERSION="0.1.0")

# ---- backends ----
set(BACKEND_SRCS
  backends/cpu_backend.cpp
  backends/stub_backends.cpp
)

# Metal (macOS only)
if(APPLE)
  set(BACKEND_SRCS ${BACKEND_SRCS} backends/metal_backend.mm)
  set(METAL_LIBS "-framework Metal" "-framework Foundation")
  target_compile_definitions(rar3core PUBLIC RAR3_HAVE_METAL=1)
  # apply to the executable below via target_link_libraries / compile flags
  set(HAVE_METAL TRUE)
endif()

# OpenCL (optional, cross-platform)
option(RAR3_WITH_OPENCL "Build OpenCL backend" OFF)
if(RAR3_WITH_OPENCL)
  find_package(OpenCL REQUIRED)
  list(APPEND BACKEND_SRCS backends/opencl_backend.cpp)
  target_compile_definitions(rar3core PUBLIC RAR3_HAVE_OPENCL=1)
endif()

# CUDA (optional, NVIDIA)
option(RAR3_WITH_CUDA "Build CUDA backend" OFF)
if(RAR3_WITH_CUDA)
  enable_language(CUDA)
  list(APPEND BACKEND_SRCS backends/cuda_backend.cu)
  target_compile_definitions(rar3core PUBLIC RAR3_HAVE_CUDA=1)
endif()

# ---- executable ----
add_executable(rar3crack src/main.cpp ${BACKEND_SRCS})
target_link_libraries(rar3crack PRIVATE rar3core)

if(HAVE_METAL)
  target_link_libraries(rar3crack PRIVATE "-framework Metal" "-framework Foundation")
  set_source_files_properties(backends/metal_backend.mm PROPERTIES COMPILE_FLAGS "-fobjc-arc")
endif()

if(RAR3_WITH_OPENCL)
  target_link_libraries(rar3crack PRIVATE OpenCL::OpenCL)
endif()

# ---- tests ----
add_executable(selftest tests/selftest.cpp)
target_link_libraries(selftest PRIVATE rar3core)
enable_testing()
add_test(NAME core_selftest COMMAND selftest)
