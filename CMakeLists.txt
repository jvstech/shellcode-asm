cmake_minimum_required(VERSION 3.16)
if (MSVC)
  cmake_policy(SET CMP0091 NEW)
endif()

project(shellcode-asm)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")

if (DEFINED PATH_TO_LLVM AND NOT "${PATH_TO_LLVM}" STREQUAL "")
  set(llvm_search_paths
    ${PATH_TO_LLVM}
    ${PATH_TO_LLVM}/lib
    ${PATH_TO_LLVM}/lib/cmake
    ${PATH_TO_LLVM}/lib/cmake/llvm
    ${PATH_TO_LLVM}/share/llvm/cmake)
  find_package(LLVM REQUIRED CONFIG
    PATHS ${llvm_search_paths}
    NO_DEFAULT_PATH)
else()
  find_package(LLVM REQUIRED CONFIG)
endif()

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}: ${LLVM_INSTALL_PREFIX}")
set(CMAKE_MODULE_PATH
  "${CMAKE_MODULE_PATH};${LLVM_INSTALL_PREFIX}/lib/cmake/llvm")
set(CMAKE_MODULE_PATH
  "${CMAKE_MODULE_PATH};${CMAKE_SOURCE_DIR}/cmake")
include(AddLLVM)
if (NOT LLVM_ENABLE_RTTI)
  if (MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /GR-")
  else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
  endif()
endif()
include_directories(${LLVM_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/include)
add_definitions(${LLVM_DEFINITIONS})

if (WIN32 OR CYGWIN)
  #set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

set(LLVM_LINK_COMPONENTS
  AllTargetsAsmParsers
  AllTargetsDescs
  AllTargetsDisassemblers
  AllTargetsInfos
  CodeGen
  Core
  LineEditor
  MC
  MCDisassembler
  MCParser
  Support
  )

add_subdirectory(lib)
add_subdirectory(tools)

