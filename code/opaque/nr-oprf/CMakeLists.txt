
cmake_minimum_required(VERSION 3.10)

project(nr-oprf LANGUAGES C CXX)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/PQ-MPC/cmake)

add_compile_options("-pthread;-Wall;-march=native;-maes;-mrdseed;-std=c++17;-O3;-fPIC")

find_package(GMP REQUIRED)

find_package(SEAL 3.1.0 EXACT QUIET)
if (NOT SEAL_FOUND)
    message(STATUS "SEAL 3.1.0 was not found: clone and install SEAL locally")
    execute_process(COMMAND ${CMAKE_COMMAND} -DCMAKE_INSTALL_PREFIX=${PROJECT_SOURCE_DIR}/build .
      WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/PQ-MPC/extern/SEAL/src")
    execute_process(COMMAND ${CMAKE_COMMAND} --build . --target install
      WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/PQ-MPC/extern/SEAL/src")
    find_package(SEAL 3.1.0 EXACT REQUIRED PATHS "${PROJECT_SOURCE_DIR}/PQ-MPC/extern/SEAL/src")
endif ()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/PQ-MPC)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../csidh)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../csidh/p512)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../CSI-FiSh/implementation)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../CSI-FiSh/implementation/XKCP/bin/generic64)

add_subdirectory(PQ-MPC/emp-tool)
add_subdirectory(PQ-MPC/pq-ot)

add_library(nr-oprf SHARED oprf.cpp)
target_link_libraries(nr-oprf
  PUBLIC
  emp-tool
  pq-ot
  )
