cmake_minimum_required(VERSION 3.4.1)
project(CSI-FiSh LANGUAGES C DESCRIPTION "adapted CSI-FiSh with PRF")
enable_language(C ASM)

add_library(CSI-FiSh STATIC
		p512/constants.c 
		rng.c 
		mont.c 
    p512/uint.s
    p512/fp.s
		classgroup.c 
		csidh.c 
    reduce.c 
    )

  set(CMAKE_POSITION_INDEPENDENT_CODE ON)

  set(CMAKE_C_FLAGS "-std=c99 -pedantic -Wall -Wextra -march=native -O3 -fPIC")

  # for keccak
  add_custom_target(ALL COMMAND make all
                   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/XKCP/)
  target_include_directories(CSI-FiSh PUBLIC  "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(CSI-FiSh PUBLIC keccak)
