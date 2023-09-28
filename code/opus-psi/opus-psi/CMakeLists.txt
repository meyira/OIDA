cmake_minimum_required(VERSION 3.4.1)
set(CMAKE_SOURCE_DIR ..)

add_subdirectory(GSL)
add_subdirectory(csidh-20210627)
add_subdirectory(cuckoofilter)

set(SRCS
  AES.cpp
  BitVector.cpp
  ChannelWrapper.cpp
  Defines.cpp
  PRNG.cpp
  SecureRandom.cpp
  utils/Log.cpp
  )

add_library(opus-psi SHARED ${SRCS})

# normal x86 build
set(CMAKE_C_FLAGS "-ffunction-sections -Wall -msse2 \
-msse4.1 -mpclmul -flto -no-pie -Wno-ignored-attributes \
-fPIC -fsanitize=address")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++20 -maes -mrdseed ")

SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O3 -g -ggdb -rdynamic")
SET(CMAKE_CXX_FLAGS_DEBUG "-O3 -g -ggdb -rdynamic")


target_include_directories(opus-psi PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../")
target_include_directories(opus-psi PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../csidh-20210627")
target_link_libraries(opus-psi
  GSL
  )

target_link_libraries(opus-psi cuckoo csidh)


add_subdirectory(test)

