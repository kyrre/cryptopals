cmake_minimum_required(VERSION 3.7.1)

set(CMAKE_C_COMPILER "/usr/bin/clang")
set(CMAKE_CXX_COMPILER "/usr/bin/clang++")
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic -Wextra -Wno-gnu -pthread")
set(THREADS_PREFER_PTHREAD_FLAG ON)


# Hunter snapshot that will be used
include("cmake/HunterGate.cmake")
HunterGate(
    URL "https://github.com/ruslo/hunter/archive/v0.18.43.tar.gz"
    SHA1 "d2c8c42cd07f7cefe18fd9a9b9c13114b1a15a27"
)

# ignore warnings from
include_directories(SYSTEM "include")
project(cryptopals)

# Download dependencies
hunter_add_package(Catch)
hunter_add_package(cxxopts)
hunter_add_package(fmt)
hunter_add_package(Boost)
hunter_add_package(OpenSSL)
hunter_add_package(Boost COMPONENTS system filesystem)
hunter_add_package(CURL)



find_package(Threads REQUIRED)

# Find dependencies
find_package(Catch CONFIG REQUIRED)
find_package(cxxopts CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(Boost CONFIG REQUIRED system)
find_package(OpenSSL REQUIRED)
find_package(CURL CONFIG REQUIRED)



set(BYTE
  src/bytearray.cpp
  src/utils.cpp
  src/analysis/aes.cpp
  src/hex.cpp
  src/fs.cpp
  src/hamming.cpp
  src/oracle/aes.cpp
  src/oracle/profile.cpp
  src/analysis/frequency.cpp
  src/mt19937.cpp
  src/sha1.cpp
)

set(AES
  src/methods/aes.cpp
  src/methods/padding.cpp
)


# Targets
add_executable(simple src/simple.cpp src/hist.cpp ${AES} ${BYTE})
target_link_libraries(simple PUBLIC cxxopts::cxxopts fmt Boost::boost OpenSSL::SSL OpenSSL::Crypto Boost::system Threads::Threads PRIVATE CURL::libcurl)

add_executable(server src/server.cpp src/bytearray.cpp src/sha1.cpp src/hex.cpp)
target_link_libraries(server PUBLIC fmt Boost::system Threads::Threads)


# Tests
add_executable(challenge1 tests/base.cpp tests/challenge1.cpp src/hist.cpp ${AES} ${BYTE})
target_link_libraries(challenge1 PUBLIC Catch::Catch OpenSSL::SSL OpenSSL::Crypto)
#
add_executable(challenge2 tests/base.cpp tests/challenge2.cpp src/bytearray.cpp src/hist.cpp ${AES} ${BYTE})
target_link_libraries(challenge2 PUBLIC Catch::Catch OpenSSL::SSL OpenSSL::Crypto)
#

add_executable(challenge3 tests/base.cpp tests/challenge3.cpp src/bytearray.cpp src/hist.cpp ${AES} ${BYTE})
target_link_libraries(challenge3 PUBLIC Catch::Catch OpenSSL::SSL OpenSSL::Crypto)
#
add_executable(challenge4 tests/base.cpp tests/challenge4.cpp src/bytearray.cpp src/hist.cpp ${AES} ${BYTE})
target_link_libraries(challenge4 PUBLIC Catch::Catch OpenSSL::SSL OpenSSL::Crypto)
#
add_executable(challenge5 tests/base.cpp tests/challenge5.cpp)
target_link_libraries(challenge5 PUBLIC Catch::Catch Boost::boost OpenSSL::SSL OpenSSL::Crypto)
#


add_executable(hist tests/base.cpp tests/hist.cpp src/hist.cpp src/bytearray.cpp)
target_link_libraries(hist PUBLIC Catch::Catch)
#
add_executable(hamming tests/base.cpp tests/hamming.cpp src/hamming.cpp src/bytearray.cpp)
target_link_libraries(hamming PUBLIC Catch::Catch)

add_executable(mt19937 tests/base.cpp tests/mt19937.cpp src/bytearray.cpp src/mt19937.cpp)
target_link_libraries(mt19937 PUBLIC Catch::Catch)



# Testing
enable_testing()
include_directories(src)
add_test(NAME Challenge1 COMMAND challenge1)
add_test(NAME Challenge2 COMMAND challenge2)
add_test(NAME Challenge3 COMMAND challenge3)
add_test(NAME Challenge4 COMMAND challenge4)

add_test(NAME Histogram COMMAND hist)
add_test(NAME Hamming COMMAND hamming)
add_test(NAME MT19937 COMMAND mt19937)
