cmake_minimum_required(VERSION 3.10)
project(Zanshin VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "[-] libpcap not found. Install it with: sudo apt install libpcap-dev")
endif()

option(ZANSHIN_NATIVE_OPT "Optimize for the build host CPU (non-portable)" OFF)

add_executable(zanshin main.cpp)
target_link_libraries(zanshin PRIVATE ${PCAP_LIBRARY})
target_compile_options(zanshin PRIVATE -O2 -Wall -Wextra -Wpedantic)

if(ZANSHIN_NATIVE_OPT)
    target_compile_options(zanshin PRIVATE -march=native)
endif()