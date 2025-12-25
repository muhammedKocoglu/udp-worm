cmake_minimum_required(VERSION 3.16)
project(UDPWorm)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic")

# Find Boost
# Asio is header-only but may depend on System for certain features.
find_package(Boost 1.71.0 REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Gather all source files
file(GLOB_RECURSE SOURCES "src/*.cpp")

# Add the executable
add_executable(udp_fec_test ${SOURCES})

set(RAPTORQ_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/libraptorq)
set(RAPTORQ_INCLUDE_DIR ${RAPTORQ_ROOT})
set(RAPTORQ_EIGEN_DIR ${RAPTORQ_ROOT}/eigen3)

# Include directories
target_include_directories(udp_fec_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
    ${RAPTORQ_INCLUDE_DIR}
    ${RAPTORQ_EIGEN_DIR}
    ${Boost_INCLUDE_DIRS}
)
target_compile_definitions(udp_fec_test PRIVATE RQ_HEADER_ONLY)

# Link Boost libraries and filesystem for C++17+
target_link_libraries(udp_fec_test PRIVATE 
    Boost::system
    OpenSSL::Crypto
    Threads::Threads
    stdc++fs
)

# Place the executable in the build directory for easy testing
set_target_properties(udp_fec_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

message(STATUS "Source files: ${SOURCES}")
