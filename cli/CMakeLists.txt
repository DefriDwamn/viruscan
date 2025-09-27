cmake_minimum_required(VERSION 3.31.7)
project(viruscancli CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES
    ${CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES})
set(CONCURRENTQUEUE_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/../externals/concurrentqueue)

include(FetchContent)
FetchContent_Declare(
  boost
  URL https://github.com/boostorg/boost/releases/download/boost-1.89.0/boost-1.89.0-cmake.7z
      USES_TERMINAL_DOWNLOAD
      TRUE
  DOWNLOAD_NO_EXTRACT FALSE)
FetchContent_MakeAvailable(boost)

file(GLOB_RECURSE SOURCES "src/*.cpp")

add_executable(viruscancli ${SOURCES})

target_link_libraries(viruscancli PRIVATE viruscanlib Boost::program_options
                                          Boost::filesystem)
target_include_directories(
  viruscancli
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
          ${CMAKE_CURRENT_SOURCE_DIR}/../lib/include ${CONCURRENTQUEUE_DIR})
