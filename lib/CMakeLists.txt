cmake_minimum_required(VERSION 3.31.7)
project(viruscanlib CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES
    ${CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES})

include(FetchContent)
FetchContent_Declare(
  gtest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.17.0)
FetchContent_Declare(
  boost
  URL https://github.com/boostorg/boost/releases/download/boost-1.89.0/boost-1.89.0-cmake.7z
      USES_TERMINAL_DOWNLOAD
      TRUE
  DOWNLOAD_NO_EXTRACT FALSE)
FetchContent_MakeAvailable(gtest boost)

file(GLOB_RECURSE SOURCES "src/*.cpp")
include_directories("include")
add_library(viruscanlib SHARED ${SOURCES})
target_link_libraries(viruscanlib PRIVATE Boost::filesystem Boost::hash2)

option(BUILD_TESTS "Tests" ON)
if(BUILD_TESTS)
  enable_testing()

  add_executable(viruscanlib_tests tests/test_md5calc.cpp)
  target_link_libraries(viruscanlib_tests PRIVATE viruscanlib GTest::gtest_main
                                                  Boost::filesystem)
  include(GoogleTest)
  gtest_discover_tests(viruscanlib_tests
                       WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endif()
