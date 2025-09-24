#include "boost/filesystem/operations.hpp"
#include "md5calc.hpp"
#include <algorithm>
#include <boost/filesystem.hpp>
#include <fstream>
#include <gtest/gtest.h>
#include <random>

namespace fs = boost::filesystem;

class MD5CalcTest : public ::testing::Test {
protected:
  fs::path test_dir;
  viruscan::md5calc calculator;

  void SetUp() override {
    test_dir = fs::current_path() / "md5calc_test";
    fs::create_directories(test_dir);
  }

  // void TearDown() override { fs::remove_all(test_dir); }

  fs::path create_test_file(const std::string &filename,
                            const std::string &content) {
    auto path = test_dir / filename;
    std::ofstream file(path, std::ios::binary);
    file.write(content.data(), content.size());
    return path;
  }

  fs::path create_random_file(const std::string &filename, size_t size) {
    auto path = test_dir / filename;
    std::ofstream f(path, std::ios::binary);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<char> dist;
    std::vector<char> data(size);
    for (auto &c : data) {
      c = dist(gen);
    }
    f.write(data.data(), data.size());
    return path;
  }
};

TEST_F(MD5CalcTest, EmptyFile) {
  auto filepath = create_test_file("empty.txt", "");
  auto result = calculator.calc(filepath);

  EXPECT_EQ(result, "d41d8cd98f00b204e9800998ecf8427e");
}

TEST_F(MD5CalcTest, SmallFile) {
  auto filepath = create_test_file("small.txt", "Hello, World!");
  auto result = calculator.calc(filepath);

  EXPECT_EQ(result, "65a8e27d8879283831b664bd8b7f0ad4");
}

TEST_F(MD5CalcTest, RussianText) {
  auto filepath = create_test_file("russian.txt", "Привет, мир!");
  auto result = calculator.calc(filepath);

  EXPECT_EQ(result, "c446a2994f35689482651b7c7ba8b56c");
}

TEST_F(MD5CalcTest, LargeFile) {
  auto filepath = create_random_file("large.bin", 1 * 1024 * 1024 * 1024);
  auto result = calculator.calc(filepath);
  std::cout << "Large md5: " << result << "\n";
  EXPECT_EQ(result.size(), 32);
  EXPECT_TRUE(std::all_of(result.begin(), result.end(),
                          [](char c) { return std::isxdigit(c); }));
}

TEST_F(MD5CalcTest, ExactBufferSize) {
  auto filepath = create_random_file("exact_8k.bin", 8 * 1024);
  auto result = calculator.calc(filepath);

  EXPECT_EQ(result.size(), 32);
}

TEST_F(MD5CalcTest, BufferSizePlusOne) {
  auto filepath = create_random_file("8k_plus_1.bin", 8 * 1024 + 1);
  auto result = calculator.calc(filepath);

  EXPECT_EQ(result.size(), 32);
}

TEST_F(MD5CalcTest, NonExistentFile) {
  auto filepath = test_dir / "nonexistent.txt";

  EXPECT_THROW({ calculator.calc(filepath); }, std::runtime_error);
}

TEST_F(MD5CalcTest, ConsistentHashing) {
  auto filepath = create_test_file("consistent.txt", "Test content");

  auto hash1 = calculator.calc(filepath);
  auto hash2 = calculator.calc(filepath);

  EXPECT_EQ(hash1, hash2);
  EXPECT_EQ(hash1.size(), 32);
}

TEST_F(MD5CalcTest, DifferentFilesDifferentHashes) {
  auto file1 = create_test_file("file1.txt", "Content 1");
  auto file2 = create_test_file("file2.txt", "Content 2");

  auto hash1 = calculator.calc(file1);
  auto hash2 = calculator.calc(file2);

  EXPECT_NE(hash1, hash2);
}

TEST_F(MD5CalcTest, ValidMD5Format) {
  auto filepath = create_test_file("format_test.txt", "MD5 format test");
  auto result = calculator.calc(filepath);

  EXPECT_EQ(result.size(), 32);
  EXPECT_TRUE(std::all_of(result.begin(), result.end(), [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
  }));
}
