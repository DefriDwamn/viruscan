#include "boost/filesystem/operations.hpp"
#include "virusdatabase.hpp"
#include <boost/filesystem.hpp>
#include <fstream>
#include <gtest/gtest.h>
#include <random>

namespace fs = boost::filesystem;

class VirusDatabaseTest : public ::testing::Test {
protected:
  fs::path test_dir;

  void SetUp() override {
    test_dir = fs::current_path() / "virusdb_test";
    fs::create_directories(test_dir);
  }

  void TearDown() override { fs::remove_all(test_dir); }
  fs::path create_sample_db() {
    auto path = test_dir / "viruses.csv";
    std::ofstream file(path.string(), std::ios::binary);
    file << "a9963513d093ffb2bc7ceb9807771ad4;Exploit\n"
         << "ac6204ffeb36d2320e52f1d551cfa370;Dropper\n"
         << "8ee70903f43b227eeb971262268af5a8;Downloader\n"
         << "d41d8cd98f00b204e9800998ecf8427e;Trojan\n"
         << "5d41402abc4b2a76b9719d911017c592;Worm\n"
         << "098f6bcd4621d373cade4e832627b4f6;Ransomware\n"
         << "ad0234829205b9033196ba818f7a872b;Spyware\n";
    return path;
  }
  fs::path create_large_db() {
    auto path = test_dir / "large.csv";
    std::ofstream file(path.string(), std::ios::binary);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    for (int i = 0; i < 100000; ++i) {
      std::string md5;
      for (int j = 0; j < 32; ++j) {
        md5 += "0123456789abcdef"[dis(gen)];
      }
      file << md5 << ";ThreatType" << i << "\n";
    }
    file << "a9963513d093ffb2bc7ceb9807771ad4;Exploit\n";
    return path;
  }
};

TEST_F(VirusDatabaseTest, FindExist) {
  auto db_path = create_sample_db();
  viruscan::VirusDatabase db(db_path);

  auto result1 = db.contains("a9963513d093ffb2bc7ceb9807771ad4");
  EXPECT_TRUE(result1.has_value());
  EXPECT_EQ(result1.value(), "Exploit");

  auto result2 = db.contains("ac6204ffeb36d2320e52f1d551cfa370");
  EXPECT_TRUE(result2.has_value());
  EXPECT_EQ(result2.value(), "Dropper");

  auto result3 = db.contains("8ee70903f43b227eeb971262268af5a8");
  EXPECT_TRUE(result3.has_value());
  EXPECT_EQ(result3.value(), "Downloader");
}

TEST_F(VirusDatabaseTest, FindNonExist) {
  auto db_path = create_sample_db();
  viruscan::VirusDatabase db(db_path);

  auto result = db.contains("00000000000000000000000000000000");
  EXPECT_FALSE(result.has_value());

  auto result2 = db.contains("short");
  EXPECT_FALSE(result2.has_value());

  auto result3 = db.contains("");
  EXPECT_FALSE(result3.has_value());
}

TEST_F(VirusDatabaseTest, ThrowsOnMissingFile) {
  auto missing_path = test_dir / "nonexistent.csv";

  EXPECT_THROW(
      { viruscan::VirusDatabase db(missing_path); }, std::runtime_error);
}

TEST_F(VirusDatabaseTest, ThrowsOnDirectory) {
  auto dir_path = test_dir / "directory";
  fs::create_directories(dir_path);

  EXPECT_THROW({ viruscan::VirusDatabase db(dir_path); }, std::runtime_error);
}

TEST_F(VirusDatabaseTest, LargeFile) {
  auto db_path = create_large_db();
  viruscan::VirusDatabase db(db_path);
  auto result = db.contains("a9963513d093ffb2bc7ceb9807771ad4");
  EXPECT_TRUE(result.has_value());
  EXPECT_EQ(result.value(), "Exploit");
}
