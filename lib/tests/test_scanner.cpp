#include "boost/filesystem/operations.hpp"
#include "scanner.hpp"
#include "gmock/gmock.h"
#include <atomic>
#include <chrono>
#include <fstream>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>

using namespace viruscan;
using namespace testing;
using namespace std::chrono_literals;

class MockScanEventHandler : public IScanEventHandler {
public:
  MOCK_METHOD(void, on_file_scanned, (const FileScannedEvent &), (override));
  MOCK_METHOD(void, on_virus_found, (const VirusFoundEvent &), (override));
  MOCK_METHOD(void, on_scan_error, (const ScanErrorEvent &), (override));
  MOCK_METHOD(void, on_progress_update, (const ScanProgressEvent &),
              (override));
};

class ScannerTest : public Test {
protected:
  void SetUp() override {
    test_dir = boost::filesystem::current_path() / "scanner_test";
    boost::filesystem::create_directories(test_dir);
    csv_path = test_dir / "viruses.csv";
    create_test_csv();
  }

  void TearDown() override { boost::filesystem::remove_all(test_dir); }

  void create_test_csv() {
    std::ofstream csv(csv_path.string(), std::ios::binary);
    csv << "5d41402abc4b2a76b9719d911017c592;TestVirus\n"
        << "e4d909c290d0fb1ca068ffaddf22cbd0;AnotherVirus\n";
    csv.close();
  }

  void create_file(const boost::filesystem::path &path,
                            const std::string &content) {
    std::ofstream file(path.string(), std::ios::binary);
    file << content;
    file.close();
  }

  boost::filesystem::path test_dir;
  boost::filesystem::path csv_path;
};

TEST_F(ScannerTest, CtorInit) {
  EXPECT_NO_THROW({ Scanner scanner(csv_path); });
}

TEST_F(ScannerTest, AddEventHandler) {
  Scanner scanner(csv_path);
  auto handler = std::make_unique<MockScanEventHandler>();

  EXPECT_NO_THROW({ scanner.add_event_handler(std::move(handler)); });
}

TEST_F(ScannerTest, ScanEmptyDirectoryCompletes) {
  Scanner scanner(csv_path);
  auto mock_handler = std::make_unique<MockScanEventHandler>();

  EXPECT_CALL(*mock_handler, on_progress_update(_)).Times(1);

  EXPECT_CALL(*mock_handler, on_file_scanned(_)).Times(0);

  EXPECT_CALL(*mock_handler, on_virus_found(_)).Times(0);

  scanner.add_event_handler(std::move(mock_handler));

  auto empty_dir = test_dir / "empty_dir";
  boost::filesystem::create_directories(empty_dir);

  scanner.scan(empty_dir.string());
}

TEST_F(ScannerTest, ScanDetectsKnownVirus) {
  auto infected_file = test_dir / "infected2.txt";
  create_file(infected_file, "hello");

  Scanner scanner(csv_path);
  auto mock_handler = std::make_unique<MockScanEventHandler>();
  
  EXPECT_CALL(*mock_handler, on_file_scanned(_)).Times(AtLeast(1));
  EXPECT_CALL(*mock_handler, on_virus_found(_)).Times(AtLeast(1));
  EXPECT_CALL(*mock_handler, on_progress_update(_)).Times(AtLeast(1));

  scanner.add_event_handler(std::move(mock_handler));

  scanner.scan(test_dir.string());
}

TEST_F(ScannerTest, ScanHandlesNonExistentPath) {
  Scanner scanner(csv_path);
  auto mock_handler = std::make_unique<MockScanEventHandler>();

  EXPECT_CALL(*mock_handler, on_scan_error(_)).Times(AtLeast(1));

  scanner.add_event_handler(std::move(mock_handler));

  scanner.scan("/non/existent/path/that/does/not/exist");
}

TEST_F(ScannerTest, StopScanTerminatesGracefully) {
  Scanner scanner(csv_path);

  for (int i = 0; i < 50; ++i) {
    std::ofstream file((test_dir / ("stop_test_" + std::to_string(i) + ".txt")).string());
    file << "Content " << i;
    file.close();
  }

  std::atomic<bool> scan_completed{false};

  std::thread scan_thread([&]() {
    scanner.scan(test_dir.string());
    scan_completed = true;
  });

  std::this_thread::sleep_for(10ms);

  scanner.stop_scan();

  scan_thread.join();

  EXPECT_TRUE(scan_completed);
}

TEST_F(ScannerTest, StopScanImmediateTerminatesQuickly) {
  Scanner scanner(csv_path);

  for (int i = 0; i < 20; ++i) {
    std::ofstream file((test_dir /
                       ("immediate_stop_" + std::to_string(i) + ".txt")).string());
    file << "Content " << i;
    file.close();
  }

  std::atomic<bool> scan_completed{false};
  auto start_time = std::chrono::steady_clock::now();

  std::thread scan_thread([&]() {
    scanner.scan(test_dir.string());
    scan_completed = true;
  });

  std::this_thread::sleep_for(5ms);
  scanner.stop_scan_immediate();

  scan_thread.join();
  auto duration = std::chrono::steady_clock::now() - start_time;

  EXPECT_TRUE(scan_completed);
  EXPECT_LT(duration, 1s);
}

TEST_F(ScannerTest, ScanningProcessesAllFiles) {
  for (int i = 0; i < 30; ++i) {
    std::ofstream file((test_dir / ("concurrent_" + std::to_string(i) + ".txt")).string());
    file << "File " << i;
    file.close();
  }

  Scanner scanner(csv_path);
  auto mock_handler = std::make_unique<MockScanEventHandler>();

  std::atomic<int> files_scanned{0};

  EXPECT_CALL(*mock_handler, on_file_scanned(_))
      .WillRepeatedly([&](const FileScannedEvent &) { files_scanned++; });

  scanner.add_event_handler(std::move(mock_handler));
  scanner.scan(test_dir.string());

  EXPECT_GE(files_scanned, 30);
}
