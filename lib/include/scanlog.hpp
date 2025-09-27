#pragma once

#include <blockingconcurrentqueue.h>
#include <boost/filesystem.hpp>
#include <format>
#include <fstream>
#include <source_location>

namespace viruscan {

struct FileScannedEvent {
  boost::filesystem::path path;
  std::string md5_hash;
  uintmax_t size;
};

struct VirusFoundEvent {
  boost::filesystem::path path;
  std::string md5_hash;
  std::string threat_name;
};

struct ScanErrorEvent {
  boost::filesystem::path path;
  std::string error_message;
  std::source_location location;
};

struct ScanProgressEvent {
  size_t files_processed;
  size_t total_files_estimated;
  double progress_percentage;
};

class IScanEventHandler {
public:
  virtual ~IScanEventHandler() = default;
  virtual void on_file_scanned(const FileScannedEvent &event) = 0;
  virtual void on_virus_found(const VirusFoundEvent &event) = 0;
  virtual void on_scan_error(const ScanErrorEvent &event) = 0;
  virtual void on_progress_update(const ScanProgressEvent &event) = 0;
};

class FileScanEventHandler : public IScanEventHandler {
private:
  moodycamel::BlockingConcurrentQueue<std::string> log_queue;
  std::jthread writer_thread;
  std::atomic<bool> stop_writer{false};
  std::string log_path;
  static constexpr size_t RESERVED_BUFFER = 100;

  void writer_worker() {
    std::ofstream file(log_path, std::ios::out);
    if (!file.is_open()) {
      throw std::runtime_error("Cannot open log file: " + log_path);
    }

    std::vector<std::string> buffer;
    buffer.reserve(RESERVED_BUFFER);

    while (!stop_writer || log_queue.size_approx() != 0) {
      std::string message;
      bool got_message =
          log_queue.wait_dequeue_timed(message, std::chrono::milliseconds(100));
      if (got_message) {
        buffer.push_back(std::move(message));
        if (buffer.size() >= RESERVED_BUFFER) {
          flush_buffer(file, buffer);
        }
      } else {
        if (stop_writer && log_queue.size_approx() == 0) {
          break;
        }
      }
    }
    flush_buffer(file, buffer);
  }

  void flush_buffer(std::ofstream &file, std::vector<std::string> &buffer) {
    for (const auto &msg : buffer) {
      file << msg << '\n';
    }
    file.flush();
    buffer.clear();
  }

public:
  explicit FileScanEventHandler(const std::string &path)
      : log_path(path),
        writer_thread(&FileScanEventHandler::writer_worker, this) {}

  ~FileScanEventHandler() {
    stop_writer = true;
    if (writer_thread.joinable()) {
      writer_thread.join();
    }
  }

  void write_log(const std::string &message) { log_queue.enqueue(message); }

  void on_file_scanned(const FileScannedEvent &event) override {
    write_log(std::format("SCANNED|{}|{}|{}", event.path.generic_string(),
                          event.size, event.md5_hash));
  }

  void on_virus_found(const VirusFoundEvent &event) override {
    write_log(std::format("VIRUS|{}|{}|{}", event.path.generic_string(),
                          event.threat_name, event.md5_hash));
  }

  void on_scan_error(const ScanErrorEvent &event) override {
    write_log(std::format("ERROR|{}|{}:{}|{}", event.path.generic_string(),
                          event.location.file_name(), event.location.line(),
                          event.error_message));
  }

  void on_progress_update(const ScanProgressEvent &event) override {
    write_log(std::format("PROGRESS|{}/{}|{:.1f}%", event.files_processed,
                          event.total_files_estimated,
                          event.progress_percentage));
  }
};

} // namespace viruscan
