#pragma once

#include <boost/filesystem.hpp>
#include <format>
#include <fstream>
#include <iomanip>
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
  std::ofstream log_file_;
  std::string log_path_;

public:
  explicit FileScanEventHandler(const std::string &log_path)
      : log_path_(log_path) {
    open_log_file();
  }

  ~FileScanEventHandler() override {
    if (log_file_.is_open()) {
      log_file_.close();
    }
  }

  void on_file_scanned(const FileScannedEvent &event) override {
    write_log(std::format("SCANNED|{}|{}|{}|{}", get_current_timestamp(),
                          event.path.string(), event.size, event.md5_hash));
  }

  void on_virus_found(const VirusFoundEvent &event) override {
    write_log(std::format("VIRUS|{}|{}|{}|{}", get_current_timestamp(),
                          event.path.string(), event.threat_name,
                          event.md5_hash));
  }

  void on_scan_error(const ScanErrorEvent &event) override {
    write_log(std::format("ERROR|{}|{}|{}:{}|{}", get_current_timestamp(),
                          event.path.string(), event.location.file_name(),
                          event.location.line(), event.error_message));
  }

  void on_progress_update(const ScanProgressEvent &event) override {
    write_log(std::format("PROGRESS|{}|{}/{}|{:.1f}%", get_current_timestamp(),
                          event.files_processed, event.total_files_estimated,
                          event.progress_percentage));
  }

  void reopen() {
    if (log_file_.is_open()) {
      log_file_.close();
    }
    open_log_file();
  }

  std::string get_log_path() const { return log_path_; }

private:
  void open_log_file() {
    log_file_.open(log_path_, std::ios::app);
    if (!log_file_.is_open()) {
      throw std::runtime_error("Cannot open log file: " + log_path_);
    }
    log_file_ << std::format("!!!! Scan started at {}\n",
                             get_current_timestamp());
    log_file_.flush();
  }

  void write_log(const std::string &message) {
    if (!log_file_.is_open()) {
      reopen();
    }

    log_file_ << message << '\n';
    log_file_.flush();
  }

  std::string get_current_timestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
  }
};

} // namespace viruscan
