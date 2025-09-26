#include "blockingconcurrentqueue.h"
#include "boost/filesystem/path.hpp"
#include <chrono>
#include <md5calc.hpp>
#include <memory>
#include <scanlog.hpp>
#include <string_view>
#include <thread>
#include <virusdatabase.hpp>

namespace viruscan {
class Scanner {
private:
  moodycamel::BlockingConcurrentQueue<boost::filesystem::path> queue;

  std::atomic<bool> producer_done{false};
  std::atomic<size_t> files_processed{0};
  std::atomic<size_t> errors_encountered{0};
  std::atomic<size_t> viruses_found{0};
  std::chrono::steady_clock::time_point scan_start_time;
  std::chrono::milliseconds scan_duration;

  std::vector<std::unique_ptr<IScanEventHandler>> event_handlers;
  std::unique_ptr<md5calc> md5_calculator;
  std::unique_ptr<VirusDatabase> virus_db;
  boost::filesystem::path path_to_csv;

  std::vector<std::jthread> consumers;
  std::jthread producer;

  void recursive_scan(const std::string &path, moodycamel::ProducerToken &ptok,
                      std::stop_token stoken);

public:
  Scanner(boost::filesystem::path path_to_csv);
  Scanner(const Scanner &) = delete;
  Scanner(Scanner &&) = delete;
  Scanner &operator=(const Scanner &) = delete;
  Scanner &operator=(Scanner &&) = delete;

  void scan(std::string_view root_path);
  void stop_scan();
  void stop_scan_immediate();
  void process_file(const boost::filesystem::path &file_path);

  void consumer_worker(moodycamel::ConsumerToken &ctok, int worker_id,
                       std::stop_token stoken);

  void add_event_handler(std::unique_ptr<IScanEventHandler> handler);
  void notify_file_scanned(const boost::filesystem::path &path,
                           const std::string &md5, uintmax_t size);
  void notify_virus_found(const boost::filesystem::path &path,
                          const std::string &md5, const std::string &threat);
  void notify_error(const boost::filesystem::path &path,
                    const std::string &error);
  void notify_scan_completed();

  size_t get_files_processed() const;
  size_t get_viruses_found() const;
  size_t get_errors_encountered() const;
  std::chrono::milliseconds get_scan_duration() const;
};
} // namespace viruscan
