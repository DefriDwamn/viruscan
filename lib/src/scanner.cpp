#include "scanner.hpp"
#include <memory>
#include <optional>
namespace viruscan {

Scanner::Scanner(boost::filesystem::path path_to_csv)
    : path_to_csv(path_to_csv), md5_calculator(std::make_unique<md5calc>()),
      virus_db(std::make_unique<VirusDatabase>(path_to_csv)) {};

void Scanner::recursive_scan(const std::string &path,
                             moodycamel::ProducerToken &ptok,
                             std::stop_token stoken) {
  try {
    for (const auto &entry : boost::filesystem::recursive_directory_iterator(
             path,
             boost::filesystem::directory_options::skip_permission_denied)) {
      if (stoken.stop_requested() || producer_done)
        break;
      if (boost::filesystem::is_regular_file(entry)) {
        queue.enqueue(ptok, entry.path());
      }
    }
  } catch (const boost::filesystem::filesystem_error &ex) {
    notify_error(boost::filesystem::path(path), ex.what());
  }
};

void Scanner::scan(std::string_view root_path) {
  scan_start_time = std::chrono::steady_clock::now();

  moodycamel::ProducerToken ptok(queue);

  producer = std::jthread([this, root_path = std::string(root_path),
                           &ptok](std::stop_token stoken) {
    if (stoken.stop_requested())
      return;
    recursive_scan(root_path, ptok, stoken);
    producer_done = true;
  });

  const auto num_consumers =
      std::max(1u, std::thread::hardware_concurrency() - 2);
  consumers.reserve(num_consumers);

  for (auto i = 0; i < num_consumers; ++i) {
    consumers.emplace_back([this, i](std::stop_token stoken) {
      moodycamel::ConsumerToken ctok(queue);
      consumer_worker(ctok, i, stoken);
    });
  }

  producer.join();
  for (auto &consumer : consumers) {
    consumer.join();
  }

  auto scan_end_time = std::chrono::steady_clock::now();
  scan_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      scan_end_time - scan_start_time);
  notify_scan_completed();
};

void Scanner::consumer_worker(moodycamel::ConsumerToken &ctok, int worker_id,
                              std::stop_token stoken) {
  boost::filesystem::path file_path;

  while (!stoken.stop_requested()) {
    if (queue.try_dequeue(ctok, file_path)) {
      process_file(file_path);
      continue;
    }

    if (producer_done && queue.size_approx() == 0)
      break;

    if (queue.wait_dequeue_timed(ctok, file_path,
                                 std::chrono::milliseconds(100))) {
      if (stoken.stop_requested())
        break;
      process_file(file_path);
    }
  }
};

void Scanner::stop_scan() { producer_done = true; };

void Scanner::stop_scan_immediate() {
  producer_done = true;
  for (auto &consumer : consumers) {
    if (consumer.joinable()) {
      consumer.request_stop();
    }
  }
  if (producer.joinable()) {
    producer.request_stop();
  }
}

void Scanner::process_file(const boost::filesystem::path &file_path) {
  try {
    if (!boost::filesystem::exists(file_path))
      return;

    auto file_size = boost::filesystem::file_size(file_path);
    // cpu bound task
    auto md5_hash = md5_calculator->calc(file_path);
    // i/o bound task
    auto infected = virus_db->contains(md5_hash);

    files_processed++;
    if (infected.has_value()) {
      notify_virus_found(file_path, md5_hash, infected.value());
      viruses_found++;
    }
    notify_file_scanned(file_path, md5_hash, file_size);

  } catch (const std::exception &e) {
    errors_encountered++;
    notify_error(file_path, e.what());
  }
};

void Scanner::add_event_handler(std::unique_ptr<IScanEventHandler> handler) {
  event_handlers.push_back(std::move(handler));
};

void Scanner::notify_file_scanned(const boost::filesystem::path &path,
                                  const std::string &md5, uintmax_t size) {
  FileScannedEvent event{path, md5, size};
  for (const auto &handler : event_handlers) {
    handler->on_file_scanned(event);
  }
};

void Scanner::notify_virus_found(const boost::filesystem::path &path,
                                 const std::string &md5,
                                 const std::string &threat) {
  VirusFoundEvent event{path, md5, threat};
  for (const auto &handler : event_handlers) {
    handler->on_virus_found(event);
  }
};

void Scanner::notify_error(const boost::filesystem::path &path,
                           const std::string &error) {
  ScanErrorEvent event{path, error, std::source_location::current()};
  for (const auto &handler : event_handlers) {
    handler->on_scan_error(event);
  }
};

void Scanner::notify_scan_completed() {
  ScanProgressEvent event{files_processed, files_processed, 100.0};
  for (const auto &handler : event_handlers) {
    handler->on_progress_update(event);
  }
};

size_t Scanner::get_files_processed() const { return files_processed; }

size_t Scanner::get_viruses_found() const { return viruses_found; }

size_t Scanner::get_errors_encountered() const { return errors_encountered; }

std::chrono::milliseconds Scanner::get_scan_duration() const {
  return scan_duration;
}

} // namespace viruscan
