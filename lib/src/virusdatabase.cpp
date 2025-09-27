#include "virusdatabase.hpp"
#include <boost/filesystem.hpp>
#include <format>
#include <fstream>
#include <iostream>
#include <optional>
#include <string_view>

namespace viruscan {
VirusDatabase::VirusDatabase(const boost::filesystem::path &csv_path)
    : csv_path(csv_path) {
  init_csv();
}

std::optional<std::string>
VirusDatabase::search_in_file(std::string_view md5_hash) const {
  std::ifstream file(csv_path.string(), std::ios::binary);
  if (!file) {
    return std::nullopt;
  }
  std::string line;
  while (std::getline(file, line)) {
    if (line.length() < 33)
      continue;

    if (line.compare(0, 32, md5_hash) == 0 && line[32] == ';') {
      std::string threat_type = line.substr(33);

      size_t start = threat_type.find_first_not_of(" \t");
      size_t end = threat_type.find_last_not_of(" \t");

      if (start != std::string::npos) {
        threat_type = threat_type.substr(start, (end != std::string::npos)
                                                    ? end - start + 1
                                                    : std::string::npos);

        return threat_type;
      }
    }
  }

  return std::nullopt;
}

std::optional<std::string>
VirusDatabase::contains(std::string_view md5_hash) const {
  std::string key(md5_hash);
  if (auto it = cache.find(key); it != cache.end()) {
    return it->second;
  } else if (cache.size() < MAX_CACHE_SIZE) {
    return std::nullopt;
  }
  return search_in_file(md5_hash);
}

void VirusDatabase::init_csv() {
  namespace fs = boost::filesystem;

  if (!fs::exists(csv_path)) {
    throw std::runtime_error(
        std::format("VirusDB not found: {}", csv_path.string()));
  }

  if (!fs::is_regular_file(csv_path)) {
    throw std::runtime_error(
        std::format("VirusDB not a file: {}", csv_path.string()));
  }

  std::ifstream file(csv_path.string(), std::ios::binary);
  if (!file) {
    throw std::runtime_error("Cannot open virus database file");
  }

  std::string line;
  size_t records_loaded = 0;

  while (std::getline(file, line) && records_loaded < MAX_CACHE_SIZE) {
    if (line.length() < 33)
      continue;
    if (line[32] == ';') {
      std::string md5 = line.substr(0, 32);
      std::string threat_type = line.substr(33);

      size_t start = threat_type.find_first_not_of(" \t");
      size_t end = threat_type.find_last_not_of(" \t");
      if (start != std::string::npos) {
        threat_type = threat_type.substr(start, (end != std::string::npos)
                                                    ? end - start + 1
                                                    : std::string::npos);

        cache.emplace(std::move(md5), std::move(threat_type));
        records_loaded++;
      }
    }
  }
}
} // namespace viruscan
