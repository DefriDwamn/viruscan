#include "virusdatabase.hpp"
#include <algorithm>
#include <boost/filesystem.hpp>
#include <cctype>
#include <format>
#include <fstream>
#include <iostream>
#include <optional>
#include <string_view>

#ifdef _WIN32
  #include <windows.h>
#endif

namespace viruscan {

VirusDatabase::VirusDatabase(const boost::filesystem::path &csv_path)
    : csv_path(csv_path) {
  init_csv();
}

std::optional<std::string>
VirusDatabase::search_in_file(std::string_view md5_hash) const {
#ifdef _WIN32
    HANDLE hFile = CreateFileA(
        csv_path.string().c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    if (hFile == INVALID_HANDLE_VALUE) return std::nullopt;

    const DWORD bufSize = 8192;
    char buf[bufSize];
    DWORD bytesRead = 0;
    std::string leftover;
    std::optional<std::string> result;

    while (ReadFile(hFile, buf, bufSize, &bytesRead, nullptr) && bytesRead > 0) {
        std::string data = leftover + std::string(buf, bytesRead);
        leftover.clear();
        size_t pos = 0, nl;
        while ((nl = data.find('\n', pos)) != std::string::npos) {
            std::string line = data.substr(pos, nl - pos);
            pos = nl + 1;
            if (line.size() >= 33) {
                bool match = true;
                for (size_t i = 0; i < 32; ++i) {
                    if (std::tolower(static_cast<unsigned char>(line[i])) !=
                        std::tolower(static_cast<unsigned char>(md5_hash[i]))) {
                        match = false;
                        break;
                    }
                }
                if (match && line[32] == ';') {
                    std::string t = line.substr(33);
                    size_t b = t.find_first_not_of(" \t\r");
                    size_t e = t.find_last_not_of(" \t\r");
                    if (b != std::string::npos) {
                        result = t.substr(b, e - b + 1);
                        CloseHandle(hFile);
                        return result;
                    }
                }
            }
        }
        if (pos < data.size()) leftover = data.substr(pos);
    }
    if (!leftover.empty() && leftover.size() >= 33) {
        bool match = true;
        for (size_t i = 0; i < 32; ++i) {
            if (std::tolower(static_cast<unsigned char>(leftover[i])) !=
                std::tolower(static_cast<unsigned char>(md5_hash[i]))) {
                match = false;
                break;
            }
        }
        if (match && leftover[32] == ';') {
            std::string t = leftover.substr(33);
            size_t b = t.find_first_not_of(" \t\r");
            size_t e = t.find_last_not_of(" \t\r");
            if (b != std::string::npos) {
                result = t.substr(b, e - b + 1);
            }
        }
    }
    CloseHandle(hFile);
    return result;
#else
    std::ifstream file(csv_path.string(), std::ios::binary);
    if (!file) return std::nullopt;

    std::string line;
    while (std::getline(file, line)) {
        if (line.size() < 33) continue;
        bool match = true;
        for (size_t i = 0; i < 32; ++i) {
            if (std::tolower(static_cast<unsigned char>(line[i])) !=
                std::tolower(static_cast<unsigned char>(md5_hash[i]))) {
                match = false;
                break;
            }
        }
        if (match && line[32] == ';') {
            std::string t = line.substr(33);
            size_t b = t.find_first_not_of(" \t\r");
            size_t e = t.find_last_not_of(" \t\r");
            if (b != std::string::npos) return t.substr(b, e - b + 1);
        }
    }
    return std::nullopt;
#endif
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
      std::transform(md5.begin(), md5.end(), md5.begin(),
                     [](unsigned char c) { return std::tolower(c); });
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
