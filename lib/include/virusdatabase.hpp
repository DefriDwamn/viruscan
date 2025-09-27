#include "boost/filesystem/path.hpp"
#include <optional>
#include <string>
#include "viruscanlib_export.hpp"
#include <unordered_map>

namespace viruscan {
class VIRUSCANLIB_API VirusDatabase {
private:
  boost::filesystem::path csv_path;
  static constexpr size_t MAX_CACHE_SIZE = 100'000;

  void init_csv();
  std::optional<std::string> search_in_file(std::string_view md5_hash) const;
  std::unordered_map<std::string, std::string> cache;

public:
  VirusDatabase(const boost::filesystem::path &csv_path);
  ~VirusDatabase() = default;
  VirusDatabase(const VirusDatabase &) = delete;
  VirusDatabase &operator=(const VirusDatabase &) = delete;
  VirusDatabase(VirusDatabase &&) = default;
  VirusDatabase &operator=(VirusDatabase &&) = default;

  std::optional<std::string> contains(std::string_view md5_hash) const;
};
} // namespace viruscan
