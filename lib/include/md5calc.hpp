#include "viruscanlib_export.hpp"
#include <boost/filesystem.hpp>
#include <string>

namespace viruscan {
class VIRUSCANLIB_API md5calc {
public:
  std::string calc(const boost::filesystem::path &filepath);

private:
  static constexpr size_t BUFFER_SIZE = 8 * 1024; // 8KB
};
} // namespace viruscan
