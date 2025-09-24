#include <boost/filesystem.hpp>
#include <string>

namespace viruscan {
class md5calc {
public:
  std::string calc(const boost::filesystem::path &filepath);
private:
  static constexpr size_t MAX_FILE_SIZE = 1 * 1024 * 1024;
};
} // namespace viruscan
