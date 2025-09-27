#include "md5calc.hpp"
#include "boost/hash2/md5.hpp"
#include <array>
#include <fstream>
#include <ios>
#include <stdexcept>
#include <string>

namespace viruscan {

std::string md5calc::calc(const boost::filesystem::path &filepath) {
  std::ifstream f(filepath.string(), std::ios::binary);
  if (!f) {
    throw std::runtime_error(filepath.string());
  }
  boost::hash2::md5_128 hasher;
  std::array<char, BUFFER_SIZE> buff;
  while (f.read(buff.data(), buff.size())) {
    hasher.update(buff.data(), f.gcount());
  }
  if (f.gcount() > 0) {
    hasher.update(buff.data(), f.gcount());
  }
  return to_string(hasher.result());
};

} // namespace viruscan
