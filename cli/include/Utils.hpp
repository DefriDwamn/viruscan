#pragma once
#include <sstream>
#include <string>
#include <vector>

class Utils {
public:
  enum class Color { RED, GREEN, BLUE, YELLOW, CYAN, MAGENTA, WHITE, DEFAULT };

  template <typename... Args>
  static std::string colorize(Color color, const Args &...args);

  inline static std::vector<std::string> split(const std::string &str,
                                               char delimiter);

private:
  template <typename T>
  static void appendToStream(std::ostringstream &oss, const T &value);

  template <typename T, typename... Args>
  static void appendToStream(std::ostringstream &oss, const T &value,
                             const Args &...args);
};

template <typename... Args>
std::string Utils::colorize(Color color, const Args &...args) {
  std::ostringstream oss;
  appendToStream(oss, args...);

  std::string colorCode;
  switch (color) {
  case Color::RED:
    colorCode = "\033[31m";
    break;
  case Color::GREEN:
    colorCode = "\033[32m";
    break;
  case Color::BLUE:
    colorCode = "\033[34m";
    break;
  case Color::YELLOW:
    colorCode = "\033[33m";
    break;
  case Color::CYAN:
    colorCode = "\033[36m";
    break;
  case Color::MAGENTA:
    colorCode = "\033[35m";
    break;
  case Color::WHITE:
    colorCode = "\033[37m";
    break;
  case Color::DEFAULT:
    colorCode = "\033[0m";
    break;
  }
  return colorCode + oss.str() + "\033[0m";
}

template <typename T>
void Utils::appendToStream(std::ostringstream &oss, const T &value) {
  oss << value;
}

template <typename T, typename... Args>
void Utils::appendToStream(std::ostringstream &oss, const T &value,
                           const Args &...args) {
  oss << value;
  appendToStream(oss, args...);
}

std::vector<std::string> Utils::split(const std::string &str, char delimiter) {
  std::vector<std::string> result;
  std::string token;
  std::istringstream tokenStream(str);
  while (std::getline(tokenStream, token, delimiter)) {
    result.push_back(token);
  }
  return result;
}
