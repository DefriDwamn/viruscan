#include "Utils.hpp"
#include <boost/program_options.hpp>
#include <filesystem>
#include <iostream>
#include <memory>
#include <scanner.hpp>
#include <string>

namespace po = boost::program_options;
namespace fs = std::filesystem;

int main(int argc, char *argv[]) {
  try {
    std::string baseFile, logFile, scanPath;
    po::options_description desc("Virus Scanner CLI - Allowed options");
    po::variables_map vm;
    desc.add_options()("help,h", "Show help message")(
        "base,b", po::value<std::string>(&baseFile)->required(),
        "Path to base CSV file with virus signatures")(
        "log,l", po::value<std::string>(&logFile)->required(),
        "Path to output log file")(
        "path,p", po::value<std::string>(&scanPath)->required(),
        "Path to directory to scan")("verbose,v", "Verbose output");
    try {
      po::store(po::parse_command_line(argc, argv, desc), vm);
      if (vm.count("help")) {
        std::cout << desc << "\n";
        return 0;
      }
      po::notify(vm);
    } catch (const po::error &e) {
      std::cerr << Utils::colorize(Utils::Color::RED, "CLI error: ", e.what())
                << "\n";
      std::cout << desc << "\n";
      return 1;
    }
    if (!fs::exists(baseFile)) {
      throw std::runtime_error("Base file: " + baseFile);
    }
    if (!fs::exists(scanPath)) {
      throw std::runtime_error("Scan path: " + scanPath);
    }

    auto scanner = std::make_unique<viruscan::Scanner>(baseFile);

    auto fileHandler =
        std::make_unique<viruscan::FileScanEventHandler>(logFile);
    scanner->add_event_handler(std::move(fileHandler));

    // auto consoleHandler = std::make_unique<ConsoleEventHandler>();
    // if (vm.count("verbose")) {
    //   scanner->add_event_handler(std::move(consoleHandler));
    // }
   
    std::cout << Utils::colorize(Utils::Color::GREEN, "Starting scan...")
              << "\n";
    scanner->scan(scanPath);
    std::cout << Utils::colorize(Utils::Color::GREEN, "Scan completed!") << "\n"
              << "Files processed: " << scanner->get_files_processed() << "\n"
              << Utils::colorize(Utils::Color::RED,
                                 std::format("Viruses found: {}",
                                             scanner->get_viruses_found()))
              << "\n"
              << "Errors encountered: " << scanner->get_errors_encountered()
              << "\n"
              << "Scan duration: " << scanner->get_scan_duration() << "\n"
              << "Logs saved to: " << fs::absolute(logFile) << "\n";
  } catch (const std::exception &e) {
    std::cerr << Utils::colorize(Utils::Color::RED, "Fatal error: ", e.what())
              << "\n";
    return 1;
  }
}
