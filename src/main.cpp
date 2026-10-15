#include "tracetrust/core.hpp"
#include <array>
#include <charconv>
#include <fstream>
#include <iostream>

namespace {
constexpr const char *help = R"(TraceTrust 1.0.0 — offline network evidence triage

Usage:
  tracetrust analyze INPUT.pcap --output NEW_DIRECTORY [options]
  tracetrust --help | --version | --default-config

Options:
  --config FILE              JSON configuration; unknown keys are errors
  --json-only                Write report.json without the offline dashboard
  --window-seconds N         Sliding window for TT-A, TT-B and TT-D (default 10)
  --scan-ports N             Distinct destination ports for TT-A (12)
  --syn-count N              SYN-without-ACK packets per directed tuple (5)
  --burst-window-seconds N   Sliding window for TT-C (1)
  --burst-packets N          Packet threshold for TT-C (80)
  --burst-bytes N            Captured-byte threshold for TT-C (65536; OR packets)
  --dns-count N              DNS query packets per source for TT-D (20)
  --flow-timeout-seconds N   Conversation idle gap (60)
  --max-packets N            Analyzed record limit (100000; maximum 200000)
  --max-file-mib N           Input buffer limit (128; maximum 512)

CLI values override JSON regardless of argument order. All windows are inclusive.
Output parent must exist; NEW_DIRECTORY must not exist. No overwrite option.
Classic PCAP 2.4 / Ethernet only; no live capture, PCAPNG, or online services.
Inspect findings in index.html or report.json; findings do not prove an attack.

Exit codes: 0 analysis complete (findings allowed); 2 usage/I/O/format error;
            3 report written with partial/unsupported packet data or record prefix.
Example:
  tracetrust analyze examples/investigation.pcap --output reports/first
)";

std::uint32_t number(std::string_view value) {
    std::uint32_t result{};
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size())
        throw tracetrust::Error("Option requires an unsigned decimal integer.");
    return result;
}

int run(int argc, char **argv) {
    using namespace tracetrust;
    if (argc == 2) {
        const std::string option = argv[1];
        if (option == "--help" || option == "-h") {
            std::cout << help;
            return 0;
        }
        if (option == "--version") {
            std::cout << "TraceTrust " << version << '\n';
            return 0;
        }
        if (option == "--default-config") {
            std::cout << config_json(Config{}).dump(2) << '\n';
            return 0;
        }
    }
    if (argc < 3 || std::string_view(argv[1]) != "analyze")
        throw Error("Use 'tracetrust --help' for usage.");
    if (std::string_view(argv[2]) == "--help") {
        std::cout << help;
        return 0;
    }
    std::filesystem::path output, config_path;
    Json overrides = Json::object();
    bool json_only = false;
    for (int i = 3; i < argc; ++i) {
        std::string option = argv[i];
        if (option == "--json-only") {
            json_only = true;
            continue;
        }
        if (i + 1 >= argc)
            throw Error("Missing value for " + printable(option));
        const std::string value = argv[++i];
        if (option == "--output") {
            if (!output.empty())
                throw Error("--output must appear only once.");
            output = value;
        } else if (option == "--config") {
            if (!config_path.empty())
                throw Error("--config must appear only once.");
            config_path = value;
        } else {
            if (!option.starts_with("--"))
                throw Error("Unknown argument: " + printable(option));
            option.erase(0, 2);
            for (auto &c : option)
                if (c == '-')
                    c = '_';
            if (!config_json(Config{}).contains(option))
                throw Error("Unknown option: " + printable(option));
            if (overrides.contains(option))
                throw Error("Duplicate option: " + printable(option));
            overrides[option] = number(value);
        }
    }
    if (output.empty())
        throw Error("--output NEW_DIRECTORY is required.");
    Json settings = Json::object();
    if (!config_path.empty()) {
        std::error_code ec;
        const auto size = std::filesystem::file_size(config_path, ec);
        if (ec || size > 64 * 1024)
            throw Error("Configuration must be a readable JSON file of at most 64 KiB.");
        std::ifstream file(config_path);
        if (!file)
            throw Error("Cannot open configuration file.");
        std::array<char, 64 * 1024 + 1> buffer{};
        file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        if (file.bad() || file.gcount() > 64 * 1024)
            throw Error("Configuration read failed or exceeded 64 KiB.");
        settings = Json::parse(buffer.data(), buffer.data() + file.gcount());
        parse_config(settings); // Validate before overrides; never mask an invalid file.
    }
    settings.update(overrides);
    const auto config = parse_config(settings);
    const auto input = read_input(argv[2], config);
    const auto analysis = analyze(input, config);
    const auto report = make_report(analysis, now_utc());
    write_reports(output, report, json_only);
    const auto &summary = report.at("summary");
    const bool partial =
        !analysis.capture.complete || summary.at("partial_packets").get<std::size_t>() != 0;
    std::cout << "TraceTrust " << version << " | " << input.filename << '\n'
              << "SHA-256  " << input.sha256 << '\n'
              << "Packets  " << analysis.packets.size() << " | Conversations  "
              << analysis.flows.size() << " | Findings  " << analysis.findings.size() << '\n'
              << "Reports written: report.json" << (json_only ? "" : ", index.html") << '\n';
    if (partial)
        std::cerr << "Warning: partial or unsupported data. Review capture and packet warnings in "
                     "the report.\n";
    return partial ? 3 : 0;
}
} // namespace

int main(int argc, char **argv) {
    try {
        return run(argc, argv);
    } catch (const std::bad_alloc &) {
        std::cerr << "Error: memory exhausted; reduce capture size or --max-packets.\n";
    } catch (const tracetrust::Error &error) {
        std::cerr << "Error: " << error.what() << '\n';
    } catch (const nlohmann::json::exception &) {
        std::cerr << "Error: invalid JSON configuration or report data.\n";
    } catch (const std::exception &) {
        std::cerr
            << "Error: analysis could not be completed. Check input and output permissions.\n";
    }
    return 2;
}
