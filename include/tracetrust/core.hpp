#pragma once
#include "tracetrust/model.hpp"
#include <filesystem>
#include <nlohmann/json.hpp>
#include <span>
#include <string_view>

namespace tracetrust {
using Json = nlohmann::json;
Input read_input(const std::filesystem::path &path, const Config &config);
std::string sha256(std::span<const std::uint8_t> bytes);
CaptureIndex parse_capture(std::span<const std::uint8_t> bytes, std::uint32_t max_packets);
Packet decode_packet(const Frame &frame, std::span<const std::uint8_t> bytes);
Analysis analyze(const Input &input, const Config &config);
std::vector<Flow> aggregate_flows(std::vector<Packet> &packets, const Config &config);
std::vector<Finding> detect(const std::vector<Packet> &packets, const Config &config);
std::string utc(Time timestamp);
std::string now_utc();
std::string printable(std::string_view text);
Json config_json(const Config &config);
Config parse_config(const Json &json);
Json make_report(const Analysis &analysis, std::string_view generated_utc);
std::string dashboard(const Json &report);
void write_reports(const std::filesystem::path &directory, const Json &report, bool json_only);
std::vector<std::string> flag_names(std::uint16_t flags);
} // namespace tracetrust
