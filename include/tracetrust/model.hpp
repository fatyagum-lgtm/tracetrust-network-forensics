#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace tracetrust {
inline constexpr const char *version = "1.0.0";
using Bytes = std::vector<std::uint8_t>;
using Time = std::uint64_t;
inline constexpr Time second = 1'000'000'000ULL;

class Error : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

struct Config {
    std::uint32_t window_seconds{10};
    std::uint32_t scan_ports{12};
    std::uint32_t syn_count{5};
    std::uint32_t burst_window_seconds{1};
    std::uint32_t burst_packets{80};
    std::uint32_t burst_bytes{65'536};
    std::uint32_t dns_count{20};
    std::uint32_t flow_timeout_seconds{60};
    std::uint32_t max_packets{100'000};
    std::uint32_t max_file_mib{128};
    void validate() const;
};

struct Frame {
    std::uint32_t number{};
    std::uint64_t record_offset{};
    std::size_t data_offset{};
    Time timestamp{};
    std::uint32_t captured_length{};
    std::uint32_t original_length{};
};

struct CaptureIndex {
    bool little_endian{};
    bool nanoseconds{};
    bool complete{true};
    std::uint32_t snaplen{};
    std::vector<Frame> frames;
    std::vector<std::string> warnings;
};

struct DnsQuestion {
    std::string name;
    std::uint16_t type{};
    std::uint16_t qclass{};
};

struct Packet {
    Frame frame;
    std::string network{"Ethernet"};
    std::string protocol{"Other"};
    std::string source;
    std::string destination;
    std::optional<std::uint16_t> source_port;
    std::optional<std::uint16_t> destination_port;
    std::uint16_t tcp_flags{};
    std::uint32_t tcp_sequence{};
    std::uint32_t tcp_acknowledgment{};
    std::optional<std::uint8_t> icmp_type;
    std::optional<std::uint8_t> hop_limit;
    bool transport_valid{};
    bool partial{};
    bool malformed{};
    std::vector<std::uint16_t> vlans;
    bool dns_valid{};
    bool dns_response{};
    bool dns_truncated_flag{};
    std::uint16_t dns_id{};
    std::uint8_t dns_rcode{};
    std::vector<DnsQuestion> questions;
    std::vector<std::string> warnings;
    std::string flow_id;
};

struct Flow {
    std::string id;
    std::string protocol;
    std::string endpoint_a;
    std::string endpoint_b;
    std::optional<std::uint16_t> port_a;
    std::optional<std::uint16_t> port_b;
    std::vector<std::uint16_t> vlans;
    Time first{};
    Time last{};
    std::uint64_t packets_ab{};
    std::uint64_t packets_ba{};
    std::uint64_t bytes_ab{};
    std::uint64_t bytes_ba{};
    std::uint64_t syn{};
    std::uint64_t syn_ack{};
    std::uint64_t ack{};
    std::uint64_t fin{};
    std::uint64_t rst{};
    std::vector<std::uint32_t> frames;
};

struct Finding {
    std::string id;
    std::string rule;
    std::string title;
    std::string priority;
    std::string source;
    std::string destination;
    Time first{};
    Time last{};
    std::uint32_t window_seconds{};
    std::map<std::string, std::uint64_t> observed;
    std::map<std::string, std::uint64_t> thresholds;
    std::vector<std::uint32_t> frames;
    std::vector<std::string> flows;
    std::uint64_t evidence_total{};
    std::string explanation;
    std::string recommendation;
    std::string limitation;
};

struct Input {
    std::string filename;
    std::string sha256;
    Bytes bytes;
};

struct Analysis {
    std::string filename;
    std::string sha256;
    std::uint64_t file_bytes{};
    CaptureIndex capture;
    Config config;
    std::vector<Packet> packets;
    std::vector<Flow> flows;
    std::vector<Finding> findings;
    std::optional<Time> first;
    std::optional<Time> last;
};
} // namespace tracetrust
