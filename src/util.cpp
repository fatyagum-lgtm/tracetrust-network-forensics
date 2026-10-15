#include "tracetrust/core.hpp"
#include <array>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <memory>
#include <openssl/evp.h>
#include <sstream>

namespace tracetrust {
std::string sha256(std::span<const std::uint8_t> bytes) {
    using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Context context(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int size = 0;
    if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(context.get(), bytes.data(), bytes.size()) != 1 ||
        EVP_DigestFinal_ex(context.get(), digest.data(), &size) != 1) {
        throw Error("OpenSSL SHA-256 failed.");
    }
    std::ostringstream output;
    for (unsigned int i = 0; i < size; ++i)
        output << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(digest[i]);
    return output.str();
}

std::string utc(Time timestamp) {
    const auto seconds = static_cast<std::time_t>(timestamp / second);
    std::tm value{};
    if (gmtime_r(&seconds, &value) == nullptr)
        throw Error("Timestamp cannot be represented in UTC on this platform.");
    std::ostringstream output;
    output << std::put_time(&value, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(9)
           << timestamp % second << 'Z';
    return output.str();
}

std::string now_utc() {
    const auto elapsed = std::chrono::system_clock::now().time_since_epoch();
    return utc(
        static_cast<Time>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count()));
}

std::string printable(std::string_view text) {
    std::ostringstream output;
    for (const unsigned char value : text) {
        if (value >= 32 && value <= 126 && value != '\\')
            output << value;
        else
            output << "\\x" << std::hex << std::setfill('0') << std::setw(2)
                   << static_cast<unsigned>(value);
    }
    return output.str();
}

void Config::validate() const {
    if (window_seconds < 1 || window_seconds > 86'400 || burst_window_seconds < 1 ||
        burst_window_seconds > 86'400 || flow_timeout_seconds < 1 || flow_timeout_seconds > 86'400)
        throw Error("Window and idle-timeout values must be between 1 and 86400 seconds.");
    if (scan_ports < 2 || scan_ports > 65'536 || syn_count < 2 || dns_count < 2 ||
        burst_packets < 2 || burst_bytes < 1)
        throw Error("Rule counts must be >= 2; scan_ports <= 65536; burst_bytes >= 1.");
    if (max_packets < 1 || max_packets > 200'000 || max_file_mib < 1 || max_file_mib > 512)
        throw Error("max_packets must be 1..200000 and max_file_mib must be 1..512.");
}

Json config_json(const Config &c) {
    return {{"window_seconds", c.window_seconds}, {"scan_ports", c.scan_ports},
            {"syn_count", c.syn_count},           {"burst_window_seconds", c.burst_window_seconds},
            {"burst_packets", c.burst_packets},   {"burst_bytes", c.burst_bytes},
            {"dns_count", c.dns_count},           {"flow_timeout_seconds", c.flow_timeout_seconds},
            {"max_packets", c.max_packets},       {"max_file_mib", c.max_file_mib}};
}

Config parse_config(const Json &json) {
    if (!json.is_object())
        throw Error("Configuration must be a JSON object.");
    Config c;
    std::map<std::string, std::uint32_t *> fields{
        {"window_seconds", &c.window_seconds}, {"scan_ports", &c.scan_ports},
        {"syn_count", &c.syn_count},           {"burst_window_seconds", &c.burst_window_seconds},
        {"burst_packets", &c.burst_packets},   {"burst_bytes", &c.burst_bytes},
        {"dns_count", &c.dns_count},           {"flow_timeout_seconds", &c.flow_timeout_seconds},
        {"max_packets", &c.max_packets},       {"max_file_mib", &c.max_file_mib}};
    for (const auto &[name, value] : json.items()) {
        if (!fields.contains(name) || !value.is_number_integer() ||
            (!value.is_number_unsigned() && value.get<std::int64_t>() < 0) ||
            value.get<std::uint64_t>() > 0xFFFFFFFFULL)
            throw Error("Unknown configuration key or invalid unsigned integer: " +
                        printable(name));
        *fields.at(name) = value.get<std::uint32_t>();
    }
    c.validate();
    return c;
}

std::vector<std::string> flag_names(std::uint16_t flags) {
    std::vector<std::string> result;
    const std::array<std::string, 9> names{"FIN", "SYN", "RST", "PSH", "ACK",
                                           "URG", "ECE", "CWR", "NS"};
    for (std::size_t i = 0; i < names.size(); ++i)
        if ((flags & (1U << i)) != 0)
            result.push_back(names[i]);
    return result;
}
} // namespace tracetrust
