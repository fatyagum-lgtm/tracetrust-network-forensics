#include "assets.hpp"
#include "tracetrust/core.hpp"
#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace tracetrust {
namespace {
template <typename T> Json optional(const std::optional<T> &value) {
    return value ? Json(*value) : Json(nullptr);
}
double milliseconds(Time value) {
    return static_cast<double>(value) / 1'000'000.0;
}
Json packet_json(const Packet &packet, Time origin) {
    const auto &f = packet.frame;
    Json dns = nullptr;
    if (packet.dns_valid) {
        Json questions = Json::array();
        for (const auto &q : packet.questions)
            questions.push_back({{"name", q.name}, {"type", q.type}, {"class", q.qclass}});
        dns = {{"id", packet.dns_id},
               {"response", packet.dns_response},
               {"truncated_flag", packet.dns_truncated_flag},
               {"rcode", packet.dns_rcode},
               {"questions", questions},
               {"scope", "header_and_questions_only"}};
    }
    return {{"frame", f.number},
            {"record_offset", f.record_offset},
            {"timestamp_ns", std::to_string(f.timestamp)},
            {"timestamp_utc", utc(f.timestamp)},
            {"relative_ms", milliseconds(f.timestamp - origin)},
            {"captured_bytes", f.captured_length},
            {"original_bytes", f.original_length},
            {"network", packet.network},
            {"protocol", packet.protocol},
            {"source", packet.source},
            {"destination", packet.destination},
            {"source_port", optional(packet.source_port)},
            {"destination_port", optional(packet.destination_port)},
            {"vlans", packet.vlans},
            {"hop_limit", optional(packet.hop_limit)},
            {"tcp_flags", flag_names(packet.tcp_flags)},
            {"tcp_sequence", packet.protocol == "TCP" ? Json(packet.tcp_sequence) : Json(nullptr)},
            {"tcp_acknowledgment",
             packet.protocol == "TCP" ? Json(packet.tcp_acknowledgment) : Json(nullptr)},
            {"icmp_type", optional(packet.icmp_type)},
            {"dns", dns},
            {"flow_id", packet.flow_id.empty() ? Json(nullptr) : Json(packet.flow_id)},
            {"status", packet.malformed ? "malformed"
                       : packet.partial ? "partial"
                                        : "observed"},
            {"warnings", packet.warnings}};
}
Json flow_json(const Flow &f, Time origin) {
    return {{"id", f.id},
            {"protocol", f.protocol},
            {"endpoint_a", f.endpoint_a},
            {"endpoint_b", f.endpoint_b},
            {"port_a", optional(f.port_a)},
            {"port_b", optional(f.port_b)},
            {"vlans", f.vlans},
            {"first_utc", utc(f.first)},
            {"last_utc", utc(f.last)},
            {"first_relative_ms", milliseconds(f.first - origin)},
            {"last_relative_ms", milliseconds(f.last - origin)},
            {"duration_ms", milliseconds(f.last - f.first)},
            {"packets", f.packets_ab + f.packets_ba},
            {"captured_bytes", f.bytes_ab + f.bytes_ba},
            {"packets_a_to_b", f.packets_ab},
            {"packets_b_to_a", f.packets_ba},
            {"bytes_a_to_b", f.bytes_ab},
            {"bytes_b_to_a", f.bytes_ba},
            {"tcp_observations",
             {{"syn_without_ack", f.syn},
              {"syn_ack", f.syn_ack},
              {"ack", f.ack},
              {"fin", f.fin},
              {"rst", f.rst}}},
            {"direction_note",
             "A is the first observed sender; no client/server or connection-success inference."},
            {"frames", f.frames}};
}
Json finding_json(const Finding &f) {
    const auto width = static_cast<Time>(f.window_seconds) * second;
    return {{"id", f.id},
            {"rule", f.rule},
            {"title", f.title},
            {"priority", f.priority},
            {"source", f.source},
            {"destination", f.destination.empty() ? Json(nullptr) : Json(f.destination)},
            {"first_utc", utc(f.first)},
            {"last_utc", utc(f.last)},
            {"window_seconds", f.window_seconds},
            {"window_start_utc", utc(f.last >= width ? f.last - width : 0)},
            {"window_end_utc", utc(f.last)},
            {"observed", f.observed},
            {"thresholds", f.thresholds},
            {"frames", f.frames},
            {"flows", f.flows},
            {"evidence_total", f.evidence_total},
            {"evidence_sampled", f.evidence_total > f.frames.size()},
            {"explanation", f.explanation},
            {"recommendation", f.recommendation},
            {"limitation", f.limitation}};
}

struct Host {
    std::uint64_t sent{}, received{}, bytes_sent{}, bytes_received{};
    std::set<std::uint16_t> destination_ports;
};

Json traffic(const Analysis &a, Json &protocols, Json &hosts) {
    std::map<std::string, std::pair<std::uint64_t, std::uint64_t>> counts;
    std::map<std::string, Host> endpoints;
    const Time origin = a.first.value_or(0);
    const Time span = a.last.value_or(origin) - origin;
    // At most 120 uniform buckets. Integer arithmetic is exact before serialization.
    const Time bucket_seconds = std::max<Time>(1, (span / second + 120) / 120);
    const Time width = bucket_seconds * second;
    const auto bucket_count = a.packets.empty() ? 0 : static_cast<std::size_t>(span / width + 1);
    std::vector<std::uint64_t> packets(bucket_count), bytes(bucket_count);
    for (const auto &p : a.packets) {
        ++counts[p.protocol].first;
        counts[p.protocol].second += p.frame.captured_length;
        const auto bucket = static_cast<std::size_t>((p.frame.timestamp - origin) / width);
        ++packets[bucket];
        bytes[bucket] += p.frame.captured_length;
        if (!p.source.empty()) {
            auto &host = endpoints[p.source];
            ++host.sent;
            host.bytes_sent += p.frame.captured_length;
            if (p.destination_port)
                host.destination_ports.insert(*p.destination_port);
        }
        if (!p.destination.empty()) {
            auto &host = endpoints[p.destination];
            ++host.received;
            host.bytes_received += p.frame.captured_length;
        }
    }
    protocols = Json::array();
    for (const auto &[name, count] : counts)
        protocols.push_back(
            {{"protocol", name}, {"packets", count.first}, {"captured_bytes", count.second}});
    hosts = Json::array();
    for (const auto &[name, host] : endpoints)
        hosts.push_back({{"address", name},
                         {"packets_sent", host.sent},
                         {"packets_received", host.received},
                         {"bytes_sent", host.bytes_sent},
                         {"bytes_received", host.bytes_received},
                         {"destination_ports", host.destination_ports}});
    std::sort(hosts.begin(), hosts.end(), [](const auto &left, const auto &right) {
        const auto lb = left.at("bytes_sent").template get<std::uint64_t>() +
                        left.at("bytes_received").template get<std::uint64_t>();
        const auto rb = right.at("bytes_sent").template get<std::uint64_t>() +
                        right.at("bytes_received").template get<std::uint64_t>();
        return lb != rb ? lb > rb : left.at("address") < right.at("address");
    });
    Json bins = Json::array();
    for (std::size_t i = 0; i < bucket_count; ++i) {
        const Time start = origin + i * width;
        bins.push_back({{"start_utc", utc(start)},
                        {"start_relative_ms", milliseconds(i * width)},
                        {"end_relative_ms", milliseconds((i + 1) * width)},
                        {"packets", packets[i]},
                        {"captured_bytes", bytes[i]}});
    }
    return {{"bucket_seconds", bucket_seconds}, {"interval", "[start, end)"}, {"buckets", bins}};
}

void replace(std::string &text, std::string_view from, std::string_view to) {
    const auto at = text.find(from);
    if (at == std::string::npos)
        throw Error("Embedded dashboard template is invalid.");
    text.replace(at, from.size(), to);
}
void exclusive_file(int directory, const char *name, std::string_view text) {
    const int fd =
        ::openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        throw Error("Cannot create report file exclusively; no existing file was overwritten.");
    std::size_t position = 0;
    bool failed = false;
    while (position < text.size()) {
        const auto written = ::write(fd, text.data() + position, text.size() - position);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0) {
            failed = true;
            break;
        }
        position += static_cast<std::size_t>(written);
    }
    if (::fsync(fd) != 0)
        failed = true;
    if (::close(fd) != 0)
        failed = true;
    if (failed)
        throw Error(
            "Report write failed; the new output directory may contain an incomplete file.");
}
} // namespace

Json make_report(const Analysis &a, std::string_view generated_utc) {
    const Time origin = a.first.value_or(0);
    Json packets = Json::array(), flows = Json::array(), findings = Json::array();
    std::uint64_t bytes = 0, partial = 0, malformed = 0, warnings = 0, dns = 0;
    for (const auto &packet : a.packets) {
        packets.push_back(packet_json(packet, origin));
        bytes += packet.frame.captured_length;
        partial += packet.partial;
        malformed += packet.malformed;
        warnings += !packet.warnings.empty();
        dns += packet.dns_valid;
    }
    for (const auto &flow : a.flows)
        flows.push_back(flow_json(flow, origin));
    for (const auto &finding : a.findings)
        findings.push_back(finding_json(finding));
    Json protocols, hosts;
    auto timeline = traffic(a, protocols, hosts);
    return {{"schema_version", 1},
            {"tool", {{"name", "TraceTrust"}, {"version", version}}},
            {"generated_utc", generated_utc},
            {"config", config_json(a.config)},
            {"capture",
             {{"filename", a.filename},
              {"sha256", a.sha256},
              {"file_bytes", a.file_bytes},
              {"format", "classic PCAP 2.4"},
              {"link_type", "Ethernet (1)"},
              {"byte_order", a.capture.little_endian ? "little" : "big"},
              {"timestamp_resolution", a.capture.nanoseconds ? "nanoseconds" : "microseconds"},
              {"snaplen", a.capture.snaplen},
              {"records_complete", a.capture.complete},
              {"warnings", a.capture.warnings}}},
            {"summary",
             {{"packets", a.packets.size()},
              {"captured_bytes", bytes},
              {"flows", a.flows.size()},
              {"hosts", hosts.size()},
              {"findings", a.findings.size()},
              {"partial_packets", partial},
              {"malformed_packets", malformed},
              {"packets_with_warnings", warnings},
              {"dns_packets", dns},
              {"first_utc", a.first ? Json(utc(*a.first)) : Json(nullptr)},
              {"last_utc", a.last ? Json(utc(*a.last)) : Json(nullptr)},
              {"duration_ms", milliseconds(a.last.value_or(origin) - origin)}}},
            {"protocols", protocols},
            {"hosts", hosts},
            {"timeline", timeline},
            {"flows", flows},
            {"findings", findings},
            {"packets", packets},
            {"limitations",
             Json::array(
                 {"Educational triage tool, not a certified forensic procedure or legal chain of "
                  "custody.",
                  "Timestamps are capture-clock observations interpreted as UTC; clock accuracy is "
                  "unknown.",
                  "No IP reassembly, TCP stream reassembly, checksum validation, decryption, or "
                  "application transfer-size inference.",
                  "Heuristic findings require context; priorities are triage policy, not "
                  "calibrated probabilities.",
                  "Hash covers the complete acquired file; a limited or damaged record stream may "
                  "yield only a prefix analysis.",
                  "Report contains addresses, ports and DNS questions; review before sharing."})}};
}

std::string dashboard(const Json &report) {
    // Escape script terminators and HTML delimiters even inside application/json.
    const auto json = report.dump(-1, ' ', true);
    std::string data;
    data.reserve(json.size());
    for (const char c : json) {
        if (c == '<')
            data += "\\u003c";
        else if (c == '>')
            data += "\\u003e";
        else if (c == '&')
            data += "\\u0026";
        else
            data += c;
    }
    std::string html(assets::html);
    replace(html, "__TT_CSS__", assets::css);
    replace(html, "__TT_JS__", assets::js);
    replace(html, "__TT_DATA__", data);
    return html;
}

void write_reports(const std::filesystem::path &directory, const Json &report, bool json_only) {
    if (::mkdir(directory.c_str(), 0700) != 0)
        throw Error("Output must be a new directory with an existing, writable parent. Existing "
                    "paths are never overwritten.");
    const int fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        throw Error("Cannot securely open the new output directory.");
    try {
        exclusive_file(fd, "report.json", report.dump(2, ' ', true) + "\n");
        if (!json_only)
            exclusive_file(fd, "index.html", dashboard(report));
        if (::fsync(fd) != 0)
            throw Error("Output directory could not be synchronized.");
    } catch (...) {
        ::close(fd);
        throw;
    }
    ::close(fd);
}
} // namespace tracetrust
