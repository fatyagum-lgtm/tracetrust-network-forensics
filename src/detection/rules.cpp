#include "tracetrust/core.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <tuple>

namespace tracetrust {
namespace {
using Group = std::vector<const Packet *>;
enum class Mode { ports, count, burst };
struct Window {
    std::size_t left{}, right{};
    std::uint64_t count{}, bytes{}, ports{};
    bool eligible{};
};

Window peak(const Group &group, std::uint32_t seconds, Mode mode, std::uint64_t threshold,
            std::uint64_t bytes_threshold = 0) {
    Window best;
    std::map<std::uint16_t, std::size_t> ports;
    std::uint64_t bytes = 0;
    std::size_t left = 0;
    for (std::size_t right = 0; right < group.size(); ++right) {
        bytes += group[right]->frame.captured_length;
        if (group[right]->destination_port)
            ++ports[*group[right]->destination_port];
        while (group[right]->frame.timestamp - group[left]->frame.timestamp >
               static_cast<Time>(seconds) * second) {
            bytes -= group[left]->frame.captured_length;
            if (group[left]->destination_port) {
                auto item = ports.find(*group[left]->destination_port);
                if (--item->second == 0)
                    ports.erase(item);
            }
            ++left;
        }
        Window current{left, right, right - left + 1, bytes, ports.size(), false};
        const auto score = mode == Mode::ports ? current.ports : current.count;
        const auto best_score = mode == Mode::ports ? best.ports : best.count;
        current.eligible = score >= threshold || (mode == Mode::burst && bytes >= bytes_threshold);
        if (current.eligible &&
            (!best.eligible || std::tie(score, current.count, current.bytes) >
                                   std::tie(best_score, best.count, best.bytes)))
            best = current;
    }
    return best;
}

Finding evidence(const Group &group, const Window &window, std::uint32_t seconds) {
    Finding finding;
    finding.source = group[window.right]->source;
    finding.destination = group[window.left]->destination;
    for (std::size_t i = window.left; i <= window.right; ++i) {
        if (group[i]->destination != finding.destination) {
            finding.destination.clear();
            break;
        }
    }
    finding.first = group[window.left]->frame.timestamp;
    finding.last = group[window.right]->frame.timestamp;
    finding.window_seconds = seconds;
    finding.evidence_total = window.count;
    finding.observed = {{"packets", window.count},
                        {"captured_bytes", window.bytes},
                        {"unique_destination_ports", window.ports}};
    std::set<std::string> flows;
    for (std::size_t i = window.left; i <= window.right && finding.frames.size() < 128; ++i) {
        finding.frames.push_back(group[i]->frame.number);
        if (!group[i]->flow_id.empty())
            flows.insert(group[i]->flow_id);
    }
    finding.flows.assign(flows.begin(), flows.end());
    return finding;
}

void scans(const std::map<std::tuple<std::string, std::string, std::string>, Group> &groups,
           const Config &c, std::vector<Finding> &result) {
    for (const auto &[key, group] : groups) {
        const auto window = peak(group, c.window_seconds, Mode::ports, c.scan_ports);
        if (!window.eligible)
            continue;
        auto finding = evidence(group, window, c.window_seconds);
        finding.rule = "TT-A";
        finding.title = "Potential port sweep (" + std::get<2>(key) + ")";
        finding.priority = "medium";
        finding.destination = std::get<1>(key);
        finding.thresholds = {{"unique_destination_ports_gte", c.scan_ports}};
        finding.explanation =
            "Distinct destination ports reached from one source to one destination, "
            "within one transport protocol. TCP counts SYN without ACK; UDP counts valid headers.";
        finding.recommendation = "Check authorized scanning, service discovery, host role, and "
                                 "responses in the supporting frames.";
        finding.limitation = "Legitimate discovery can trigger this rule. Distributed or slow "
                             "sweeps may be missed. Contact does not establish compromise.";
        result.push_back(std::move(finding));
    }
}

void syns(const std::map<std::tuple<std::string, std::string, std::uint16_t, std::uint16_t>, Group>
              &groups,
          const Config &c, std::vector<Finding> &result) {
    for (const auto &[key, group] : groups) {
        const auto window = peak(group, c.window_seconds, Mode::count, c.syn_count);
        if (!window.eligible)
            continue;
        auto finding = evidence(group, window, c.window_seconds);
        finding.rule = "TT-B";
        finding.title = "Repeated TCP SYN activity";
        finding.priority = "medium";
        finding.destination = std::get<1>(key);
        finding.observed["source_port"] = std::get<2>(key);
        finding.observed["destination_port"] = std::get<3>(key);
        finding.thresholds = {{"syn_without_ack_gte", c.syn_count}};
        finding.explanation = "SYN packets without ACK on the same directed address/port tuple "
                              "reached the threshold. Retransmissions are included.";
        finding.recommendation = "Inspect SYN sequence numbers and reverse traffic; check loss, "
                                 "service availability, and capture placement.";
        finding.limitation = "Repeated packets are not necessarily separate connection attempts. "
                             "Missing replies do not prove failure or malicious intent.";
        result.push_back(std::move(finding));
    }
}

void volumes(const std::map<std::string, Group> &groups, const Config &c,
             std::vector<Finding> &result, bool dns) {
    for (const auto &[source, group] : groups) {
        const auto seconds = dns ? c.window_seconds : c.burst_window_seconds;
        const auto window = peak(group, seconds, dns ? Mode::count : Mode::burst,
                                 dns ? c.dns_count : c.burst_packets, c.burst_bytes);
        if (!window.eligible)
            continue;
        auto finding = evidence(group, window, seconds);
        finding.rule = dns ? "TT-D" : "TT-C";
        finding.title = dns ? "High DNS query activity" : "Concentrated traffic burst";
        finding.priority = "low";
        if (dns) {
            finding.thresholds = {{"dns_query_packets_gte", c.dns_count}};
            finding.explanation = "UDP port-53 packets with a decoded DNS header, QR=0 and at "
                                  "least one valid question reached the per-source threshold.";
            finding.recommendation = "Review queried names, retransmissions, resolver behavior, "
                                     "and the expected workload of the source host.";
            finding.limitation = "Counts query packets, including duplicates, not unique names. "
                                 "DNS over TCP, encrypted DNS and other ports are not analyzed. "
                                 "High rate is not proof of tunneling.";
        } else {
            finding.thresholds = {{"packets_gte", c.burst_packets},
                                  {"captured_bytes_gte", c.burst_bytes}};
            finding.explanation = "Packets OR captured bytes sent by one decoded IP source reached "
                                  "a fixed threshold in a sliding window.";
            finding.recommendation = "Compare with the host's normal workload, backups, transfers, "
                                     "and capture duplication; inspect destinations and timing.";
            finding.limitation =
                "This is a fixed volume rule, not a learned baseline. Captured bytes include link "
                "headers and may omit truncated data. Benign bursts are expected.";
        }
        result.push_back(std::move(finding));
    }
}
} // namespace

std::vector<Finding> detect(const std::vector<Packet> &packets, const Config &config) {
    Group order;
    order.reserve(packets.size());
    for (const auto &packet : packets)
        order.push_back(&packet);
    std::stable_sort(order.begin(), order.end(), [](const auto *a, const auto *b) {
        return std::tie(a->frame.timestamp, a->frame.number) <
               std::tie(b->frame.timestamp, b->frame.number);
    });
    std::map<std::tuple<std::string, std::string, std::string>, Group> scan_groups;
    std::map<std::tuple<std::string, std::string, std::uint16_t, std::uint16_t>, Group> syn_groups;
    std::map<std::string, Group> burst_groups, dns_groups;
    for (const auto *packet : order) {
        if (!packet->source.empty())
            burst_groups[packet->source].push_back(packet);
        if (!packet->transport_valid || packet->malformed)
            continue;
        const bool syn = packet->protocol == "TCP" && (packet->tcp_flags & 0x12U) == 0x02U;
        if (syn || packet->protocol == "UDP")
            scan_groups[{packet->source, packet->destination, packet->protocol}].push_back(packet);
        if (syn)
            syn_groups[{packet->source, packet->destination, *packet->source_port,
                        *packet->destination_port}]
                .push_back(packet);
        if (packet->dns_valid && !packet->dns_response && !packet->questions.empty())
            dns_groups[packet->source].push_back(packet);
    }
    std::vector<Finding> result;
    scans(scan_groups, config, result);
    syns(syn_groups, config, result);
    volumes(burst_groups, config, result, false);
    volumes(dns_groups, config, result, true);
    for (std::size_t i = 0; i < result.size(); ++i) {
        std::ostringstream id;
        id << "A" << std::setw(5) << std::setfill('0') << i + 1;
        result[i].id = id.str();
    }
    return result;
}
} // namespace tracetrust
