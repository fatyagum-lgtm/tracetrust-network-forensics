#include "tracetrust/core.hpp"
#include <algorithm>
#include <iomanip>
#include <numeric>
#include <sstream>
#include <tuple>

namespace tracetrust {
namespace {
using Endpoint = std::pair<std::string, std::optional<std::uint16_t>>;
using FlowKey = std::tuple<std::string, std::vector<std::uint16_t>, Endpoint, Endpoint>;
std::string identifier(std::size_t number) {
    std::ostringstream out;
    out << 'F' << std::setw(6) << std::setfill('0') << number;
    return out.str();
}
} // namespace

std::vector<Flow> aggregate_flows(std::vector<Packet> &packets, const Config &config) {
    std::vector<std::size_t> order(packets.size());
    std::iota(order.begin(), order.end(), 0);
    std::stable_sort(order.begin(), order.end(), [&](auto a, auto b) {
        return std::tie(packets[a].frame.timestamp, packets[a].frame.number) <
               std::tie(packets[b].frame.timestamp, packets[b].frame.number);
    });
    std::map<FlowKey, std::size_t> active;
    std::vector<Flow> flows;
    for (const auto index : order) {
        auto &packet = packets[index];
        packet.flow_id.clear();
        if (!packet.transport_valid)
            continue;
        const Endpoint source{packet.source, packet.source_port};
        const Endpoint destination{packet.destination, packet.destination_port};
        const FlowKey key{packet.protocol, packet.vlans, std::min(source, destination),
                          std::max(source, destination)};
        auto found = active.find(key);
        if (found == active.end() || packet.frame.timestamp - flows[found->second].last >
                                         static_cast<Time>(config.flow_timeout_seconds) * second) {
            Flow flow;
            flow.id = identifier(flows.size() + 1);
            flow.protocol = packet.protocol;
            flow.endpoint_a = packet.source;
            flow.endpoint_b = packet.destination;
            flow.port_a = packet.source_port;
            flow.port_b = packet.destination_port;
            flow.vlans = packet.vlans;
            flow.first = packet.frame.timestamp;
            flows.push_back(std::move(flow));
            active[key] = flows.size() - 1;
            found = active.find(key);
        }
        auto &flow = flows[found->second];
        packet.flow_id = flow.id;
        flow.last = packet.frame.timestamp;
        const bool ab = source == Endpoint{flow.endpoint_a, flow.port_a};
        (ab ? flow.packets_ab : flow.packets_ba)++;
        (ab ? flow.bytes_ab : flow.bytes_ba) += packet.frame.captured_length;
        if ((packet.tcp_flags & 0x02U) != 0) {
            if ((packet.tcp_flags & 0x10U) != 0)
                ++flow.syn_ack;
            else
                ++flow.syn;
        }
        if ((packet.tcp_flags & 0x10U) != 0)
            ++flow.ack;
        if ((packet.tcp_flags & 0x01U) != 0)
            ++flow.fin;
        if ((packet.tcp_flags & 0x04U) != 0)
            ++flow.rst;
        flow.frames.push_back(packet.frame.number);
    }
    return flows;
}

Analysis analyze(const Input &input, const Config &config) {
    config.validate();
    Analysis result;
    result.filename = input.filename;
    result.sha256 = input.sha256;
    result.file_bytes = input.bytes.size();
    result.config = config;
    result.capture = parse_capture(input.bytes, config.max_packets);
    result.packets.reserve(result.capture.frames.size());
    for (const auto &frame : result.capture.frames) {
        result.packets.push_back(decode_packet(
            frame, std::span(input.bytes).subspan(frame.data_offset, frame.captured_length)));
        if (!result.first || frame.timestamp < *result.first)
            result.first = frame.timestamp;
        if (!result.last || frame.timestamp > *result.last)
            result.last = frame.timestamp;
    }
    result.flows = aggregate_flows(result.packets, config);
    result.findings = detect(result.packets, config);
    return result;
}
} // namespace tracetrust
