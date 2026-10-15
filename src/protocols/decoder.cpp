#include "tracetrust/core.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <set>

namespace tracetrust {
namespace {
using View = std::span<const std::uint8_t>;

// These helpers are called only after a containing header has been bounds-checked.
std::uint16_t u16(View bytes, std::size_t at) {
    return static_cast<std::uint16_t>((static_cast<unsigned>(bytes[at]) << 8U) | bytes[at + 1]);
}
std::uint32_t u32(View bytes, std::size_t at) {
    return (static_cast<std::uint32_t>(u16(bytes, at)) << 16U) | u16(bytes, at + 2);
}
void warn(Packet &packet, const std::string &message, bool malformed = false) {
    packet.warnings.push_back(message);
    packet.partial = true;
    packet.malformed = packet.malformed || malformed;
}
std::string address(View bytes, int family) {
    std::array<char, INET6_ADDRSTRLEN> text{};
    if (inet_ntop(family, bytes.data(), text.data(), text.size()) == nullptr)
        throw Error("Cannot format IP address.");
    return text.data();
}

// A name can jump only within this DNS message. Bound both expansion and pointer work.
std::optional<std::pair<std::string, std::size_t>> dns_name(View data, std::size_t start) {
    std::string name;
    std::size_t cursor = start, consumed = 0, expanded = 1;
    bool jumped = false;
    std::set<std::size_t> visited;
    for (unsigned steps = 0; steps < 128; ++steps) {
        if (cursor >= data.size() || !visited.insert(cursor).second)
            return std::nullopt;
        const auto length = data[cursor];
        if ((length & 0xc0U) == 0xc0U) {
            if (data.size() - cursor < 2)
                return std::nullopt;
            const auto pointer = static_cast<std::size_t>(u16(data, cursor) & 0x3fffU);
            if (pointer < 12 || pointer >= cursor)
                return std::nullopt;
            if (!jumped)
                consumed += 2;
            cursor = pointer;
            jumped = true;
            continue;
        }
        if ((length & 0xc0U) != 0)
            return std::nullopt;
        ++cursor;
        if (!jumped)
            ++consumed;
        if (length == 0)
            return std::pair{name.empty() ? std::string(".") : name, start + consumed};
        if (length > data.size() - cursor || expanded + length + 1 > 255)
            return std::nullopt;
        expanded += length + 1;
        if (!name.empty())
            name += '.';
        for (std::size_t i = 0; i < length; ++i) {
            const char value = static_cast<char>(data[cursor + i]);
            name += value == '.' ? "\\x2e" : printable(std::string_view(&value, 1));
        }
        cursor += length;
        if (!jumped)
            consumed += length;
    }
    return std::nullopt;
}

void dns(Packet &packet, View data) {
    if (data.size() < 12) {
        warn(packet, "DNS header is incomplete.");
        return;
    }
    const auto count = u16(data, 4);
    if (count > 16) {
        warn(packet, "DNS question limit (16) exceeded; questions not decoded.");
        return;
    }
    std::vector<DnsQuestion> questions;
    std::size_t cursor = 12;
    for (std::uint16_t i = 0; i < count; ++i) {
        const auto name = dns_name(data, cursor);
        if (!name || name->second > data.size() || data.size() - name->second < 4) {
            warn(packet, "DNS question is truncated or has an invalid name/compression pointer.",
                 true);
            return;
        }
        cursor = name->second;
        questions.push_back({name->first, u16(data, cursor), u16(data, cursor + 2)});
        cursor += 4;
    }
    packet.dns_valid = true; // Header and questions only, not validation of resource records.
    packet.dns_id = u16(data, 0);
    packet.dns_response = (data[2] & 0x80U) != 0;
    packet.dns_truncated_flag = (data[2] & 0x02U) != 0;
    packet.dns_rcode = data[3] & 0x0fU;
    packet.questions = std::move(questions);
}

void transport(Packet &packet, View data, std::uint8_t protocol, std::size_t expected) {
    if (protocol == 6) {
        if (data.size() < 20) {
            warn(packet, "TCP fixed header is incomplete.");
            return;
        }
        const auto header = static_cast<std::size_t>(data[12] >> 4U) * 4;
        if (header < 20 || header > expected) {
            warn(packet, "Invalid TCP data offset.", true);
            return;
        }
        if (header > data.size()) {
            warn(packet, "TCP options are incomplete.");
            return;
        }
        packet.protocol = "TCP";
        packet.source_port = u16(data, 0);
        packet.destination_port = u16(data, 2);
        packet.tcp_sequence = u32(data, 4);
        packet.tcp_acknowledgment = u32(data, 8);
        packet.tcp_flags = static_cast<std::uint16_t>(((data[12] & 1U) << 8U) | data[13]);
        packet.transport_valid = true;
        if ((*packet.source_port == 53 || *packet.destination_port == 53) && data.size() > header)
            packet.warnings.push_back("DNS over TCP is not decoded (no stream reassembly).");
    } else if (protocol == 17) {
        if (data.size() < 8) {
            warn(packet, "UDP header is incomplete.");
            return;
        }
        const auto length = u16(data, 4);
        if (length < 8 || length > expected) {
            warn(packet, "Invalid UDP datagram length.", true);
            return;
        }
        packet.protocol = "UDP";
        packet.source_port = u16(data, 0);
        packet.destination_port = u16(data, 2);
        packet.transport_valid = true;
        if (length > data.size())
            warn(packet, "UDP payload is capture-truncated.");
        if (*packet.source_port == 53 || *packet.destination_port == 53)
            dns(packet, data.first(std::min<std::size_t>(length, data.size())).subspan(8));
    } else if ((protocol == 1 && packet.network == "IPv4") ||
               (protocol == 58 && packet.network == "IPv6")) {
        if (data.size() < 4) {
            warn(packet, "ICMP header is incomplete.");
            return;
        }
        packet.protocol = protocol == 1 ? "ICMP" : "ICMPv6";
        packet.icmp_type = data[0];
        packet.transport_valid = true;
    } else if (protocol != 59) {
        warn(packet, "IP next-header/protocol " + std::to_string(protocol) + " is unsupported.");
    }
}

void ipv4(Packet &packet, View data) {
    packet.network = "IPv4";
    packet.protocol = "IPv4";
    if (data.size() < 20) {
        warn(packet, "IPv4 fixed header is incomplete.");
        return;
    }
    const auto header = static_cast<std::size_t>(data[0] & 0x0fU) * 4;
    const auto length = u16(data, 2);
    if ((data[0] >> 4U) != 4 || header < 20 || length < header) {
        warn(packet, "Invalid IPv4 version, header length, or total length.", true);
        return;
    }
    if (header > data.size()) {
        warn(packet, "IPv4 options are incomplete.");
        return;
    }
    packet.source = address(data.subspan(12, 4), AF_INET);
    packet.destination = address(data.subspan(16, 4), AF_INET);
    packet.hop_limit = data[8];
    if (length > data.size())
        warn(packet, "IPv4 payload is capture-truncated.");
    if ((u16(data, 6) & 0x3fffU) != 0) {
        warn(packet, "IPv4 fragment: transport decoding skipped; reassembly is unsupported.");
        return;
    }
    transport(packet, data.first(std::min<std::size_t>(length, data.size())).subspan(header),
              data[9], length - header);
}

void ipv6(Packet &packet, View data) {
    packet.network = "IPv6";
    packet.protocol = "IPv6";
    if (data.size() < 40) {
        warn(packet, "IPv6 fixed header is incomplete.");
        return;
    }
    if ((data[0] >> 4U) != 6) {
        warn(packet, "Invalid IPv6 version.", true);
        return;
    }
    packet.source = address(data.subspan(8, 16), AF_INET6);
    packet.destination = address(data.subspan(24, 16), AF_INET6);
    packet.hop_limit = data[7];
    const std::size_t length = 40U + u16(data, 4);
    auto next = data[6];
    if (length == 40 && next != 59) {
        warn(packet, "Zero IPv6 payload length; jumbograms are unsupported.");
        return;
    }
    if (length > data.size())
        warn(packet, "IPv6 payload is capture-truncated.");
    data = data.first(std::min(length, data.size()));
    std::size_t cursor = 40;
    for (unsigned extensions = 0;; ++extensions) {
        if (next == 44) {
            warn(packet,
                 "IPv6 fragment header: transport decoding skipped; reassembly is unsupported.");
            return;
        }
        if (next != 0 && next != 43 && next != 60 && next != 51)
            break;
        if (extensions >= 8) {
            warn(packet, "IPv6 extension-header limit (8) exceeded.");
            return;
        }
        if (data.size() - cursor < 2) {
            warn(packet, "IPv6 extension header is incomplete.");
            return;
        }
        const auto size = next == 51 ? (static_cast<std::size_t>(data[cursor + 1]) + 2) * 4
                                     : (static_cast<std::size_t>(data[cursor + 1]) + 1) * 8;
        if (next == 51 && size < 12) {
            warn(packet, "Invalid IPv6 authentication-header length.", true);
            return;
        }
        if (size > length - cursor) {
            warn(packet, "Invalid IPv6 extension length.", true);
            return;
        }
        if (size > data.size() - cursor) {
            warn(packet, "IPv6 extension body is incomplete.");
            return;
        }
        next = data[cursor];
        cursor += size;
    }
    transport(packet, data.subspan(cursor), next, length - cursor);
}
} // namespace

Packet decode_packet(const Frame &frame, View bytes) {
    Packet packet;
    packet.frame = frame;
    if (frame.captured_length < frame.original_length)
        warn(packet, "Frame is capture-truncated (captured < original).");
    if (bytes.size() < 14) {
        warn(packet, "Ethernet header is incomplete.");
        return packet;
    }
    auto type = u16(bytes, 12);
    std::size_t cursor = 14;
    while (type == 0x8100 || type == 0x88a8) {
        if (packet.vlans.size() >= 2) {
            warn(packet, "More than two VLAN tags are unsupported.");
            return packet;
        }
        if (bytes.size() - cursor < 4) {
            warn(packet, "VLAN header is incomplete.");
            return packet;
        }
        packet.vlans.push_back(u16(bytes, cursor) & 0x0fffU);
        type = u16(bytes, cursor + 2);
        cursor += 4;
    }
    if (type == 0x0800)
        ipv4(packet, bytes.subspan(cursor));
    else if (type == 0x86dd)
        ipv6(packet, bytes.subspan(cursor));
    else if (type == 0x0806)
        packet.protocol = "ARP"; // EtherType classification only.
    else
        warn(packet, "EtherType " + std::to_string(type) + " is unsupported.");
    return packet;
}
} // namespace tracetrust
