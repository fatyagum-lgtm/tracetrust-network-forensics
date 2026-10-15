#include "tracetrust/core.hpp"
#include <algorithm>
#include <array>
#include <fstream>
#include <functional>
#include <iostream>
#include <random>
#include <sys/stat.h>
#include <unistd.h>

using namespace tracetrust;
namespace {
struct Test {
    std::string group, name;
    std::function<void()> run;
};
std::vector<Test> &tests() {
    static std::vector<Test> list;
    return list;
}
struct Register {
    Register(std::string group, std::string name, std::function<void()> fn) {
        tests().push_back({std::move(group), std::move(name), std::move(fn)});
    }
};
#define JOIN_(a, b) a##b
#define JOIN(a, b) JOIN_(a, b)
#define TEST(group, name)                                                                          \
    void JOIN(test_, __LINE__)();                                                                  \
    const Register JOIN(reg_, __LINE__)(group, name, JOIN(test_, __LINE__));                       \
    void JOIN(test_, __LINE__)()
#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression))                                                                         \
            throw std::runtime_error(std::string(#expression) + " at line " +                      \
                                     std::to_string(__LINE__));                                    \
    } while (false)
void throws(const std::function<void()> &action, std::string_view contains = "") {
    try {
        action();
    } catch (const Error &error) {
        CHECK(std::string_view(error.what()).find(contains) != std::string_view::npos);
        return;
    }
    throw std::runtime_error("Expected a TraceTrust Error");
}

void put(Bytes &b, std::size_t offset, std::uint32_t value, std::size_t width = 2,
         bool le = false) {
    for (std::size_t i = 0; i < width; ++i)
        b.at(offset + i) = static_cast<std::uint8_t>(value >> (8U * (le ? i : width - 1 - i)));
}
Bytes udp(Bytes payload = {}, std::uint16_t sport = 41000, std::uint16_t dport = 9999) {
    Bytes b(14 + 20 + 8 + payload.size());
    put(b, 12, 0x0800);
    b[14] = 0x45;
    put(b, 16, static_cast<std::uint32_t>(b.size() - 14));
    b[22] = 64;
    b[23] = 17;
    const Bytes source{192, 0, 2, 1}, destination{198, 51, 100, 2};
    std::copy(source.begin(), source.end(), b.begin() + 26);
    std::copy(destination.begin(), destination.end(), b.begin() + 30);
    put(b, 34, sport);
    put(b, 36, dport);
    put(b, 38, static_cast<std::uint32_t>(8 + payload.size()));
    std::copy(payload.begin(), payload.end(), b.begin() + 42);
    return b;
}
Bytes tcp(std::uint16_t sport = 41000, std::uint16_t dport = 443, std::uint8_t flags = 2) {
    auto b = udp(Bytes(12), sport, dport);
    b[23] = 6;
    std::fill(b.begin() + 38, b.end(), 0);
    put(b, 38, 123456, 4);
    b[46] = 0x50;
    b[47] = flags;
    return b;
}
Bytes reverse(Bytes b) {
    for (std::size_t i = 0; i < 4; ++i)
        std::swap(b[26 + i], b[30 + i]);
    std::swap(b[34], b[36]);
    std::swap(b[35], b[37]);
    return b;
}
Bytes v6(Bytes v4) {
    Bytes b(14 + 40);
    put(b, 12, 0x86dd);
    b[14] = 0x60;
    put(b, 18, static_cast<std::uint32_t>(v4.size() - 34));
    b[20] = v4[23];
    b[21] = 64;
    b[22] = 0x20;
    b[23] = 1;
    b[24] = 0x0d;
    b[25] = 0xb8;
    b[37] = 1;
    b[38] = 0x20;
    b[39] = 1;
    b[40] = 0x0d;
    b[41] = 0xb8;
    b[53] = 2;
    b.insert(b.end(), v4.begin() + 34, v4.end());
    return b;
}
Bytes dns_question() {
    Bytes b(12);
    put(b, 0, 0x1234);
    put(b, 4, 1);
    b[2] = 1;
    const Bytes question{4, 'd', 'e', 'm', 'o', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1};
    b.insert(b.end(), question.begin(), question.end());
    return b;
}
Bytes pcap(const std::vector<std::pair<Time, Bytes>> &packets = {}, bool le = true,
           bool nano = false) {
    Bytes b(24);
    put(b, 0, nano ? 0xa1b23c4dU : 0xa1b2c3d4U, 4, le);
    put(b, 4, 2, 2, le);
    put(b, 6, 4, 2, le);
    put(b, 16, 65535, 4, le);
    put(b, 20, 1, 4, le);
    for (const auto &[time, frame] : packets) {
        const auto offset = b.size();
        b.resize(offset + 16);
        put(b, offset, static_cast<std::uint32_t>(time / second), 4, le);
        put(b, offset + 4, static_cast<std::uint32_t>((time % second) / (nano ? 1 : 1000)), 4, le);
        put(b, offset + 8, static_cast<std::uint32_t>(frame.size()), 4, le);
        put(b, offset + 12, static_cast<std::uint32_t>(frame.size()), 4, le);
        b.insert(b.end(), frame.begin(), frame.end());
    }
    return b;
}
Packet decoded(const Bytes &b, Time time = 100 * second, std::uint32_t number = 1) {
    return decode_packet(Frame{number, 24, 40, time, static_cast<std::uint32_t>(b.size()),
                               static_cast<std::uint32_t>(b.size())},
                         b);
}
Input input(Bytes b) {
    return {"synthetic.pcap", sha256(b), std::move(b)};
}
std::vector<Packet> series(std::size_t count, const Bytes &b, Time step = second) {
    std::vector<Packet> result;
    for (std::size_t i = 0; i < count; ++i)
        result.push_back(decoded(b, 100 * second + i * step, static_cast<std::uint32_t>(i + 1)));
    aggregate_flows(result, Config{});
    return result;
}
std::vector<Finding> rule(const std::vector<Packet> &packets, std::string_view id,
                          const Config &c = {}) {
    auto findings = detect(packets, c);
    std::erase_if(findings, [&](const auto &f) { return f.rule != id; });
    return findings;
}
class Temporary {
  public:
    Temporary() {
        std::array<char, 40> pattern{};
        std::string name = "/tmp/tracetrust-test-XXXXXX";
        std::copy(name.begin(), name.end(), pattern.begin());
        const auto *created = ::mkdtemp(pattern.data());
        if (!created)
            throw std::runtime_error("mkdtemp failed");
        path = created;
    }
    ~Temporary() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    std::filesystem::path path;
};
void write(const std::filesystem::path &path, const Bytes &b) {
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char *>(b.data()), static_cast<std::streamsize>(b.size()));
    CHECK(f.good());
}

TEST("capture", "four byte-order/resolution combinations preserve timestamps") {
    for (bool le : {false, true})
        for (bool nano : {false, true}) {
            auto result = parse_capture(pcap({{123 * second + 456789000, tcp()}}, le, nano), 100);
            CHECK(result.complete);
            CHECK(result.frames.size() == 1);
            CHECK(result.frames[0].timestamp == 123 * second + 456789000);
            CHECK(result.little_endian == le);
            CHECK(result.nanoseconds == nano);
        }
}
TEST("capture", "nanoseconds retain sub-microsecond precision") {
    auto result = parse_capture(pcap({{second + 987654321, udp()}}, true, true), 10);
    CHECK(result.frames[0].timestamp == second + 987654321);
}
TEST("capture", "empty capture is complete") {
    const auto a = analyze(input(pcap()), {});
    CHECK(a.capture.complete);
    CHECK(a.packets.empty());
    CHECK(a.flows.empty());
    CHECK(a.findings.empty());
    CHECK(!a.first);
}
TEST("capture", "unsupported and short global headers fail explicitly") {
    throws([] { parse_capture(Bytes{0x0a, 0x0d, 0x0d, 0x0a}, 10); }, "PCAPNG");
    for (std::size_t n = 0; n < 24; ++n)
        throws([&] { parse_capture(Bytes(n), 10); });
    throws([] { parse_capture(Bytes(24), 10); }, "magic");
    auto b = pcap();
    b[4] = 3;
    throws([&] { parse_capture(b, 10); }, "version");
    b = pcap();
    b[20] = 101;
    throws([&] { parse_capture(b, 10); }, "link type");
    b = pcap();
    put(b, 16, 0, 4, true);
    throws([&] { parse_capture(b, 10); }, "nonzero");
}
TEST("capture", "record corruption retains only a valid prefix") {
    auto b = pcap({{second, tcp()}});
    b.insert(b.end(), 15, 0);
    auto c = parse_capture(b, 100);
    CHECK(!c.complete);
    CHECK(c.frames.size() == 1);
    CHECK(!c.warnings.empty());
    b = pcap({{second, tcp()}});
    b.pop_back();
    c = parse_capture(b, 100);
    CHECK(!c.complete);
    CHECK(c.frames.empty());
}
TEST("capture", "invalid lengths and fractional seconds are rejected") {
    for (auto offset : {28U, 32U}) {
        auto b = pcap({{second, tcp()}});
        put(b, offset, 0xffffffffU, 4, true);
        CHECK(!parse_capture(b, 100).complete);
    }
    auto b = pcap({{second, tcp()}});
    put(b, 36, 1, 4, true);
    CHECK(!parse_capture(b, 100).complete);
}
TEST("capture", "resource limit marks a prefix but exact limit remains complete") {
    auto b = pcap({{second, tcp()}, {second * 2, udp()}});
    CHECK(parse_capture(b, 2).complete);
    const auto c = parse_capture(b, 1);
    CHECK(!c.complete);
    CHECK(c.frames.size() == 1);
}
TEST("capture", "non-monotonic timestamps warn and preserve record identity") {
    auto a = analyze(input(pcap({{2 * second, tcp()}, {second, reverse(tcp())}})), {});
    CHECK(!a.capture.warnings.empty());
    CHECK(a.packets[0].frame.number == 1);
    CHECK(a.first == second);
    CHECK(a.last == 2 * second);
    CHECK(a.flows[0].frames[0] == 2);
}
TEST("capture", "SHA-256 known answers and source bytes are preserved") {
    CHECK(sha256(Bytes{}) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(sha256(Bytes{'a', 'b', 'c'}) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    Temporary temp;
    const auto path = temp.path / "test.pcap";
    const auto original = pcap({{second, tcp()}});
    write(path, original);
    const auto read = read_input(path, {});
    CHECK(read.bytes == original);
    CHECK(read.sha256 == sha256(original));
    CHECK(read.filename == "test.pcap");
    CHECK(read_input(path, {}).bytes == original);
}
TEST("capture", "symlinks special files missing files and oversized files are refused") {
    Temporary temp;
    const auto file = temp.path / "evidence.pcap";
    write(file, pcap());
    std::filesystem::create_symlink(file, temp.path / "link");
    throws([&] { read_input(temp.path / "link", {}); });
    throws([&] { read_input(temp.path / "missing", {}); });
    throws([&] { read_input(temp.path, {}); });
    CHECK(::mkfifo((temp.path / "fifo").c_str(), 0600) == 0);
    throws([&] { read_input(temp.path / "fifo", {}); });
    std::filesystem::resize_file(file, 2 * 1024 * 1024);
    Config c;
    c.max_file_mib = 1;
    throws([&] { read_input(file, c); }, "max_file_mib");
}
TEST("protocols", "IPv4 TCP fields are decoded in network byte order") {
    const auto p = decoded(tcp());
    CHECK(p.protocol == "TCP");
    CHECK(p.source == "192.0.2.1");
    CHECK(p.destination == "198.51.100.2");
    CHECK(p.source_port == 41000);
    CHECK(p.destination_port == 443);
    CHECK(p.tcp_sequence == 123456);
    CHECK(p.tcp_flags == 2);
    CHECK(p.hop_limit == 64);
    CHECK(p.warnings.empty());
}
TEST("protocols", "UDP IPv6 and ICMP paths") {
    CHECK(decoded(udp()).protocol == "UDP");
    const auto p = decoded(v6(udp()));
    CHECK(p.source == "2001:db8::1");
    CHECK(p.destination == "2001:db8::2");
    CHECK(p.protocol == "UDP");
    auto b = udp();
    b[23] = 1;
    b[34] = 8;
    CHECK(decoded(b).icmp_type == 8);
    CHECK(decoded(b).protocol == "ICMP");
    b = v6(b);
    b[20] = 58;
    b[54] = 128;
    CHECK(decoded(b).protocol == "ICMPv6");
    CHECK(decoded(b).icmp_type == 128);
}
TEST("protocols", "VLAN tags are retained and excessive stacks stop") {
    auto b = tcp();
    b.insert(b.begin() + 14, {0, 7, 8, 0});
    put(b, 12, 0x8100);
    CHECK(decoded(b).vlans == std::vector<std::uint16_t>{7});
    CHECK(decoded(b).protocol == "TCP");
    b.insert(b.begin() + 14, {0, 9, 0x81, 0});
    CHECK(decoded(b).vlans.size() == 2);
    b.insert(b.begin() + 14, {0, 10, 0x81, 0});
    CHECK(decoded(b).partial);
    CHECK(!decoded(b).transport_valid);
}
TEST("protocols", "invalid IPv4 header lengths and TCP offsets are visible") {
    auto b = tcp();
    b[14] = 0x44;
    CHECK(decoded(b).malformed);
    b = tcp();
    put(b, 16, 10);
    CHECK(decoded(b).malformed);
    b = tcp();
    b[46] = 0x40;
    CHECK(decoded(b).malformed);
    b = tcp();
    b[46] = 0xf0;
    CHECK(decoded(b).malformed);
}
TEST("protocols", "capture truncation does not fabricate a transport header") {
    auto b = tcp();
    b.resize(41);
    const auto p = decoded(b);
    CHECK(p.partial);
    CHECK(!p.transport_valid);
    CHECK(!p.source_port);
    CHECK(p.protocol == "IPv4");
    b = udp(Bytes(100));
    b.resize(50);
    CHECK(decoded(b).transport_valid);
    CHECK(decoded(b).partial);
}
TEST("protocols", "IPv4 and IPv6 fragments do not yield transport flows") {
    auto b = tcp();
    put(b, 20, 0x2000);
    CHECK(!decoded(b).transport_valid);
    CHECK(decoded(b).partial);
    b = tcp();
    put(b, 20, 1);
    CHECK(!decoded(b).transport_valid);
    b = v6(tcp());
    b[20] = 44;
    CHECK(!decoded(b).transport_valid);
    CHECK(decoded(b).partial);
}
TEST("protocols", "IPv6 extension chain is length checked") {
    auto b = v6(tcp());
    b.insert(b.begin() + 54, {6, 0, 0, 0, 0, 0, 0, 0});
    b[20] = 0;
    put(b, 18, static_cast<std::uint32_t>(b.size() - 54));
    CHECK(decoded(b).protocol == "TCP");
    b[55] = 100;
    CHECK(decoded(b).malformed);
    b.resize(55);
    CHECK(decoded(b).partial);
}
TEST("protocols", "UDP length violations do not produce DNS evidence") {
    auto b = udp(dns_question(), 40000, 53);
    put(b, 38, 7);
    CHECK(decoded(b).malformed);
    CHECK(!decoded(b).dns_valid);
    put(b, 38, 65535);
    CHECK(decoded(b).malformed);
}
TEST("protocols", "DNS questions flags types and compression") {
    auto question = dns_question();
    auto p = decoded(udp(question, 42000, 53));
    CHECK(p.dns_valid);
    CHECK(!p.dns_response);
    CHECK(p.dns_id == 0x1234);
    CHECK(p.questions.size() == 1);
    CHECK(p.questions[0].name == "demo.test");
    CHECK(p.questions[0].type == 1);
    put(question, 4, 2);
    question.insert(question.end(), {0xc0, 12, 0, 28, 0, 1});
    question[2] = 0x83;
    p = decoded(udp(question, 53, 42000));
    CHECK(p.dns_valid);
    CHECK(p.questions.size() == 2);
    CHECK(p.questions[1].name == "demo.test");
    CHECK(p.questions[1].type == 28);
    CHECK(p.dns_response);
    CHECK(p.dns_truncated_flag);
}
TEST("protocols", "DNS compression loops out-of-range pointers and limits are rejected") {
    auto b = dns_question();
    b[12] = 0xc0;
    b[13] = 12;
    CHECK(decoded(udp(b, 1, 53)).malformed);
    CHECK(!decoded(udp(b, 1, 53)).dns_valid);
    b[13] = 200;
    CHECK(!decoded(udp(b, 1, 53)).dns_valid);
    b = dns_question();
    put(b, 4, 17);
    CHECK(!decoded(udp(b, 1, 53)).dns_valid);
    b = dns_question();
    b.pop_back();
    CHECK(!decoded(udp(b, 1, 53)).dns_valid);
}
TEST("protocols", "DNS strings preserve delimiters as data and escape binary bytes") {
    auto b = dns_question();
    b[13] = '<';
    b[14] = 0xff;
    b[15] = '.';
    b[16] = '\\';
    const auto p = decoded(udp(b, 1, 53));
    CHECK(p.dns_valid);
    CHECK(p.questions[0].name == "<\\xff\\x2e\\x5c.test");
}
TEST("protocols", "IPv4 and TCP options move payload boundaries safely") {
    auto b = tcp();
    b.insert(b.begin() + 34, {1, 1, 1, 1});
    b[14] = 0x46;
    b.insert(b.end(), {1, 1, 1, 1});
    b[50] = 0x60;
    put(b, 16, static_cast<std::uint32_t>(b.size() - 14));
    const auto p = decoded(b);
    CHECK(p.protocol == "TCP");
    CHECK(p.source_port == 41000);
    CHECK(!p.partial);
}
TEST("protocols", "IPv6 extension count and AH length are bounded") {
    auto make_chain = [](unsigned count) {
        auto b = v6(tcp());
        for (unsigned i = 0; i < count; ++i)
            b.insert(b.begin() + 54,
                     {static_cast<std::uint8_t>(i == 0 ? 6 : 0), 0, 0, 0, 0, 0, 0, 0});
        b[20] = 0;
        put(b, 18, static_cast<std::uint32_t>(b.size() - 54));
        return b;
    };
    CHECK(decoded(make_chain(8)).transport_valid);
    CHECK(!decoded(make_chain(9)).transport_valid);
    auto b = make_chain(1);
    b[20] = 51;
    CHECK(decoded(b).malformed);
}
TEST("protocols", "DNS expanded-name limit is exactly 255 octets") {
    auto make_name = [](unsigned last) {
        Bytes b(12);
        put(b, 4, 1);
        for (unsigned n : {63U, 63U, 63U, last}) {
            b.push_back(static_cast<std::uint8_t>(n));
            b.insert(b.end(), n, 'a');
        }
        b.insert(b.end(), {0, 0, 1, 0, 1});
        return b;
    };
    CHECK(decoded(udp(make_name(61), 1, 53)).dns_valid);
    CHECK(!decoded(udp(make_name(62), 1, 53)).dns_valid);
}
TEST("protocols", "transport protocol numbers respect their IP family") {
    auto b = tcp();
    b[23] = 58;
    CHECK(decoded(b).protocol == "IPv4");
    b = v6(tcp());
    b[20] = 1;
    CHECK(decoded(b).protocol == "IPv6");
    b.resize(54);
    b[20] = 59;
    put(b, 18, 0);
    CHECK(!decoded(b).partial);
}
TEST("protocols", "unknown Ethernet and short headers remain visible") {
    CHECK(decoded(Bytes(8)).partial);
    auto b = tcp();
    put(b, 12, 0x1234);
    CHECK(decoded(b).protocol == "Other");
    CHECK(decoded(b).partial);
    put(b, 12, 0x0806);
    CHECK(decoded(b).protocol == "ARP");
}
TEST("flows", "reverse TCP and UDP packets group bidirectionally") {
    for (const auto &b : {tcp(), udp()}) {
        auto a = analyze(input(pcap({{second, b}, {2 * second, reverse(b)}})), {});
        CHECK(a.flows.size() == 1);
        CHECK(a.flows[0].packets_ab == 1);
        CHECK(a.flows[0].packets_ba == 1);
        CHECK(a.flows[0].bytes_ab == b.size());
        CHECK(a.packets[0].flow_id == a.packets[1].flow_id);
    }
}
TEST("flows", "idle timeout boundary is inclusive and longer gaps split") {
    auto a =
        analyze(input(pcap({{second, udp()}, {61 * second, udp()}, {122 * second, udp()}})), {});
    CHECK(a.flows.size() == 2);
    CHECK(a.flows[0].frames.size() == 2);
    CHECK(a.flows[1].id == "F000002");
}
TEST("flows", "protocol port and VLAN differences do not merge") {
    std::vector<Packet> packets{decoded(tcp()), decoded(udp()), decoded(tcp(41001))};
    auto extra = decoded(tcp());
    extra.vlans = {12};
    packets.push_back(extra);
    CHECK(aggregate_flows(packets, {}).size() == 4);
}
TEST("flows", "SYN ACK FIN RST are observed counts not success states") {
    auto a = analyze(input(pcap({{second, tcp()},
                                 {2 * second, reverse(tcp(41000, 443, 0x12))},
                                 {3 * second, tcp(41000, 443, 0x11)},
                                 {4 * second, tcp(41000, 443, 4)}})),
                     {});
    const auto &f = a.flows[0];
    CHECK(f.syn == 1);
    CHECK(f.syn_ack == 1);
    CHECK(f.ack == 2);
    CHECK(f.fin == 1);
    CHECK(f.rst == 1);
}
TEST("flows", "partial network observations are not assigned invented ports") {
    auto b = tcp();
    b.resize(38);
    auto a = analyze(input(pcap({{second, b}})), {});
    CHECK(a.flows.empty());
    CHECK(a.packets[0].flow_id.empty());
}
TEST("rules", "TT-A counts distinct ports and honors exact time boundary") {
    std::vector<Packet> packets;
    for (unsigned i = 0; i < 12; ++i)
        packets.push_back(decoded(tcp(40000, static_cast<std::uint16_t>(100 + i)),
                                  i == 11 ? 110 * second : 100 * second, i + 1));
    aggregate_flows(packets, {});
    const auto found = rule(packets, "TT-A");
    CHECK(found.size() == 1);
    CHECK(found[0].observed.at("unique_destination_ports") == 12);
    CHECK(found[0].frames.size() == 12);
    CHECK(found[0].flows.size() == 12);
    packets.back().frame.timestamp++;
    CHECK(rule(packets, "TT-A").empty());
    CHECK(rule(series(30, tcp()), "TT-A").empty());
}
TEST("rules", "TT-A ignores ACK-only traffic and does not combine different targets") {
    auto packets = series(12, tcp(40000, 100, 0x10), 0);
    for (std::size_t i = 0; i < packets.size(); ++i)
        packets[i].destination_port = static_cast<std::uint16_t>(100 + i);
    CHECK(rule(packets, "TT-A").empty());
    for (auto &p : packets) {
        p.tcp_flags = 2;
        p.destination += std::to_string(p.frame.number);
    }
    CHECK(rule(packets, "TT-A").empty());
}
TEST("rules", "TT-B threshold and retransmissions are counted literally") {
    CHECK(rule(series(4, tcp()), "TT-B").empty());
    const auto f = rule(series(5, tcp()), "TT-B");
    CHECK(f.size() == 1);
    CHECK(f[0].evidence_total == 5);
    CHECK(f[0].thresholds.at("syn_without_ack_gte") == 5);
    CHECK(rule(series(5, tcp(40000, 443, 0x12)), "TT-B").empty());
}
TEST("rules", "TT-C packet and byte conditions are alternatives") {
    CHECK(rule(series(79, udp(), 0), "TT-C").empty());
    CHECK(rule(series(80, udp(), 0), "TT-C").size() == 1);
    Config c;
    c.burst_bytes = 84;
    CHECK(rule(series(2, udp(), 0), "TT-C", c).size() == 1);
    c.burst_bytes = 85;
    CHECK(rule(series(2, udp(), 0), "TT-C", c).empty());
}
TEST("rules", "TT-D counts valid query packets not responses or question count") {
    CHECK(rule(series(19, udp(dns_question(), 43000, 53), 0), "TT-D").empty());
    CHECK(rule(series(20, udp(dns_question(), 43000, 53), 0), "TT-D").size() == 1);
    auto q = dns_question();
    q[2] = 0x81;
    CHECK(rule(series(20, udp(q, 53, 43000), 0), "TT-D").empty());
    q = dns_question();
    q.resize(12);
    put(q, 4, 0);
    CHECK(rule(series(20, udp(q, 43000, 53), 0), "TT-D").empty());
}
TEST("rules", "evidence sampling keeps exact counts and valid frame/flow references") {
    const auto packets = series(200, udp(), 0);
    const auto f = rule(packets, "TT-C");
    CHECK(f.size() == 1);
    CHECK(f[0].evidence_total == 200);
    CHECK(f[0].frames.size() == 128);
    CHECK(f[0].frames.front() == 1);
    CHECK(f[0].frames.back() == 128);
    CHECK(f[0].flows == std::vector<std::string>{"F000001"});
}
TEST("rules", "configuration rejects unknown keys nonintegers overflow and unsafe limits") {
    CHECK(parse_config(Json{{"scan_ports", 20}}).scan_ports == 20);
    for (auto j : {Json{{"scna_ports", 2}}, Json{{"scan_ports", true}}, Json{{"scan_ports", 2.5}},
                   Json{{"scan_ports", -1}}, Json{{"scan_ports", 1ULL << 40U}},
                   Json{{"max_packets", 0}}, Json{{"window_seconds", 86401}}})
        throws([&] { parse_config(j); });
    throws([] { parse_config(Json::array()); });
}
TEST("report", "UTC has consistent exact fractional format") {
    CHECK(utc(0) == "1970-01-01T00:00:00.000000000Z");
    CHECK(utc(second + 987654321) == "1970-01-01T00:00:01.987654321Z");
    CHECK(now_utc().size() == 30);
}
TEST("report", "summary timeline protocols and frames reconcile exactly") {
    auto a = analyze(
        input(pcap({{second, tcp()}, {2 * second, udp()}, {3 * second, reverse(tcp())}})), {});
    const auto j = make_report(a, "2026-01-01T00:00:00.000000000Z");
    CHECK(j["summary"]["packets"] == 3);
    CHECK(j["summary"]["captured_bytes"] == 150);
    CHECK(j["summary"]["flows"] == 2);
    CHECK(j["packets"][0]["timestamp_ns"].is_string());
    std::uint64_t count = 0, volume = 0;
    for (const auto &bin : j["timeline"]["buckets"]) {
        count += bin["packets"].get<unsigned>();
        volume += bin["captured_bytes"].get<unsigned>();
    }
    CHECK(count == 3);
    CHECK(volume == 150);
    CHECK(Json::parse(j.dump()) == j);
}
TEST("report", "timeline stays bounded over a multi-year sparse capture") {
    const auto a = analyze(input(pcap({{0, udp()}, {4'000'000'000ULL * second, udp()}})), {});
    const auto j = make_report(a, "fixed");
    CHECK(j["timeline"]["buckets"].size() <= 120);
    CHECK(j["summary"]["packets"] == 2);
}
TEST("report", "script-closing strings are JSON data and never executable markup") {
    auto i = input(pcap());
    i.filename = "</script><script>globalThis.injected=1</script>\"&";
    const auto j = make_report(analyze(i, {}), "fixed"), parsed = Json::parse(j.dump());
    CHECK(parsed == j);
    const auto html = dashboard(j);
    CHECK(html.find(i.filename) == std::string::npos);
    CHECK(html.find("\\u003c/script\\u003e") != std::string::npos);
    const std::string start = "<script type=\"application/json\" id=\"report-data\">";
    const auto offset = html.find(start) + start.size();
    CHECK(Json::parse(html.substr(offset, html.find("</script>", offset) - offset)) == j);
}
TEST("report", "output directories are exclusive and input remains untouched") {
    Temporary temp;
    const auto path = temp.path / "input.pcap";
    const auto b = pcap();
    write(path, b);
    const auto j = make_report(analyze(read_input(path, {}), {}), "fixed");
    write_reports(temp.path / "report", j, false);
    CHECK(std::filesystem::exists(temp.path / "report/index.html"));
    std::ifstream f(temp.path / "report/report.json");
    Json read;
    f >> read;
    CHECK(read == j);
    throws([&] { write_reports(temp.path / "report", j, false); }, "new directory");
    throws([&] { write_reports(path, j, false); });
    CHECK(read_input(path, {}).bytes == b);
    write_reports(temp.path / "json", j, true);
    CHECK(!std::filesystem::exists(temp.path / "json/index.html"));
}
TEST("report", "analysis is deterministic with a fixed generation timestamp") {
    const auto i = input(pcap({{second, tcp()}, {second, reverse(tcp())}, {2 * second, udp()}}));
    CHECK(make_report(analyze(i, {}), "fixed") == make_report(analyze(i, {}), "fixed"));
}
TEST("report", "empty reports have explicit arrays and zero metrics") {
    const auto j = make_report(analyze(input(pcap()), {}), "fixed");
    CHECK(j["flows"].is_array());
    CHECK(j["packets"].empty());
    CHECK(j["timeline"]["buckets"].empty());
    CHECK(j["summary"]["first_utc"].is_null());
    CHECK(j["summary"]["captured_bytes"] == 0);
}
TEST("robustness", "every prefix of supported frames is bounds checked") {
    for (const auto &b : {tcp(), udp(dns_question(), 1, 53), v6(udp()), v6(tcp())}) {
        for (std::size_t n = 0; n <= b.size(); ++n) {
            const Bytes prefix(b.begin(), b.begin() + static_cast<std::ptrdiff_t>(n));
            const auto p = decoded(prefix);
            CHECK(p.frame.captured_length == n);
        }
    }
}
TEST("robustness", "seeded mutation corpus completes without unsafe memory access") {
    std::mt19937 random(0x54524143U);
    const auto seed =
        pcap({{second, tcp()}, {2 * second, udp(dns_question(), 1, 53)}, {3 * second, v6(tcp())}});
    for (unsigned attempt = 0; attempt < 2500; ++attempt) {
        auto b = seed;
        for (unsigned n = 0; n < 1 + random() % 12; ++n)
            b[random() % b.size()] = static_cast<std::uint8_t>(random());
        if (attempt % 3 == 0)
            b.resize(random() % b.size());
        try {
            const auto a = analyze(input(std::move(b)), {});
            // Mutated lengths can expose additional syntactically valid zero-byte records.
            // The invariant is bounded, non-overlapping records, not the seed's frame count.
            CHECK(a.packets.size() <= (a.file_bytes - 24) / 16);
            std::uint64_t end = 24;
            for (const auto &p : a.packets) {
                CHECK(p.frame.record_offset == end);
                end = p.frame.record_offset + 16 + p.frame.captured_length;
                CHECK(end <= a.file_bytes);
            }
            const auto j = make_report(a, "fixed");
            CHECK(j["summary"]["packets"] == a.packets.size());
        } catch (const Error &) { /* Invalid global headers are expected, never ignored successful
                                     parses. */
        }
    }
}
TEST("robustness", "frame-limit behavior under a larger valid capture") {
    std::vector<std::pair<Time, Bytes>> frames;
    for (unsigned i = 0; i < 5000; ++i)
        frames.emplace_back(i * second, udp());
    Config c;
    c.max_packets = 1000;
    const auto a = analyze(input(pcap(frames)), c);
    CHECK(a.packets.size() == 1000);
    CHECK(!a.capture.complete);
    CHECK(a.flows.size() == 1);
}
} // namespace

int main(int argc, char **argv) {
    const std::string group = argc > 1 ? argv[1] : "";
    unsigned passed = 0, failed = 0;
    for (const auto &test : tests()) {
        if (!group.empty() && test.group != group)
            continue;
        try {
            test.run();
            ++passed;
            std::cout << "PASS " << test.group << " / " << test.name << '\n';
        } catch (const std::exception &error) {
            ++failed;
            std::cerr << "FAIL " << test.name << ": " << error.what() << '\n';
        }
    }
    std::cout << passed << " passed, " << failed << " failed\n";
    return passed > 0 && failed == 0 ? 0 : 1;
}
