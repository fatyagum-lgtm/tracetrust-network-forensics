#include "tracetrust/core.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace tracetrust {
namespace {
class Descriptor {
  public:
    explicit Descriptor(int fd) : fd_(fd) {}
    ~Descriptor() {
        if (fd_ >= 0)
            ::close(fd_);
    }
    Descriptor(const Descriptor &) = delete;
    Descriptor &operator=(const Descriptor &) = delete;
    int get() const {
        return fd_;
    }

  private:
    int fd_;
};

std::uint32_t integer(std::span<const std::uint8_t> bytes, std::size_t pos, bool little,
                      std::size_t width = 4) {
    if (pos > bytes.size() || width > bytes.size() - pos)
        throw Error("Short PCAP header.");
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < width; ++i)
        value |= static_cast<std::uint32_t>(bytes[pos + i]) << (8U * (little ? i : width - 1 - i));
    return value;
}
} // namespace

Input read_input(const std::filesystem::path &path, const Config &config) {
    config.validate();
    Descriptor file(::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
    if (file.get() < 0)
        throw Error("Cannot open input; it must be a readable regular file, not a symlink.");
    struct stat before {
    }, after{}, named{};
    if (::fstat(file.get(), &before) != 0 || !S_ISREG(before.st_mode) || before.st_size < 0)
        throw Error("Input is not a regular file.");
    const auto size = static_cast<std::uint64_t>(before.st_size);
    if (size > static_cast<std::uint64_t>(config.max_file_mib) * 1024U * 1024U)
        throw Error("Input exceeds max_file_mib; no analysis was performed.");
    Input input;
    input.filename = printable(path.filename().string());
    input.bytes.resize(static_cast<std::size_t>(size));
    std::size_t position = 0;
    while (position < input.bytes.size()) {
        const auto count =
            ::read(file.get(), input.bytes.data() + position,
                   std::min<std::size_t>(1024 * 1024, input.bytes.size() - position));
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            throw Error("Input changed or could not be read completely.");
        position += static_cast<std::size_t>(count);
    }
    std::uint8_t extra{};
    if (::read(file.get(), &extra, 1) != 0 || ::fstat(file.get(), &after) != 0 ||
        ::lstat(path.c_str(), &named) != 0 || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec || named.st_ino != after.st_ino ||
        named.st_dev != after.st_dev || !S_ISREG(named.st_mode))
        throw Error("Input changed during acquisition; no stable observation is claimed.");
    input.sha256 = sha256(input.bytes);
    return input;
}

CaptureIndex parse_capture(std::span<const std::uint8_t> bytes, std::uint32_t max_packets) {
    if (bytes.size() >= 4 && bytes[0] == 0x0a && bytes[1] == 0x0d && bytes[2] == 0x0d &&
        bytes[3] == 0x0a)
        throw Error("PCAPNG is not supported natively. Supply classic Ethernet PCAP 2.4.");
    if (bytes.size() < 24)
        throw Error("Capture has no complete 24-byte classic-PCAP header.");
    CaptureIndex result;
    const auto magic = integer(bytes, 0, false);
    switch (magic) {
    case 0xd4c3b2a1U:
        result.little_endian = true;
        break;
    case 0xa1b2c3d4U:
        break;
    case 0x4d3cb2a1U:
        result.little_endian = true;
        result.nanoseconds = true;
        break;
    case 0xa1b23c4dU:
        result.nanoseconds = true;
        break;
    default:
        throw Error("Unrecognized capture magic; only classic PCAP is supported.");
    }
    const auto le = result.little_endian;
    if (integer(bytes, 4, le, 2) != 2 || integer(bytes, 6, le, 2) != 4)
        throw Error("Unsupported classic-PCAP version; expected 2.4.");
    result.snaplen = integer(bytes, 16, le);
    if (result.snaplen == 0)
        throw Error("PCAP snapshot length must be nonzero.");
    if (integer(bytes, 20, le) != 1)
        throw Error("Unsupported PCAP link type or flags; Ethernet (1) only.");
    if (integer(bytes, 8, le) != 0 || integer(bytes, 12, le) != 0)
        result.warnings.push_back("Legacy/reserved global fields are nonzero and ignored; "
                                  "timestamps are interpreted as epoch time.");
    std::size_t position = 24;
    Time previous = 0;
    while (position < bytes.size()) {
        auto stop = [&](const std::string &reason) {
            result.complete = false;
            result.warnings.push_back(reason + " at byte " + std::to_string(position) +
                                      "; only the preceding complete records are analyzed.");
        };
        if (result.frames.size() >= max_packets) {
            stop("Frame limit reached");
            break;
        }
        if (bytes.size() - position < 16) {
            stop("Truncated record header");
            break;
        }
        const auto sec = integer(bytes, position, le);
        const auto fraction = integer(bytes, position + 4, le);
        const auto caplen = integer(bytes, position + 8, le);
        const auto wirelen = integer(bytes, position + 12, le);
        if (fraction >= (result.nanoseconds ? 1'000'000'000U : 1'000'000U)) {
            stop("Invalid timestamp fraction");
            break;
        }
        if (caplen > result.snaplen || caplen > wirelen || caplen > 16U * 1024U * 1024U) {
            stop("Invalid or excessive packet length");
            break;
        }
        if (caplen > bytes.size() - position - 16) {
            stop("Truncated packet record");
            break;
        }
        const Time timestamp = static_cast<Time>(sec) * second +
                               static_cast<Time>(fraction) * (result.nanoseconds ? 1U : 1000U);
        if (!result.frames.empty() && timestamp < previous &&
            std::find(result.warnings.begin(), result.warnings.end(),
                      "Non-monotonic record timestamps; analysis windows use timestamp order.") ==
                result.warnings.end())
            result.warnings.push_back(
                "Non-monotonic record timestamps; analysis windows use timestamp order.");
        previous = timestamp;
        result.frames.push_back(Frame{static_cast<std::uint32_t>(result.frames.size() + 1),
                                      position, position + 16, timestamp, caplen, wirelen});
        position += 16 + static_cast<std::size_t>(caplen);
    }
    return result;
}
} // namespace tracetrust
