# TraceTrust architecture and scope

## Plan recorded before implementation

TraceTrust will be a native C++20, offline classic-PCAP analyzer. The current
project brief supersedes the earlier tool-validation-benchmark proposal. Its
deliverable is a working investigation CLI and an offline analyst dashboard.
It will not depend on TShark or Zeek to decode captures.

The stages are: bounded capture reader → protocol decoder → timestamp-ordered
conversation aggregation → four explicit rules → JSON and self-contained HTML →
synthetic verification, sanitizers, static checks, and documentation.

## Components and contracts

| Component | Responsibility |
| --- | --- |
| `capture` | Read a regular file without writing it; bind SHA-256 to the read bytes; validate classic-PCAP headers, records, byte order and time precision |
| `protocols` | Decode Ethernet/VLAN, IPv4/IPv6, TCP/UDP/ICMP and bounded UDP DNS questions; preserve warnings and partial observations |
| `flows` | Aggregate canonical bidirectional endpoint tuples, split on configurable idle gaps, retain direction counts and frame references |
| `detection` | Evaluate timestamp-sorted sliding windows; produce evidence-linked, deterministic threshold findings |
| `reporting` | Encode provenance, configurations, observations and findings as JSON; embed safe JSON in a compiled-in offline dashboard |
| `dashboard` | Render genuine report data with filters, timeline selection, topology and an evidence inspector; no network dependencies |

## Boundaries

Only classic PCAP 2.4 with Ethernet link type is accepted. Both byte orders and
microsecond/nanosecond timestamps are supported. PCAPNG and other link types are
explicitly unsupported. IPv4 fragments and IPv6 fragmentation are not reassembled.
TCP is summarized by observed headers, not reassembled into byte streams. DNS
support covers UDP headers and question sections, not all resource records or
TCP DNS. No live traffic, scanning, name resolution, or network connections exist
in the analyzer.

Input bytes and decoded metadata are bounded by documented file and frame limits.
Malformed packet data becomes a warning rather than an unchecked read. A damaged
PCAP record stops parsing at a known prefix and marks the report incomplete.
An unsupported or invalid global header is an operation error. Source mutation
detected across the read is an error; no stable live-system view is promised.

Conversation endpoints are not automatically called client/server. The first
observed endpoint is A; reverse traffic is B→A. Reuse without an idle gap may be
merged. TCP flags describe observed signals, not a proven successful connection.

Thresholds are analyst configuration, not calibrated probabilities. A SYN repeat
may be a retransmission; a port sweep may be inventory; a traffic burst may be a
backup; a DNS burst may be legitimate automation. Every finding must include its
window, exact count, threshold, supporting frames, and these limitations.

## Dependencies and safety choices

OpenSSL EVP supplies SHA-256. The MIT-licensed nlohmann/json library supplies JSON
encoding. CMake embeds the dashboard assets in the executable, allowing reports
to work without an asset directory or CDN. Captured strings are rendered through
DOM text nodes; embedded JSON escapes HTML-significant characters. New report
directories and create-only files prevent accidental overwrites.

The implementation targets the available Linux/POSIX environment. Portability
is not claimed until another platform is actually built and tested.

## Primary documentation consulted

Accessed 2026-10-14. These sources guide field interpretation, not endorsements.

- Harris and Richardson, *PCAP Capture File Format*, IETF draft-ietf-opsawg-pcap-06:
  https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-06.html (Internet-Draft).
- RFC 791 (IPv4): https://www.rfc-editor.org/rfc/rfc791.html
- RFC 8200 (IPv6): https://www.rfc-editor.org/rfc/rfc8200.html
- RFC 9293 (TCP): https://www.rfc-editor.org/rfc/rfc9293.html
- RFC 1035 (DNS, including compression): https://www.rfc-editor.org/rfc/rfc1035.html
- TShark official manual: https://www.wireshark.org/docs/man-pages/tshark.html
- Zeek offline quick start: https://docs.zeek.org/en/lts/quickstart.html

Any optional external comparison must use `tshark -n -r` or `zeek -r`, record
the installed version, and compare only aligned field semantics. Availability
and actual execution will be recorded in validation documentation.
