# Rules: exact semantics and limits

Rules operate on decoded observations, sorted by `(epoch nanoseconds, frame number)`.
They do not use arrival order as a clock, resolve names, or infer user intent.

## Windows and deterministic selection

For each grouping key, a two-pointer sweep maintains an inclusive interval
`[end - configured_window, end]`. Its end is an observed packet timestamp. Time
before the unsigned PCAP epoch is outside the input domain; reported starts clamp
at zero. The rule evaluates every such candidate window, including equality at
both the time and count thresholds. This is a sliding window, not timeline bins:
dashboard bins use half-open `[start,end)` intervals for non-overlapping totals.

Only one finding per rule/group is retained. TT-A maximizes distinct ports, then
packet count, then captured bytes. TT-B, TT-C and TT-D select the qualifying window
with the most packets, then bytes. Exact ties retain the earliest candidate.
For TT-C this need not be the maximum-byte window: it is a representative
qualifying window, not an exhaustive episode list or a scored maximum anomaly.

`window_start_utc` / `window_end_utc` are configured boundaries. `first_utc` /
`last_utc` are the first/last supporting observations and may span less than the
configured window. The evidence count is exact for the selected window. References
retain the first 128 supporting frames; `evidence_sampled` makes this explicit.
Flow references are the unique flows of that retained subset. All analyzed frames
remain in `packets` and can be queried separately.

IDs are assigned in rule order TT-A through TT-D, then the ordered grouping keys.
The same input and config produce the same observations/IDs; `generated_utc` changes
on each CLI run. Thresholds are not calibrated probabilities. Medium/low are a
documented triage ordering, not a claim of confidence or impact.

## TT-A: potential port sweep

Group: source address, destination address, transport. Count distinct destination
ports among TCP SYN-without-ACK packets or valid UDP header observations. A packet
marked malformed is excluded. Partial packets with complete transport headers can
still supply usable ports. Default: 12 ports in 10 seconds.

Repeated visits to one port do not increase the distinct count. Sources, targets
and transports are not combined. Authorized discovery and inventory can trigger
the rule. Slow/distributed scans, ACK-based scanning and unsupported transports
can evade it. It does not prove a completed connection or access to a service.

## TT-B: repeated SYN activity

Group: directed source/destination address and port tuple. Count SYN=1, ACK=0.
Default: five packets in 10 seconds. SYN retransmissions are intentionally not
deduplicated: sequence numbers remain visible in frame details. A busy tuple or
packet duplication can trigger the rule. Different source ports create different
groups, so changing-port attempts can be missed. Incomplete reverse capture can
hide replies; neither missing replies nor repeated SYNs proves failure.

## TT-C: concentrated traffic burst

Group: decoded IP source. Count packets and captured link-layer bytes. Default:
at least 80 packets **OR** 65,536 bytes in one second. This includes partial or
malformed transport observations when the source IP was decoded; they remain
flagged in the report. Unresolved Ethernet records cannot be assigned to a host.

This is a fixed-volume threshold, not detection against a learned normal baseline.
Backups, updates, bulk transfers and duplicate capture can trigger it. Low-volume
abuse can pass unnoticed. The bytes are PCAP captured lengths, including Ethernet
headers; they do not estimate unique delivered application data.

## TT-D: high DNS query activity

Group: source IP. Count UDP port-53 packets with a parsed DNS header, QR=0 and at
least one completely decoded question. Default: 20 packets in 10 seconds. A
multi-question packet counts once. Duplicate names, repeated IDs and retransmitted
queries are counted. This rule does not inspect entropy, answer records, TTLs or
malware indicators, and does not distinguish DNS opcodes beyond the QR condition.

Resolvers, browser startup and automated jobs can produce legitimate bursts.
TCP DNS, encrypted DNS, alternate ports, invalid questions and fragment-only
captures are outside scope. A high rate does not establish DNS tunneling.

## Identity, tuning and evaluation limits

Conversation keys include the VLAN stack. Rule groups currently use IP identities
across VLANs. Overlapping addresses from isolated tenants can therefore combine
for detection. Separate such captures before using these rules; VLAN-aware rule
identity is future work. NAT, capture placement, missing directions and missing
frames also change what an IP identity represents.

Raising a count threshold can remove findings; lowering it can increase benign
alerts. A longer window gathers more observations but does not automatically mean
a higher event rate. Use `--default-config`, retain the resulting JSON configuration,
and state why a threshold suits the network under review. Do not tune against one
example and report detection accuracy as if it were an independent evaluation.

The sample has independently specified triggering patterns and a non-triggering
baseline. It validates rule mechanics, not realistic precision/recall, resistance
to evasion, or malware detection.
