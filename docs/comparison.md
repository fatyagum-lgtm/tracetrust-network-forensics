# Optional external comparison

**Status: not executed.** Neither TShark nor Zeek was installed in this workspace.
The attempted system package installation failed in the managed execution
environment. Native C++ analysis, tests and the dashboard do not require either
program. There is no measured agreement or performance comparison to report.

For an authorized local comparison, first record actual installed versions:

```bash
tshark --version
zeek --version
```

The official TShark interface supports offline `-r` and `-n` to disable name
resolution. From this repository root, after creating `reports/`:

```bash
tshark -n -r examples/captures/baseline.pcap -T fields \
  -e frame.number -e frame.cap_len -e frame.time_epoch \
  -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst \
  -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \
  > reports/tshark-baseline.tsv
```

Compare complete-record count, sum of captured lengths, epoch timestamps and
address/port tuples. TraceTrust's baseline expectation is specified separately in
`examples/expectations.json`. Do not compare its exclusive transport categories
against TShark's highest-layer display column: a packet labeled HTTP or DNS there
is TCP or UDP here. Avoid forcing agreement on fragments or incomplete frames,
where decoder policies differ.

The official Zeek quick start supports an offline capture and JSON logs:

```bash
mkdir -p reports/zeek-baseline
cd reports/zeek-baseline
zeek -r ../../examples/captures/baseline.pcap LogAscii::use_json=T
```

Zeek's connection semantics, originator/responder inference, transport state,
timeouts and byte accounting differ from this project's idle-separated bidirectional
tuples. Compare only aligned observations and explain mismatches; `conn.log` rows
are not automatically equivalent to TraceTrust conversations.

These commands are reproduction guidance, not a claimed completed experiment.
Sources: [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html),
[Zeek quick start](https://docs.zeek.org/en/lts/quickstart.html).
