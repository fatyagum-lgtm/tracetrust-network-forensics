"use strict";
(() => {
  const data = JSON.parse(document.getElementById("report-data").textContent);
  const $ = (id) => document.getElementById(id);
  const integer = new Intl.NumberFormat("en-US");
  const number = (n) => integer.format(n);
  const bytes = (n) => {
    if (n < 1024) return `${number(n)} B`;
    const unit = Math.min(3, Math.floor(Math.log(n) / Math.log(1024)));
    return `${(n / 1024 ** unit).toFixed(unit === 1 ? 1 : 2)} ${["B", "KiB", "MiB", "GiB"][unit]}`;
  };
  const duration = (ms) => `${(ms / 1000).toFixed(3)} s`;
  const endpoint = (address, port) => port == null ? address : `${address.includes(":") ? `[${address}]` : address}:${port}`;
  const set = (id, text) => {
    $(id).textContent = text;
  };
  const element = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text != null) node.textContent = text;
    if (className) node.className = className;
    return node;
  };
  const svg = (tag, attrs, text) => {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
    if (text != null) node.textContent = text;
    return node;
  };
  const button = (text, action, className) => {
    const node = element("button", text, className);
    node.addEventListener("click", action);
    return node;
  };
  const empty = (parent, text) => parent.append(element("p", text, "empty"));
  const cell = (row, value, className) => {
    const td = element("td", null, className);
    if (value instanceof Node) td.append(value);
    else td.textContent = value;
    row.append(td);
  };
  const activate = (node, action) => {
    node.addEventListener("click", action);
    node.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        action();
      }
    });
  };
  const state = {
    metric: "packets",
    flowPage: 0,
    packetPage: 0,
    findingPage: 0,
    host: "",
    scope: null
  };
  const palette = ["#55d8c1", "#6eabf4", "#bba3ef", "#eebd75", "#a3bdcf"];
  const s = data.summary;
  const incomplete = !data.capture.records_complete || s.partial_packets > 0;
  set("tool-version", `TraceTrust / v${data.tool.version}`);
  set("capture-name", data.capture.filename);
  set("capture-start", s.first_utc ? s.first_utc.replace("T", " ").slice(0, 23) : "No recorded timestamps");
  set("capture-duration", duration(s.duration_ms));
  set("capture-format", `${data.capture.format} · Ethernet`);
  set("capture-hash", data.capture.sha256);
  set("metric-packets", number(s.packets));
  set("metric-bytes", bytes(s.captured_bytes));
  set("metric-flows", number(s.flows));
  set("metric-hosts", number(s.hosts));
  set("metric-findings", number(s.findings));
  set("nav-findings", s.findings);
  set("observation-status", incomplete ? "Partial observations · review warnings" : "Capture processed · offline");
  $("observation-status").classList.toggle("partial", incomplete);
  if (data.capture.warnings.length || s.packets_with_warnings) {
    $("warnings").hidden = false;
    set("warnings", [...data.capture.warnings, `${number(s.packets_with_warnings)} frames have decoder warnings; ${number(s.partial_packets)} partial, ${number(s.malformed_packets)} malformed. Review the evidence explorer.`].join(" "));
  }
  set("configuration", JSON.stringify(data.config, null, 2));
  set("analysis-time", `Generated ${data.generated_utc}. Source timestamp resolution: ${data.capture.timestamp_resolution}. Input size: ${number(data.capture.file_bytes)} bytes.`);
  data.limitations.forEach((text) => $("limitations").append(element("li", text)));
  $("download-json").addEventListener("click", () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json"
    }));
    const link = element("a");
    link.href = url;
    link.download = "tracetrust-report.json";
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });

  function chooseScope(scope, label) {
    state.scope = scope;
    state.packetPage = 0;
    $("packet-search").value = "";
    set("evidence-scope", label);
    $("reset-evidence").hidden = !scope;
    renderPackets();
    $("evidence").scrollIntoView({
      block: "start"
    });
  }

  function renderTimeline() {
    const parent = $("timeline");
    parent.replaceChildren();
    const bins = data.timeline.buckets;
    set("timeline-note", `Aggregated · ${data.timeline.bucket_seconds} s buckets · UTC capture clock`);
    if (!bins.length) {
      empty(parent, "No packet timestamps to display.");
      return;
    }
    const chart = svg("svg", {
      viewBox: "0 0 800 200",
      role: "group",
      "aria-label": "Select a traffic interval"
    });
    const maximum = Math.max(1, ...bins.map((b) => b[state.metric]));
    for (let i = 0; i <= 3; i++) {
      const y = 15 + i * 47;
      chart.append(svg("line", {
        x1: 42,
        x2: 792,
        y1: y,
        y2: y,
        stroke: "#253547",
        "stroke-dasharray": "3 5"
      }));
      chart.append(svg("text", {
        x: 34,
        y: y + 3,
        "text-anchor": "end"
      }, state.metric === "packets" ? number(Math.round(maximum * (1 - i / 3))) : bytes(Math.round(maximum * (1 - i / 3)))));
    }
    const step = 750 / bins.length;
    bins.forEach((bin, index) => {
      const height = bin[state.metric] / maximum * 141;
      const accessible = `${bin.start_utc}: ${number(bin.packets)} packets, ${bytes(bin.captured_bytes)}; inspect interval`;
      const group = svg("g", {
        tabindex: 0,
        role: "button",
        "aria-label": accessible
      });
      group.append(svg("title", {}, accessible));
      group.append(svg("rect", {
        x: 42 + index * step,
        y: 15,
        width: step,
        height: 141,
        fill: "transparent"
      }));
      group.append(svg("rect", {
        x: 42 + index * step + Math.min(3, step * .13),
        y: 156 - height,
        width: Math.max(1, step * .74),
        height,
        rx: 2,
        class: "bar"
      }));
      activate(group, () => chooseScope({
        start: bin.start_relative_ms,
        end: bin.end_relative_ms
      }, `Interval ${duration(bin.start_relative_ms)}–${duration(bin.end_relative_ms)}`));
      chart.append(group);
      if (index === 0 || index === bins.length - 1 || (bins.length > 8 && index % Math.ceil(bins.length / 5) === 0))
        chart.append(svg("text", {
          x: 42 + index * step + step / 2,
          y: 181,
          "text-anchor": "middle"
        }, `${(bin.start_relative_ms / 1000).toFixed(0)}s`));
    });
    parent.append(chart);
  }
  ["packets", "bytes"].forEach((mode) => $("chart-" + mode).addEventListener("click", () => {
    state.metric = mode === "packets" ? "packets" : "captured_bytes";
    $("chart-packets").setAttribute("aria-pressed", String(mode === "packets"));
    $("chart-bytes").setAttribute("aria-pressed", String(mode === "bytes"));
    renderTimeline();
  }));
  const protocols = [...data.protocols].sort((a, b) => b.packets - a.packets);
  protocols.forEach((p, index) => {
    const row = element("div", null, "protocol-row");
    const share = s.packets ? p.packets / s.packets * 100 : 0;
    row.append(element("span", p.protocol), element("strong", `${number(p.packets)} · ${share.toFixed(1)}%`));
    const meter = element("div", null, "meter"),
      bar = element("span");
    bar.style.width = `${share}%`;
    bar.style.background = palette[index % palette.length];
    meter.append(bar);
    row.append(meter);
    $("protocols").append(row);
  });
  if (!protocols.length) empty($("protocols"), "No decoded records.");

  function pagination(prefix, total, size, page) {
    const first = total ? page * size + 1 : 0,
      last = Math.min((page + 1) * size, total);
    set(`${prefix}-page-label`, `${number(first)}–${number(last)} of ${number(total)}`);
    $(`${prefix}-prev`).disabled = page === 0;
    $(`${prefix}-next`).disabled = last >= total;
  }
  [...new Set(data.flows.map((f) => f.protocol))].sort().forEach((p) => {
    const option = element("option", p);
    option.value = p;
    $("flow-protocol").append(option);
  });

  function renderFlows() {
    const query = $("flow-search").value.toLowerCase(),
      protocol = $("flow-protocol").value;
    const matches = data.flows.filter((f) => (!state.host || f.endpoint_a === state.host || f.endpoint_b === state.host) && (!protocol || protocol === f.protocol) && `${f.id} ${f.endpoint_a} ${f.endpoint_b} ${f.port_a} ${f.port_b} ${f.protocol}`.toLowerCase().includes(query));
    const field = {
      volume: "captured_bytes",
      packets: "packets",
      recent: "last_relative_ms"
    } [$("flow-sort").value];
    matches.sort((a, b) => b[field] - a[field] || a.id.localeCompare(b.id));
    const parent = $("flow-rows");
    parent.replaceChildren();
    matches.slice(state.flowPage * 15, (state.flowPage + 1) * 15).forEach((f) => {
      const row = element("tr");
      cell(row, f.id);
      cell(row, endpoint(f.endpoint_a, f.port_a));
      cell(row, "⇄");
      cell(row, endpoint(f.endpoint_b, f.port_b));
      cell(row, element("span", f.protocol, "tag"));
      cell(row, `${number(f.packets_a_to_b)} / ${number(f.packets_b_to_a)}`);
      cell(row, bytes(f.captured_bytes));
      cell(row, duration(f.duration_ms));
      cell(row, button("Inspect ↗", () => chooseScope({
        frames: new Set(f.frames)
      }, `${f.id} · ${number(f.packets)} frames`)));
      parent.append(row);
    });
    if (!matches.length) {
      const row = element("tr"),
        td = element("td", "No conversations match the selection.");
      td.colSpan = 9;
      row.append(td);
      parent.append(row);
    }
    pagination("flow", matches.length, 15, state.flowPage);
    set("flow-count", `${number(matches.length)} of ${number(data.flows.length)} conversations`);
    $("clear-host").hidden = !state.host;
    set("clear-host", state.host ? `${state.host} ×` : "Clear host");
  }

  function selectHost(host) {
    state.host = host;
    state.flowPage = 0;
    $("flow-search").value = "";
    $("flow-protocol").value = "";
    renderFlows();
    $("communications").scrollIntoView({
      block: "start"
    });
  }
  $("clear-host").addEventListener("click", () => {
    state.host = "";
    state.flowPage = 0;
    renderFlows();
  });
  ["flow-search", "flow-protocol", "flow-sort"].forEach((id) => $(id).addEventListener(id === "flow-search" ? "input" : "change", () => {
    state.flowPage = 0;
    renderFlows();
  }));
  const busiest = data.hosts.slice(0, 6);
  const maxHostBytes = Math.max(1, ...busiest.map((h) => h.bytes_sent + h.bytes_received));
  busiest.forEach((host) => {
    const row = element("div", null, "host-row"),
      total = host.bytes_sent + host.bytes_received;
    const control = button("", () => selectHost(host.address));
    control.append(element("span", host.address), element("span", bytes(total)));
    const meter = element("div", null, "meter"),
      bar = element("span");
    bar.style.width = `${total / maxHostBytes * 100}%`;
    meter.append(bar);
    row.append(control, meter);
    $("hosts").append(row);
  });
  if (!busiest.length) empty($("hosts"), "No IP endpoints observed.");

  function topology() {
    const hosts = data.hosts.slice(0, 18),
      ids = new Map(hosts.map((h, i) => [h.address, i]));
    set("topology-note", `${hosts.length} of ${data.hosts.length} endpoints shown (ranked by captured volume). Links aggregate conversations. Select a node to filter the conversation table.`);
    if (!hosts.length) {
      empty($("topology"), "No relationships to map.");
      return;
    }
    const nodes = hosts.map((host, i) => ({
      host,
      x: 300 + Math.cos(i / hosts.length * 2 * Math.PI - Math.PI / 2) * 165,
      y: 147 + Math.sin(i / hosts.length * 2 * Math.PI - Math.PI / 2) * 100
    }));
    const edges = new Map();
    data.flows.forEach((f) => {
      const a = ids.get(f.endpoint_a),
        b = ids.get(f.endpoint_b);
      if (a == null || b == null || a === b) return;
      const key = [a, b].sort((x, y) => x - y).join(":");
      if (!edges.has(key)) edges.set(key, {
        a,
        b,
        count: 0,
        packets: 0
      });
      edges.get(key).count++;
      edges.get(key).packets += f.packets;
    });
    const graph = svg("svg", {
      viewBox: "0 0 600 300",
      role: "group",
      "aria-label": "Aggregated endpoint relationships"
    });
    edges.forEach((e) => {
      const a = nodes[e.a],
        b = nodes[e.b];
      const line = svg("line", {
        x1: a.x,
        y1: a.y,
        x2: b.x,
        y2: b.y,
        "stroke-width": Math.min(5, 1 + Math.log2(e.packets + 1) / 3)
      });
      line.append(svg("title", {}, `${a.host.address} ↔ ${b.host.address}: ${e.count} conversations, ${e.packets} packets`));
      graph.append(line);
    });
    nodes.forEach(({
      host,
      x,
      y
    }) => {
      const node = svg("circle", {
        cx: x,
        cy: y,
        r: 8,
        tabindex: 0,
        role: "button",
        "aria-label": `Filter conversations for ${host.address}`
      });
      node.append(svg("title", {}, `${host.address}: ${number(host.packets_sent)} sent / ${number(host.packets_received)} received`));
      activate(node, () => selectHost(host.address));
      graph.append(node);
      graph.append(svg("text", {
        x: x + (x >= 300 ? 15 : -15),
        y: y + 4,
        "text-anchor": x >= 300 ? "start" : "end",
        class: "host-label"
      }, host.address));
    });
    $("topology").append(graph);
  }

  function renderFindings() {
    const priority = $("finding-priority").value,
      rule = $("finding-rule").value;
    const matches = data.findings.filter((f) => (!priority || f.priority === priority) && (!rule || f.rule === rule));
    const sort = $("finding-sort").value;
    matches.sort((a, b) => sort === "time" ? a.first_utc.localeCompare(b.first_utc) : sort === "evidence" ? b.evidence_total - a.evidence_total : (a.priority === "medium" ? 0 : 1) - (b.priority === "medium" ? 0 : 1) || a.id.localeCompare(b.id));
    const parent = $("finding-cards");
    parent.replaceChildren();
    matches.slice(state.findingPage * 8, (state.findingPage + 1) * 8).forEach((f) => {
      const card = element("article", null, `finding ${f.priority}`);
      const head = element("div", null, "finding-top");
      head.append(element("span", `${f.rule} / ${f.id}`, "rule-label"), element("span", `${f.priority} priority`, "priority"));
      card.append(head, element("h3", f.title), element("p", `${f.source} → ${f.destination || "multiple / observed destinations"}`, "entity"), element("p", f.explanation));
      const facts = element("div", null, "facts");
      for (const [value, label] of [
          [number(f.evidence_total), "supporting frames"],
          [`${f.window_seconds}s`, "inclusive window"]
        ]) {
        const item = element("span");
        item.append(element("b", value), document.createTextNode(` ${label}`));
        facts.append(item);
      }
      card.append(facts);
      const detail = element("details");
      detail.append(element("summary", "Conditions, context & possible false positives"));
      detail.append(element("pre", `Observed\n${JSON.stringify(f.observed, null, 2)}\nThresholds\n${JSON.stringify(f.thresholds, null, 2)}\n\n${f.first_utc}\n${f.last_utc}`));
      detail.append(element("p", `Investigate: ${f.recommendation}`), element("p", `Limits: ${f.limitation}`));
      card.append(detail);
      card.append(button(`Inspect ${number(f.frames.length)} evidence frames ↗`, () => chooseScope({
        frames: new Set(f.frames)
      }, `${f.id}${f.evidence_sampled ? " · evidence sample" : " · evidence"}`)));
      if (f.evidence_sampled) card.append(element("p", `First ${f.frames.length} of ${number(f.evidence_total)} supporting frames retained as references. Counts cover the full window.`, "evidence-note"));
      parent.append(card);
    });
    if (!matches.length) empty(parent, data.findings.length ? "No findings match these filters." : "No configured thresholds were reached. This does not establish that the traffic is benign.");
    set("finding-count", `${number(matches.length)} findings`);
    pagination("finding", matches.length, 8, state.findingPage);
  }
  ["finding-priority", "finding-rule", "finding-sort"].forEach((id) => $(id).addEventListener("change", () => {
    state.findingPage = 0;
    renderFindings();
  }));

  function inspect(packet) {
    set("inspector-title", `Frame ${packet.frame} · ${packet.protocol}`);
    const parent = $("inspector-content");
    parent.replaceChildren();
    const grid = element("dl", null, "detail-grid");
    const values = {
      "Timestamp UTC": packet.timestamp_utc,
      "Epoch nanoseconds": packet.timestamp_ns,
      "Record offset": `${packet.record_offset} bytes`,
      "Source": endpoint(packet.source || "Undecoded", packet.source_port),
      "Destination": endpoint(packet.destination || "Undecoded", packet.destination_port),
      "Captured / original": `${packet.captured_bytes} / ${packet.original_bytes} bytes`,
      "Network / protocol": `${packet.network} / ${packet.protocol}`,
      "Conversation": packet.flow_id || "Not assigned",
      "VLAN IDs": packet.vlans.join(", ") || "None observed",
      "TTL / hop limit": packet.hop_limit ?? "Unavailable",
      "TCP flags": packet.tcp_flags.join(", ") || "None",
      "Sequence / ACK": packet.tcp_sequence == null ? "Not TCP" : `${packet.tcp_sequence} / ${packet.tcp_acknowledgment}`,
      "ICMP type": packet.icmp_type ?? "Not decoded",
      "Status": packet.status,
    };
    Object.entries(values).forEach(([key, value]) => grid.append(element("dt", key), element("dd", value)));
    parent.append(grid);
    if (packet.dns) {
      parent.append(element("h3", "DNS header & questions"), element("pre", JSON.stringify(packet.dns, null, 2)));
    }
    if (packet.warnings.length) parent.append(element("p", packet.warnings.join(" "), "notice"));
    $("inspector").showModal();
  }
  $("close-inspector").addEventListener("click", () => $("inspector").close());

  function renderPackets() {
    const query = $("packet-search").value.toLowerCase();
    const matches = data.packets.filter((p) => {
      const scope = state.scope;
      if (scope?.frames && !scope.frames.has(p.frame)) return false;
      if (scope && !scope.frames && (p.relative_ms < scope.start || p.relative_ms >= scope.end)) return false;
      return !query || `${p.frame} ${p.source} ${p.destination} ${p.protocol} ${p.flow_id} ${p.status} ${p.dns?.questions.map((q) => q.name).join(" ") || ""}`.toLowerCase().includes(query);
    });
    const parent = $("packet-rows");
    parent.replaceChildren();
    matches.slice(state.packetPage * 40, (state.packetPage + 1) * 40).forEach((p) => {
      const row = element("tr");
      cell(row, button(`#${p.frame}`, () => inspect(p)));
      cell(row, duration(p.relative_ms));
      cell(row, `${endpoint(p.source || "?", p.source_port)} → ${endpoint(p.destination || "?", p.destination_port)}`);
      cell(row, element("span", p.protocol, "tag"));
      cell(row, bytes(p.captured_bytes));
      cell(row, p.dns ? p.dns.questions.map((q) => q.name).join(", ") || "DNS header" : p.tcp_flags.join(", ") || "—");
      cell(row, p.status);
      parent.append(row);
    });
    if (!matches.length) {
      const row = element("tr"),
        td = element("td", "No frames match the selection.");
      td.colSpan = 7;
      row.append(td);
      parent.append(row);
    }
    pagination("packet", matches.length, 40, state.packetPage);
  }
  let searchTimer;
  $("packet-search").addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.packetPage = 0;
      renderPackets();
    }, 120);
  });
  $("reset-evidence").addEventListener("click", () => chooseScope(null, "All frames"));
  [
    ["flow", "flowPage", renderFlows],
    ["packet", "packetPage", renderPackets],
    ["finding", "findingPage", renderFindings]
  ].forEach(([prefix, key, render]) => {
    $(`${prefix}-prev`).addEventListener("click", () => {
      state[key]--;
      render();
    });
    $(`${prefix}-next`).addEventListener("click", () => {
      state[key]++;
      render();
    });
  });
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) document.querySelectorAll("nav a").forEach((link) => link.classList.toggle("active", link.hash === `#${entry.target.id}`));
    });
  }, {
    rootMargin: "-10% 0px -65% 0px"
  });
  ["overview", "traffic", "communications", "relationships", "findings", "evidence"].forEach((id) => observer.observe($(id)));
  renderTimeline();
  renderFlows();
  topology();
  renderFindings();
  renderPackets();
})();
