# Security and responsible use

TraceTrust is an educational offline analyzer. Use captures you are authorized
to examine. It does not sniff, scan, resolve names, connect to remote services,
decrypt traffic, or upload reports. Dependency installation and optional browser
installation require network access; analysis and report viewing do not.

## Handling untrusted captures

- Work on an acquired copy in a controlled directory with an unprivileged account.
  Do not expose sensitive originals to exploratory tools. This program is not a
  replacement for write blockers or validated acquisition procedures.
- Inputs are opened read-only, with terminal symlinks refused and regular-file
  checks. The acquired bytes are hashed. Device, inode, size, mtime and ctime are
  checked around reading. Parent directories are trusted: symlinked ancestors,
  mount changes and a hostile process racing path changes are outside the threat
  model. A live file cannot be made an atomic forensic snapshot by these checks.
- Reading may update filesystem access time. No promise of zero OS side effects
  is made. The tool never intentionally writes, renames or deletes its input.
- Input size and frame-count limits bound work, but report serialization and
  browser parsing can still require substantial RAM. A per-frame metadata report
  is not appropriate for multi-gigabyte production captures.
- Every decoder checks containing lengths before field access; DNS names and
  IPv6 extension work have additional limits. Tests and sanitizers do not prove
  absence of parser vulnerabilities. Resource exhaustion remains possible within
  configured limits.
- Output must be a new directory under a trusted existing parent. Files are
  created exclusively (0600) in a directory created with mode 0700. Failures may
  leave partial new output, which must be reviewed before reuse or removal.
- Capture-derived strings are JSON-encoded, escaped for HTML embedding, and
  rendered as DOM text. A content security policy disables network connections.
  Use a maintained browser for real work; the recorded Chromium version is a
  reproducibility detail, not a browser security recommendation.

## Report privacy and trust

Exports contain the input basename, SHA-256, IP addresses, ports, DNS questions,
timestamps and selected header fields. They do not contain the absolute source
path or raw payload bytes. These metadata can still be sensitive. Review them
before sharing. A hash identifies bytes; it does not authenticate origin, prove
clock accuracy, establish consent, or create a legal chain of custody. Reports
are editable local files and are neither signed nor tamper-proof.

## Reporting a problem

Do not publish a private capture, credentials, personal data, or a working attack
against a third-party system in an issue. Use a minimal synthetic reproduction,
the analyzer version, build mode, command and relevant sanitizer output. Once
this repository is published, use its private vulnerability reporting channel
if the owner has enabled one; otherwise ask the maintainer for a private channel
without disclosing sensitive details publicly. No response-time SLA or ongoing
security maintenance is claimed for this individual project.
