# Validation record

Validation was performed locally on 2026-10-15 UTC. No GitHub-hosted workflow run,
external-tool agreement, production traffic evaluation or attack-detection accuracy
is claimed.

## Environment

| Item | Observed version / scope |
| --- | --- |
| OS | Ubuntu 24.04.3 LTS, x86_64; shared managed Linux container |
| Compiler | GCC / g++ 13.3.0 (`Ubuntu 13.3.0-6ubuntu2~24.04`) |
| CMake / Ninja | 4.4.4 / 1.13.2 |
| OpenSSL headers/library | 3.0.13 |
| nlohmann/json | 3.12.0 vendored headers |
| Python | 3.12.14 |
| Native formatting | clang-format 18.1.8 |
| Static analysis | Cppcheck 2.22.0 (cppcheck-wheel 1.5.3) |
| Fixture builder | dpkt 1.9.8 |
| Browser testing | Playwright 1.51.0; Chromium 134.0.6998.35, offline context |

The available system package manager could not install additional tools. CMake,
Ninja, formatting/static tools and optional Python packages were installed in a
separate local tooling environment. GCC and OpenSSL were already present. This
does not mean the README's normal Ubuntu apt commands were executed successfully
here. No second compiler or non-Linux OS was tested.

## Results

| Check | Actual result |
| --- | --- |
| GCC Debug build | Passed with the configured `-Wall -Wextra -Wpedantic -Wconversion -Wshadow` flags |
| GCC Release build | Passed |
| Fresh extraction of the source ZIP | Release build and **9/9 CTest entries passed** without using the working build directory |
| Native regression runner | **48 named cases passed**, including 2,500 seeded mutation iterations |
| CTest Debug | **9/9 passed**: six native groups, help, version, black-box CLI integration |
| CTest Release | **9/9 passed** |
| AddressSanitizer + UndefinedBehaviorSanitizer | **9/9 passed with leak detection disabled**, due to the environment restriction below |
| clang-format check | Passed; no formatting differences |
| Cppcheck | Passed for project source/tests with vendor diagnostics excluded |
| JavaScript syntax | `node --check dashboard/app.js` passed |
| Synthetic capture reproduction | Byte-for-byte directory comparison passed |
| README CLI walkthrough and local-prefix installation | Executed successfully; sample 205/52/4, adjusted threshold 205/52/3, empty capture 0/0/0 |
| Offline Chromium interaction tests | Passed for metrics/data consistency, finding filters, timeline/flow selection, evidence details, pagination, JSON download, 390 px layout, empty capture and injected display text |

The browser test also checks a 5,000-frame report with a bounded 40-row DOM page.
The optional larger-data check also loaded the 50,000-frame benchmark report and
verified its displayed count and bounded table page. No exhaustive browser
compatibility or accessibility audit is claimed. Screenshots in `docs/screenshots/`
were taken from the real application, not drawn or generated mockups.

## Commands actually used

The project was built from its root. `PATH` was extended with the separate
`../tracetrust-tools/bin` directory to expose installed CMake and Ninja. The
equivalent normal-environment commands are:

```bash
cmake -S . -B build-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug --parallel 2
ctest --test-dir build-debug --output-on-failure
./build-debug/tracetrust_tests

cmake -S . -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --parallel 2
ctest --test-dir build-release --output-on-failure

cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DTRACETRUST_SANITIZERS=ON
cmake --build build-asan --parallel 2
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 ctest --test-dir build-asan --output-on-failure

clang-format --dry-run --Werror include/tracetrust/*.hpp src/*.cpp src/*/*.cpp tests/tests.cpp
cppcheck --project=build-debug/compile_commands.json --enable=warning,performance,portability \
  --inline-suppr --suppress=missingIncludeSystem '--suppress=*:*/third_party/*' \
  --error-exitcode=1 --max-configs=1
node --check dashboard/app.js
```

The browser/generator/benchmark commands used the same tooling environment's Python:

```bash
../tracetrust-tools/bin/python tools/generate_fixtures.py --output regenerated
diff -r examples/captures regenerated
PLAYWRIGHT_NODEJS_PATH="$(command -v node)" ../tracetrust-tools/bin/python tests/dashboard_test.py \
  --executable build-release/tracetrust --screenshots docs/screenshots \
  --large-report reports/benchmark-final/run-50000-1/index.html
../tracetrust-tools/bin/python tools/benchmark.py \
  --executable build-release/tracetrust --output reports/benchmark-final
```

`PLAYWRIGHT_NODEJS_PATH` selected the environment's executable Node binary. It is
not needed on a normal Playwright installation. The first browser download endpoint
returned an invalid archive; Playwright's official fallback downloaded the tested
Chromium build. The test itself used no HTTP(S) requests.

## Failures discovered and resolved

- A mutation-test assertion incorrectly expected the corrupted capture to retain
  at most the seed's three records. Mutating a record length can expose additional
  syntactically valid zero-byte records. The test now checks the correct invariants:
  record bounds, no overlap, contiguous offsets and report count consistency.
- Protocol review added family-specific ICMP dispatch and an AH minimum-length
  check, with regression cases for those paths and extension-count boundaries.
- Configuration parsing was tightened to reject trailing JSON garbage and to
  bound the actual read, not only a preceding file-size observation.
- Visual review removed artificial nonzero bars from empty timeline intervals.
- Cppcheck identified an unnecessary by-value test-helper configuration parameter;
  it now takes a const reference. Vendor diagnostics are explicitly out of scope.

## Verification limits

The initial sanitizer run failed during **LeakSanitizer runtime initialization**:
it could not inspect `/proc/.../task` in this environment and reported that its
thread scan cannot work under the host's tracing restrictions. Re-running with
`ASAN_OPTIONS=detect_leaks=0` allowed address/undefined-behavior checks to complete.
Memory leak freedom is **not verified**. CI keeps leak detection enabled on a
normal runner; that hosted execution remains unverified until the repository is
published and its workflow runs.

TShark and Zeek were unavailable, so the optional comparative experiment was not
performed. The Python fixture dependency's initial Scapy approach attempted local
interface discovery during import and was replaced with dpkt's offline byte
construction. No network capture or packet transmission was performed.

The seeded mutation loop is finite, has no coverage instrumentation and cannot
establish universal parser safety. Checksums, resource-record semantics, hostile
parent-directory races, crash/power-loss atomicity, platform portability and
real-world detector accuracy remain outside verified scope.
