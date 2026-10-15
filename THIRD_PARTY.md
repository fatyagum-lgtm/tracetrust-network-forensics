# Third-party components

| Component | Version in this source distribution | Use | License |
| --- | --- | --- | --- |
| nlohmann/json | 3.12.0 | JSON configuration and serialization; vendored unmodified headers | MIT; `third_party/nlohmann-LICENSE` |
| OpenSSL libcrypto | System library, 3.0 or later required; validated with 3.0.13 | EVP SHA-256 | Apache-2.0; not redistributed here |
| dpkt | 1.9.8, optional Python development tool | Synthetic packet construction and checksums | BSD-3-Clause; not vendored |
| Playwright | 1.51.0, optional Python development tool | Local Chromium UI tests and real screenshots | Apache-2.0; not vendored |
| clang-format | 18.1.8, optional development tool | C++ formatting | Apache-2.0 with LLVM exceptions; not vendored |

The nlohmann headers were obtained from the `nlohmann_json==3.12.0` Python
distribution's `include/nlohmann` directory. Its upstream project is
https://github.com/nlohmann/json. CMake uses the committed headers, with no
network fetch at configure or build time. Optional development tools are not
part of the analysis engine or required to open generated HTML.

The repository contains no external fonts, CDN scripts, tracking code, real
network captures, or third-party image assets. Screenshots show the local app
running against the committed synthetic capture.
