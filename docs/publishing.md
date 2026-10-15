# Publishing this source repository

Nothing was committed, pushed, deployed or created on GitHub by this implementation.
The intended repository name is `tracetrust-network-forensics`.

1. Unpack the source archive and read `README.md` plus `docs/validation.md`.
2. Keep the included synthetic captures and example report. Do not add private
   PCAPs, local investigation reports, credentials or unrelated workspace files.
3. Create an empty GitHub repository with the intended name in your own account.
4. Publish the unpacked project root, including `.github/workflows/ci.yml`,
   `.gitignore`, `.clang-format`, `third_party/` and its license. GitHub Desktop or
   git can upload the complete tree; do not upload the ZIP as the repository's only
   source file. Build directories and local tools are intentionally excluded.
5. Check the Actions result after the first push. The workflow exists, but no
   remote green status should be claimed until that actual run passes.
6. Use the real dashboard screenshot and sample report when describing the project.
   Explain its assumptions and what you tested; do not describe threshold rules as
   trained threat intelligence or this project as a validated forensic product.

For a portfolio demonstration on any computer, the supplied HTML report can be
opened locally. Building/running the CLI currently requires 64-bit Linux. A native
macOS build is future work, not part of the delivered support claim.
