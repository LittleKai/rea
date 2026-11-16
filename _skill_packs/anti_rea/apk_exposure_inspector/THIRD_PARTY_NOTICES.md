# Third-party notices

de-REA project code is Apache-2.0. That license does not replace licenses for development tools, external coding agents, analysis engines, operating-system packages, or container distributions.

## JavaScript development dependencies

The committed npm lockfile fixes the installed versions and integrity values. There are no production npm dependencies in this release candidate.

| Component                                          | Version | License                                     |
| -------------------------------------------------- | ------- | ------------------------------------------- |
| TypeScript                                         | 5.9.3   | Apache-2.0; Microsoft Corporation           |
| `@types/node`                                      | 24.10.0 | MIT; Microsoft Corporation                  |
| `undici-types` (transitive development dependency) | 7.16.0  | MIT; Matteo Collina and Undici contributors |

TypeScript's applicable license accompanies its installed package; the standard Apache-2.0 text is also in this repository's `LICENSE`. Its distribution can include its own additional notices; retain those when redistributing that tool.

## External analysis and execution tools

| Component                     | Selected version                                                      | License / boundary                                                                               |
| ----------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| REA (`rea-agents`)            | 6.7.0                                                                 | MIT, Copyright (c) 2026 morluto; external tool image, not the autonomous agent runner            |
| Ghidra                        | 12.1.4                                                                | Apache-2.0 with bundled third-party licenses/notices; retain the complete distribution's notices |
| Codex CLI                     | Inspected 0.163.0                                                     | External optional runner; not bundled in the npm package; upstream software/provider terms apply |
| Node.js                       | App development 24.22.1; REA image 24.11.0                            | MIT with bundled third-party notices                                                             |
| GCC / binutils                | Tool-image package versions                                           | GPL-family licenses and applicable runtime exceptions; separate toolchain components             |
| musl                          | Tool-image package version                                            | MIT                                                                                              |
| Python                        | Tool-image package version                                            | Python Software Foundation license and distribution notices                                      |
| OpenJDK                       | JDK21 in the REA image                                                | GPLv2 with Classpath Exception and bundled notices                                               |
| Terser                        | 5.44.1                                                                | BSD-2-Clause; explicit offline web-hardening tool image, not an npm runtime dependency           |
| Acorn and Terser dependencies | Locked in `containers/web-hardening.package-lock.json`                | Each package retains its bundled license; not relicensed by de-REA                               |
| Android `apksigner`           | Owner-provided Android SDK Build Tools 35.0.0 in the local acceptance | Android SDK terms and Apache-2.0 tool notices; not bundled in the npm package                    |
| Alpine / Debian packages      | Image manifests and recorded package identities                       | Each package retains its own license                                                             |

Container recipes pin base-image identities; installed system-package identities and execution-image IDs are separate evidence. An image digest is not a substitute for satisfying redistribution obligations. Consult the tool distribution's own `LICENSE`, `NOTICE`, `licenses/`, `/usr/share/licenses`, or `/usr/share/doc` as applicable. REA's own third-party notices cover its dependency graph; this short inventory is not a relicense of that graph. See upstream `docs/compatibility.md` in `zhcalvin/DeRea@7d4917b4` for upstream identities and evidence.

## IP, PLEASE case study

The owner authorized use of the public [IP, PLEASE Mobile](https://github.com/zhcalvin/ip-please-mobile) source and this local APK example. Original game code and assets retain `Copyright (c) 2026 ctnyanya` and the project's MIT license. Mobile adaptation is attributed to that repository. Fusion Pixel font assets retain SIL Open Font License 1.1. The hardening profile preserves the APK's `assets/LICENSE` and `assets/OFL-fusion-pixel.txt` byte-for-byte. Reports and README diagrams summarize measurements; they do not relicense the original game, font, or APK.

## MIT text for the named MIT components

The following copyright notices apply to their respective components above:

```text
@types/node: Copyright (c) Microsoft Corporation.
undici-types: Copyright (c) Matteo Collina and Undici contributors
REA: Copyright (c) 2026 morluto

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
