# Third-party notices

OpenReverse uses the following third-party components. Their licenses apply to
those components independently of the OpenReverse MIT License.

## Build dependencies

- [Dear ImGui](https://github.com/ocornut/imgui), pinned by commit in
  `CMakeLists.txt` — MIT License.
- [Capstone](https://github.com/capstone-engine/capstone) 5.0.1 — BSD 3-Clause
  License.
- [nlohmann/json](https://github.com/nlohmann/json) 3.11.3 — MIT License.

CMake downloads these sources into the local build tree; they are not vendored
in this repository.

## Vendored source

`src/ui/vendor/TextEditor.*` is derived from
[ImGuiColorTextEdit](https://github.com/BalazsJako/ImGuiColorTextEdit).

MIT License

Copyright (c) 2017 BalazsJako

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Embedded font

`src/ui/embedded_font.h` is generated from Roboto Medium and is retained so the
desktop build is self-contained. Roboto is Copyright 2011 The Roboto Project
Authors and is distributed under the
[Apache License 2.0](third_party/licenses/Roboto.LICENSE.txt).
