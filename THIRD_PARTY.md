# Bundled component: ByeDPI 0.17.3

Source: https://github.com/hufrea/byedpi/tree/v0.17.3

Release: https://github.com/hufrea/byedpi/releases/tag/v0.17.3

The installer downloads the official Windows executable and verifies pinned
SHA-256 hashes of both its release archive and executable. No upstream service
scripts are installed or executed. Pathfinder manages loopback SOCKS workers.
ByeDPI is a separate project and is not authored by Pathfinder.

## License

MIT License

Copyright (c) 2024 hufrea

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

# Optional packet component: zapret2 / winws2

Source: https://github.com/bol-van/zapret2

Pinned Windows bundle:
https://github.com/bol-van/zapret-win-bundle/tree/bb6a20af35ed74778eb669f5413990eb8209c711

The Windows x64 installer downloads `winws2.exe`, its two runtime libraries,
the WinDivert driver, and two upstream Lua libraries directly from that pinned
bundle. Every file is verified against the SHA-256 digest in
`pathfinder/packet_manifest.json`; no upstream batch files, services, elevation
helpers, or Windows protection settings are installed or executed. These files
are used only when the user starts packet mode. Downloading a driver file does
not load it. The separate packet mode needs administrator access to WinDivert.

Pathfinder supplies the controller, selection logic and user interface;
zapret2 and its contributors supply the packet processing implementation.

## zapret2 license

Upstream license: https://github.com/bol-van/zapret2/blob/master/docs/LICENSE.txt

MIT License

Copyright (c) 2016-2026 bol-van

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

## WinDivert

`WinDivert.dll` and `WinDivert64.sys` are independent WinDivert components,
provided under the GNU Lesser General Public License version 3. Their license
is separate from Pathfinder's and zapret2's MIT licenses. Source, copyright
notices, and complete license text:

- https://github.com/basil00/WinDivert
- https://github.com/basil00/WinDivert/blob/master/LICENSE
- https://github.com/basil00/WinDivert/blob/master/README

## Cygwin runtime

`cygwin1.dll` is the independent Cygwin API library. Cygwin's published terms
cover this library under the GNU Lesser General Public License version 3 or
later, with the Cygwin linking exception. Source, full terms and the linking
exception:

- https://cygwin.com/licensing.html
- https://cygwin.com/git.html
- https://cygwin.com/COPYING.LIB

The installer downloads these unmodified upstream dependencies; no dependency
executables or drivers are stored in the Pathfinder Git repository. The
upstream source and licensing terms remain applicable to those components.
