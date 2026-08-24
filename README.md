# WinUniversalTriage

> **Universal Windows DFIR Triage & Live Response Tool**  
> Native VBScript execution via `cscript.exe` with `RawCopy` & `WinPmem` integration.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Platform](https://img.shields.io/badge/Platform-Windows%20XP%20to%2011%20%2F%202003%20to%202022-brightgreen.svg)]()

---

## Overview

**WinUniversalTriage** is a lightweight, battle-tested forensic triage collector written in VBScript. It collects forensically relevant artifacts across a wide spectrum of Windows architectures with **minimal dependencies**, generating a comprehensive audit log of every action taken during the collection process.

The project originated in 2015 to solve the challenge of collecting evidence from legacy Windows environments where modern collectors fail or cannot run. While originally relying on The Sleuth Kit, it now integrates `RawCopy` to extract locked forensic artifacts across both legacy and modern platforms.

---

## Key Features
- **Wide OS Coverage:** Runs seamlessly from legacy (Windows XP / Server 2003) to modern systems (Windows 11 / Server 2022).
- **Order of Volatility Collection:** Designed to respect RFC 3227 standards, prioritizing ephemeral state and volatile memory capture before disk and persistent artifact acquisition.
- **Comprehensive Audit Log:** Generates a detailed, timestamped log of all script executions, external tool invocations, and collected artifacts for forensic integrity and chain of custody.
- **Minimal Footprint:** Native VBScript execution minimizes changes to volatile memory and host state.
- **Locked File Extraction:** Leverages raw disk parsing to retrieve locked files (`$MFT`, active Registry hives).
- **Volatile Memory Capture:** Integrated support for physical memory acquisition via `WinPmem` using the signed version for Win 10 and above

---

## Tested Environments

| Operating System | Architecture | RAM |
| :--- | :--- | :--- |
| **Windows XP** | x86 | 512 MB |
| **Windows Server 2003** | x86 / x64 | 1 GB |
| **Windows Server 2008** | x64 | 2 GB |
| **Windows Server 2022** | x64 | 8 GB |
| **Windows 11** | x64 | 32 GB / 64 GB |

---

## Dependencies

Place the corresponding binaries alongside the script or within your execution path:

- **[RawFileCopy](https://github.com/jschicht/RawCopy):** Used to bypass file system locks on critical forensic artifacts (e.g., active Registry hives, `$MFT`).
- **[WinPmem](https://github.com/Velocidex/WinPmem):** Used for physical memory acquisition.  
  > *Note: For Windows 10/11 and modern Server releases, always use the signed driver version to prevent BSOD or driver blocklist issues.*

---

## Usage

Run the collector from an elevated command prompt (`Administrator`):

```cmd
cscript.exe //NoLogo WinUniversalTriage.vbs
