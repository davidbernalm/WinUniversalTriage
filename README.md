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

- **Order of Volatility Collection:** Designed to respect RFC 3227 standards, prioritizing ephemeral state and volatile memory capture before disk and persistent artifact acquisition.
- **Comprehensive Audit Log:** Generates a detailed, timestamped log of all script executions, external tool invocations, and collected artifacts for forensic integrity and chain of custody.
- **Wide OS Coverage:** Runs seamlessly from legacy (Windows XP / Server 2003) to modern systems (Windows 11 / Server 2022).
- **Minimal Footprint:** Native VBScript execution minimizes changes to volatile memory and host state.
- **Locked File Extraction:** Leverages raw disk parsing to retrieve locked files (`$MFT`, active Registry hives, event logs).
- **Volatile Memory Capture:** Integrated support for physical memory acquisition via `WinPmem`.

---

## Usage

Run the collector from an elevated command prompt (`Administrator`):

---

```cmd
cscript.exe //NoLogo WinUniversalTriage.vbs
```

---

## Disclaimer
While limited testing has been done in a combination of test and production Windows hosts, it is ultimately your responsibility to test this script for your environment and verify it fits your requirements.

## Project History
Author & Copyright: David Bernal (Copyright © 2015–Present).

Origin & Provenance: The foundational codebase of this project was created in 2015 while working at global SOC for a large company, where authorization was granted upon departure for the author to retain, develop, and maintain the original code independently.

Personal Development & Scope: All subsequent design, enhancements, bug fixes, and ongoing maintenance are carried out strictly as an independent open-source project during personal free time (weekends/off-hours), using exclusively personal resources, equipment, and private environments.

Employer Disclaimer: This project is entirely personal and is not affiliated with, endorsed by, sponsored by, or reflective of any past, current, or future employer.

## TODO
Amcache.hve collection
$MFT collection from all local drives (Only C is currently supported).
Hashing and compression, if a modern OS is present

## Output Structure

All extracted artifacts, logs, and memory dumps are automatically saved in the script's root execution path under a central `Triage_Output` directory using a dedicated, timestamped subfolder:

```text
WinUniversalTriage/
├── WinUniversalTriage.vbs
├── RawCopy.exe
├── RawCopy.au3
├── winpmem.exe
├── go-winpmem_amd64_1.0-rc2_signed.exe
└── Triage_Output/
    └── <HOSTNAME>_<LOCAL DATE>/
        ├── triage_audit.txt
        ├── FORENSIC_ARTIFACT_SUBFOLDERS
```

