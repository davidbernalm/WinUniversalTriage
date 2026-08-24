' ==============================================================================
' Copyright (C) 2015 David Bernal
'
' This program is free software: you can redistribute it and/or modify
' it under the terms of the GNU General Public License as published by
' the Free Software Foundation, either version 3 of the License, or
' any later version.
'
' This program is distributed in the hope that it will be useful,
' but WITHOUT ANY WARRANTY; without even the implied warranty of
' MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
' GNU General Public License for more details.
'
' You should have received a copy of the GNU General Public License
' along with this program. If not, see <https://www.gnu.org/licenses/>.

' ENHANCED DFIR TRIAGE COLLECTOR (Windows Server 2003 to WIN 11 Compatible)
' Native VBScript execution via cscript.exe with RawCopy & WinPmem integration
'
' AUTHOR: David Bernal
' CREATED: April 19, 2015
' MODIFIED: August 22, 2026

' Tested On
' Windows Server 2003 x86 1 GB
' Windows Server 2003 x64 1 GB
' Windows XP 500MB
' Windows Server 2008 x64 2 GB
' Windows Server 2022 x64 8 GB
' Windows 11 64 and 32 GB


WinUniversalTriage project started in 2015, when I worked for a large global company and I needed a script that would support ancient systems,
therefore I coded it in VBS script. At the time it used sleuthkit to copy locked files, but I replaced it with RawCopy to copy locked files, 
as this tool supports event older systems. I have recently enhanced it during my weekends in my free time, it is in active development,
albeit only in my time (outside of my regular job). 


allow to collect forensic relevant triage files in a diversity of Windows systems (tested from Win 2003/XP to Windows 11) having minimal dependencies and providing
a detailed audit log file of the actions performed.

DEPENDENCIES:
[RawFileCopy](https://github.com/jschicht/RawCopy) To copy OS locked files, like $MFT and registry hives
[Winpmem](https://github.com/Velocidex/WinPmem) to dump system memory, Windows OS 10 and above use the signed version of winpmem to avoid any BSOD

TODO:
Collect Amcache hive and $MFT of all system drives.
