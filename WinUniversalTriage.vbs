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
' Windows Server 2003 x86
' Windows Server 2008 x64
' Windows XP
' Windows Server 2008 x64
' Windows 11

' ==============================================================================
On Error Resume Next

' ==============================================================================
' COLLECTION TOGGLES (ENABLE / DISABLE ARTIFACT SECTIONS)
' ==============================================================================
Const ENABLE_RAM_ACQUISITION    = False
Const ENABLE_VOLATILE_STATE     = True
Const ENABLE_PROCESS_BINARIES   = True
Const ENABLE_NTFS_METADATA      = True
Const ENABLE_SYSTEM_REGISTRY    = True
Const ENABLE_EVENT_LOGS         = True
Const ENABLE_PREFETCH           = True
Const ENABLE_SCHEDULED_TASKS    = True
Const ENABLE_NETWORK_CONFIGS    = True
Const ENABLE_LogFiles           = True
Const ENABLE_USER_HIVES         = True
Const ENABLE_USER_RECENT_LNK    = True
Const ENABLE_BROWSER_HISTORY    = True

' ==============================================================================
' INITIALIZATION & CORE VARIABLES
' ==============================================================================
Const HKEY_LOCAL_MACHINE = &H80000002
Const HKEY_USERS         = &H80000003

Dim objFSO, objShell, objNetwork, objWMIService, objReg
Dim strComputer, strComputerName, strScriptDir, strDestLog, strWinDir, strSystemDrive
Dim objHashDictionary, is64BitOS

Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objShell = CreateObject("WScript.Shell")
Set objNetwork = CreateObject("WScript.Network")

strComputer = "."
strComputerName = objNetwork.ComputerName
strWinDir = objShell.ExpandEnvironmentStrings("%WINDIR%")
strSystemDrive = objShell.ExpandEnvironmentStrings("%SystemDrive%")

' Determine script directory
strScriptDir = objFSO.GetParentFolderName(WScript.ScriptFullName)

Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
Set objReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root:default:StdRegProv")

Set objHashDictionary = CreateObject("Scripting.Dictionary")

' Detect actual OS Architecture (32-bit vs 64-bit)
is64BitOS = False
Dim colProc, objProcItem
Set colProc = objWMIService.ExecQuery("SELECT AddressWidth FROM Win32_Processor")
For Each objProcItem In colProc
    If objProcItem.AddressWidth = 64 Then is64BitOS = True
Next

' Check environment architecture fallback (PROCESSOR_ARCHITECTURE)
Dim strProcArch
strProcArch = objShell.ExpandEnvironmentStrings("%PROCESSOR_ARCHITECTURE%")
If InStr(LCase(strProcArch), "64") > 0 Then is64BitOS = True

' Initialize output directory structure
Dim strTimestamp
strTimestamp = Replace(Replace(Replace(Now(), ":", "-"), "/", "-"), " ", "_")
strDestLog = strScriptDir & "\Triage_Output\" & strComputerName & "_" & strTimestamp

CreateFolderIfMissing strScriptDir & "\Triage_Output"
CreateFolderIfMissing strDestLog
If ENABLE_SYSTEM_REGISTRY Or ENABLE_USER_HIVES Then CreateFolderIfMissing strDestLog & "\Registry"
If ENABLE_USER_HIVES Or ENABLE_USER_RECENT_LNK Then CreateFolderIfMissing strDestLog & "\Registry\Users"
If ENABLE_EVENT_LOGS Then CreateFolderIfMissing strDestLog & "\EventLogs"
If ENABLE_NTFS_METADATA Then CreateFolderIfMissing strDestLog & "\NTFS"
If ENABLE_VOLATILE_STATE Or ENABLE_PROCESS_BINARIES Then CreateFolderIfMissing strDestLog & "\LiveOutput"
If ENABLE_PROCESS_BINARIES Then CreateFolderIfMissing strDestLog & "\LiveOutput\Process_Binaries"
If ENABLE_RAM_ACQUISITION Then CreateFolderIfMissing strDestLog & "\Memory"
If ENABLE_PREFETCH Then CreateFolderIfMissing strDestLog & "\Prefetch"
If ENABLE_SCHEDULED_TASKS Then CreateFolderIfMissing strDestLog & "\Tasks"
If ENABLE_NETWORK_CONFIGS Then CreateFolderIfMissing strDestLog & "\Network_Configs"
If ENABLE_LogFiles Then CreateFolderIfMissing strDestLog & "\LogFiles"
If ENABLE_BROWSER_HISTORY Then CreateFolderIfMissing strDestLog & "\BrowserHistory"

' Initialize master audit log file
Dim objLogFile
Set objLogFile = objFSO.CreateTextFile(strDestLog & "\triage_audit.log", True)
LogMessage "=== Starting Triage Collection on " & strComputerName & " ==="
LogMessage "Execution Directory: " & strScriptDir
LogMessage "Output Destination:  " & strDestLog

' ------------------------------------------------------------------------------
' 1. DYNAMIC OS DETECTION & PHYSICAL MEMORY DUMP
' ------------------------------------------------------------------------------
Dim colOS, objOSItem, strOSVersion, strPmemBinary, strPmemPath, strPmemCmd
Dim arrVer, intMajorVer

Set colOS = objWMIService.ExecQuery("SELECT Version FROM Win32_OperatingSystem")
For Each objOSItem In colOS
    strOSVersion = objOSItem.Version
Next

LogMessage "Detected OS Kernel Version: " & strOSVersion & " (64-bit Architecture: " & CStr(is64BitOS) & ")"

If ENABLE_RAM_ACQUISITION Then
    LogMessage vbCrLf & "--- SECTION 1: PHYSICAL MEMORY ACQUISITION ---"

    ' Parse major version number (e.g., "10.0.22631" -> 10, "6.3.9600" -> 6, "5.2.3790" -> 5)
    intMajorVer = 0
    arrVer = Split(strOSVersion, ".")
    If UBound(arrVer) >= 0 Then
        intMajorVer = CInt(arrVer(0))
    End If

    ' Windows 10, Windows 11, Server 2016+ (Kernel NT 10.0+) require signed Go-WinPmem for Driver Signature Enforcement / HVCI
    ' Windows 8.1, Server 2012 R2 and earlier (Kernel NT <= 6.3) use WinPmem 1.6.2
    If intMajorVer >= 10 Then
        strPmemBinary = "go-winpmem_amd64_1.0-rc2_signed.exe"
        LogMessage "Windows 10 / 11 / Server 2016+ detected (NT " & strOSVersion & "). Selecting signed Go-WinPmem..."
    Else
        strPmemBinary = "winpmem_1.6.2.exe"
        LogMessage "Windows 8.1 / Server 2012 R2 or earlier detected (NT " & strOSVersion & "). Selecting WinPmem 1.6.2..."
    End If

    strPmemPath = strScriptDir & "\" & strPmemBinary

    If objFSO.FileExists(strPmemPath) Then
        If strPmemBinary = "go-winpmem_amd64_1.0-rc2_signed.exe" Then
            strPmemCmd = """" & strPmemPath & """ acquire """ & strDestLog & "\Memory\RAM_memory.raw"""
        Else
            strPmemCmd = """" & strPmemPath & """ """ & strDestLog & "\Memory\RAM_memory.raw"""
        End If
        
        LogMessage "Executing Command: " & strPmemCmd
        objShell.Run strPmemCmd, 1, True
        LogMessage "Memory dump completed."
    Else
        LogMessage "WARNING: " & strPmemBinary & " not found in script directory. Skipping RAM acquisition."
    End If
End If

' ------------------------------------------------------------------------------
' 2. VOLATILE SYSTEM STATE COMMANDS & WMIC
' ------------------------------------------------------------------------------
If ENABLE_VOLATILE_STATE Then
    LogMessage vbCrLf & "--- SECTION 2: VOLATILE SYSTEM STATE & WMIC DATA ---"

    ' Network state, sockets, and routing tables
    ExecuteAndLog "ipconfig /all", strDestLog & "\LiveOutput\ipconfig_all.txt"
    ExecuteAndLog "ipconfig /displaydns", strDestLog & "\LiveOutput\dns_cache.txt"
    ExecuteAndLog "netstat -nao", strDestLog & "\LiveOutput\netstat_nao.txt"
    ExecuteAndLog "netstat -nabo", strDestLog & "\LiveOutput\netstat_nabo.txt"
    ExecuteAndLog "netstat -r", strDestLog & "\LiveOutput\routing_table.txt"
    ExecuteAndLog "netstat -s", strDestLog & "\LiveOutput\network_statistics.txt"
    ExecuteAndLog "nbtstat -c", strDestLog & "\LiveOutput\netbios_cache.txt"
    ExecuteAndLog "nbtstat -S", strDestLog & "\LiveOutput\netbios_sessions.txt"
    ExecuteAndLog "arp -a", strDestLog & "\LiveOutput\arp_table.txt"

    ' CLI process, module, and scheduled task listings
    ExecuteAndLog "tasklist /v /fo csv", strDestLog & "\LiveOutput\tasklist_verbose.csv"
    ExecuteAndLog "tasklist /svc /fo csv", strDestLog & "\LiveOutput\tasklist_services.csv"
    ExecuteAndLog "tasklist /m /fo csv", strDestLog & "\LiveOutput\tasklist_modules.csv"
    ExecuteAndLog "schtasks /query /v /fo csv", strDestLog & "\LiveOutput\scheduled_tasks.csv"

    ' WMIC structured inventory
    ExecuteAndLog "wmic process list full /format:csv", strDestLog & "\LiveOutput\wmic_process_list_full.csv"
    ExecuteAndLog "wmic process get Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine /format:csv", strDestLog & "\LiveOutput\wmic_process_summary.csv"
    ExecuteAndLog "wmic startup list full /format:csv", strDestLog & "\LiveOutput\wmic_startup.csv"
    ExecuteAndLog "wmic service get Name, DisplayName, PathName, StartMode, State /format:csv", strDestLog & "\LiveOutput\wmic_services.csv"
    ExecuteAndLog "wmic job list full /format:csv", strDestLog & "\LiveOutput\wmic_scheduled_jobs.csv"
    ExecuteAndLog "wmic nicconfig where IPEnabled=TRUE get Caption, IPAddress, MACAddress, DefaultIPGateway /format:csv", strDestLog & "\LiveOutput\wmic_nicconfig.csv"
    ExecuteAndLog "wmic loggedonuser get Antecedent, Dependent /format:csv", strDestLog & "\LiveOutput\wmic_loggedonuser.csv"
    ExecuteAndLog "wmic qfe list full /format:csv", strDestLog & "\LiveOutput\wmic_patches_qfe.csv"

    ' Sessions, shares, and local accounts
    ExecuteAndLog "qwinsta", strDestLog & "\LiveOutput\rdp_sessions.txt"
    ExecuteAndLog "net session", strDestLog & "\LiveOutput\net_sessions.txt"
    ExecuteAndLog "net use", strDestLog & "\LiveOutput\net_mapped_drives.txt"
    ExecuteAndLog "net share", strDestLog & "\LiveOutput\net_shares.txt"
    ExecuteAndLog "net file", strDestLog & "\LiveOutput\net_open_files.txt"
    ExecuteAndLog "net user", strDestLog & "\LiveOutput\local_users.txt"
    ExecuteAndLog "net localgroup administrators", strDestLog & "\LiveOutput\local_admins.txt"

    ' Service state and active drivers
    ExecuteAndLog "sc query state= all", strDestLog & "\LiveOutput\services_all.txt"
    ExecuteAndLog "driverquery /v /fo csv", strDestLog & "\LiveOutput\loaded_drivers.csv"

    ' Environment variables and staging directory metadata
    ExecuteAndLog "set", strDestLog & "\LiveOutput\environment_variables.txt"
    ExecuteAndLog "dir /O:D /T:W %WINDIR%\Prefetch", strDestLog & "\LiveOutput\prefetch_dir_write.txt"
    ExecuteAndLog "dir /O:D /T:C %WINDIR%\Prefetch", strDestLog & "\LiveOutput\prefetch_dir_create.txt"
    ExecuteAndLog "dir /O:D /T:W %TEMP%", strDestLog & "\LiveOutput\temp_dir_write.txt"
    ExecuteAndLog "dir /O:D /T:W %WINDIR%\Temp", strDestLog & "\LiveOutput\windir_temp_write.txt"
End If

' ------------------------------------------------------------------------------
' 3. PROCESS ENUMERATION & BINARY EXTRACTION
' ------------------------------------------------------------------------------
If ENABLE_PROCESS_BINARIES Then
    LogMessage vbCrLf & "--- SECTION 3: PROCESS ENUMERATION & BINARY STAGING ---"
    LogMessage "Executing WMI Query: SELECT * FROM Win32_Process"
    Dim colProcesses, objProcess, strRawPath, strCleanPath, strProcName, strDestProcDir, strTargetFile

    strDestProcDir = strDestLog & "\LiveOutput\Process_Binaries"
    Set colProcesses = objWMIService.ExecQuery("SELECT * FROM Win32_Process")

    objLogFile.WriteLine vbCrLf & "--- RUNNING PROCESSES (WMI ENUMERATION) ---"
    For Each objProcess In colProcesses
        objLogFile.WriteLine "PID: " & objProcess.ProcessId & " | Parent PID: " & objProcess.ParentProcessId
        objLogFile.WriteLine "Name: " & objProcess.Name
        objLogFile.WriteLine "Path: " & objProcess.ExecutablePath
        objLogFile.WriteLine "CLI:  " & objProcess.CommandLine
        
        strRawPath = ""
        If Not IsNull(objProcess.ExecutablePath) Then
            strRawPath = objProcess.ExecutablePath
        ElseIf Not IsNull(objProcess.CommandLine) Then
            strRawPath = objProcess.CommandLine
        End If
        
        If strRawPath <> "" Then
            strCleanPath = CleanProcessPath(strRawPath)
            
            If strCleanPath <> "" And objFSO.FileExists(strCleanPath) Then
                ' Avoid copying identical binaries multiple times
                If Not objHashDictionary.Exists(LCase(strCleanPath)) Then
                    objHashDictionary.Add LCase(strCleanPath), "COLLECTED"
                    
                    strProcName = objFSO.GetFileName(strCleanPath)
                    strTargetFile = strDestProcDir & "\" & objProcess.ProcessId & "_" & strProcName
                    
                    On Error Resume Next
                    objFSO.CopyFile strCleanPath, strTargetFile, True
                    
                    ' Fallback to RawCopy if standard copy fails due to file locks
                    If Err.Number <> 0 Then
                        Err.Clear
                        LogMessage "File locked by OS. Attempting RawCopy fallback for: " & strCleanPath
                        CopyLockedFile strCleanPath, strTargetFile
                    Else
                        LogMessage "Standard Copy Succeeded: " & strCleanPath & " -> " & strTargetFile
                    End If
                    
                    objLogFile.WriteLine "Binary Staged: " & strTargetFile
                Else
                    objLogFile.WriteLine "Binary Staged: Already collected from path"
                End If
            Else
                objLogFile.WriteLine "Binary Staged: Unable to resolve file on disk (" & strCleanPath & ")"
            End If
        End If
        objLogFile.WriteLine "--------------------------------------------------"
    Next
End If

' ------------------------------------------------------------------------------
' 4. LOW-LEVEL FORENSIC EXTRACTION VIA RAWCOPY & STANDARD COPY
' ------------------------------------------------------------------------------
LogMessage vbCrLf & "--- SECTION 4: LOW-LEVEL ARTIFACT EXTRACTION VIA RAWCOPY & STANDARD COPY ---"

' Extract core NTFS metadata
If ENABLE_NTFS_METADATA Then
    CopyLockedFile strSystemDrive & "\$MFT", strDestLog & "\NTFS\$MFT"
    CopyLockedFile strSystemDrive & "\$LogFile", strDestLog & "\NTFS\$LogFile"
End If

' Extract core system registry hives (System hives are always locked by kernel)
If ENABLE_SYSTEM_REGISTRY Then
    SafeExtractHive strWinDir & "\System32\config\SAM", strDestLog & "\Registry\SAM", "SAM"
    SafeExtractHive strWinDir & "\System32\config\SOFTWARE", strDestLog & "\Registry\SOFTWARE", "SOFTWARE"
    SafeExtractHive strWinDir & "\System32\config\SYSTEM", strDestLog & "\Registry\SYSTEM", "SYSTEM"
    SafeExtractHive strWinDir & "\System32\config\SECURITY", strDestLog & "\Registry\SECURITY", "SECURITY"
End If

' Extract Windows Event Logs (Legacy .evt via RawCopy vs Modern .evtx via Standard Copy)
If ENABLE_EVENT_LOGS Then
    If Left(strOSVersion, 3) = "5.2" Or Left(strOSVersion, 3) = "5.1" Then
        ' Legacy Event Logs (.evt for Windows Server 2003 / XP) - Locked by EventLog service
        LogMessage "Collecting Legacy Event Logs (.evt) via RawCopy..."
        If objFSO.FolderExists(strWinDir & "\System32\config") Then
            SafeExtractHive strWinDir & "\System32\config\SysEvent.Evt", strDestLog & "\EventLogs\SysEvent.Evt", "SysEvent.Evt"
            SafeExtractHive strWinDir & "\System32\config\AppEvent.Evt", strDestLog & "\EventLogs\AppEvent.Evt", "AppEvent.Evt"
            SafeExtractHive strWinDir & "\System32\config\SecEvent.Evt", strDestLog & "\EventLogs\SecEvent.Evt", "SecEvent.Evt"
        End If
    Else
        ' Modern Event Logs (.evtx for Windows Vista / 7 / 8 / 10 / 11 / Server 2008+) - Unlocked, Standard Copy
        LogMessage "Collecting Modern Event Logs (.evtx) via Standard Copy from C:\Windows\System32\winevt\Logs..."
        Dim strEvtxFolder
        strEvtxFolder = strWinDir & "\System32\winevt\Logs"
        
        If objFSO.FolderExists(strEvtxFolder) Then
            On Error Resume Next
            objFSO.CopyFile strEvtxFolder & "\*.evtx", strDestLog & "\EventLogs\", True
            If Err.Number = 0 Then
                LogMessage "Standard Copy Succeeded: " & strEvtxFolder & "\*.evtx -> " & strDestLog & "\EventLogs\"
            Else
                LogMessage "Standard Copy encountered issues (" & Err.Description & "). Falling back to per-file copy..."
                Err.Clear
                Dim objEvtxFolder, objEvtxFile
                Set objEvtxFolder = objFSO.GetFolder(strEvtxFolder)
                For Each objEvtxFile In objEvtxFolder.Files
                    If LCase(objFSO.GetExtensionName(objEvtxFile.Name)) = "evtx" Then
                        objFSO.CopyFile objEvtxFile.Path, strDestLog & "\EventLogs\" & objEvtxFile.Name, True
                    End If
                Next
            End If
        Else
            LogMessage "WARNING: winevt\Logs directory not found at " & strEvtxFolder
        End If
    End If
End If

' ------------------------------------------------------------------------------
' 5. EXECUTION & PERSISTENCE ARTIFACTS
' ------------------------------------------------------------------------------
LogMessage vbCrLf & "--- SECTION 5: EXECUTION & PERSISTENCE ARTIFACTS ---"

' Prefetch directory (.pf files)
If ENABLE_PREFETCH Then
    If objFSO.FolderExists(strWinDir & "\Prefetch") Then
        LogMessage "Copying Prefetch files: " & strWinDir & "\Prefetch\*.pf -> " & strDestLog & "\Prefetch\"
        objFSO.CopyFile strWinDir & "\Prefetch\*.pf", strDestLog & "\Prefetch\", True
    End If
End If

' Scheduled job files (.job and SA.DAT)
If ENABLE_SCHEDULED_TASKS Then
    If objFSO.FolderExists(strWinDir & "\Tasks") Then
        LogMessage "Copying Scheduled Jobs: " & strWinDir & "\Tasks\*.job -> " & strDestLog & "\Tasks\"
        objFSO.CopyFile strWinDir & "\Tasks\*.job", strDestLog & "\Tasks\", True
        If objFSO.FileExists(strWinDir & "\Tasks\SA.DAT") Then
            LogMessage "Copying Task Log: " & strWinDir & "\Tasks\SA.DAT -> " & strDestLog & "\Tasks\"
            objFSO.CopyFile strWinDir & "\Tasks\SA.DAT", strDestLog & "\Tasks\", True
        End If
    End If
End If

' Static resolution files
If ENABLE_NETWORK_CONFIGS Then
    If objFSO.FileExists(strWinDir & "\System32\drivers\etc\hosts") Then
        LogMessage "Copying Hosts File: " & strWinDir & "\System32\drivers\etc\hosts -> " & strDestLog & "\Network_Configs\hosts.txt"
        objFSO.CopyFile strWinDir & "\System32\drivers\etc\hosts", strDestLog & "\Network_Configs\hosts.txt", True
    End If
    If objFSO.FileExists(strWinDir & "\System32\drivers\etc\lmhosts") Then
        LogMessage "Copying LMHosts File: " & strWinDir & "\System32\drivers\etc\lmhosts -> " & strDestLog & "\Network_Configs\lmhosts.txt"
        objFSO.CopyFile strWinDir & "\System32\drivers\etc\lmhosts", strDestLog & "\Network_Configs\lmhosts.txt", True
    End If
End If

' LogFiles Folder collection
If ENABLE_LogFiles Then
    If objFSO.FolderExists(strWinDir & "\System32\LogFiles") Then
        LogMessage "Copying LogFiles Directory: " & strWinDir & "\System32\LogFiles -> " & strDestLog & "\LogFiles"
        objFSO.CopyFolder strWinDir & "\System32\LogFiles", strDestLog & "\LogFiles"
    End If
End If

' ------------------------------------------------------------------------------
' 6. DYNAMIC USER PROFILE & REGISTRY HIVE EXTRACTION VIA SAFE EXTRACTION
' ------------------------------------------------------------------------------
If ENABLE_USER_HIVES Or ENABLE_USER_RECENT_LNK Or ENABLE_BROWSER_HISTORY Then
    LogMessage vbCrLf & "--- SECTION 6: USER PROFILES & REGISTRY HIVES (SAFE EXTRACTION) ---"
    Dim objProfilesDictionary, colUserProfiles, objUserProfileItem
    Dim strProfilePath, strUsername, strUserRegDir, strUserBrowserDir
    Dim strKeyPath, arrSubKeys, subkey, strProfileImagePath
    Dim strProfilesBase, objProfilesFolder, objSubFolder

    Set objProfilesDictionary = CreateObject("Scripting.Dictionary")

    ' Method 1: WMI Win32_UserProfile (Native and accurate for Windows Vista through Windows 11)
    Set colUserProfiles = objWMIService.ExecQuery("SELECT LocalPath, SID FROM Win32_UserProfile")
    For Each objUserProfileItem In colUserProfiles
        If Not IsNull(objUserProfileItem.LocalPath) And objUserProfileItem.LocalPath <> "" Then
            strProfilePath = Trim(objUserProfileItem.LocalPath)
            strUsername = objFSO.GetFileName(strProfilePath)
            
            ' Filter service accounts
            If LCase(strUsername) <> "localservice" And LCase(strUsername) <> "networkservice" And LCase(strUsername) <> "systemprofile" Then
                If Not objProfilesDictionary.Exists(LCase(strProfilePath)) Then
                    objProfilesDictionary.Add LCase(strProfilePath), strUsername
                End If
            End If
        End If
    Next

    ' Method 2: Registry ProfileList (Compatible with legacy Windows Server 2003 / XP & Fallback)
    strKeyPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    objReg.EnumKey HKEY_LOCAL_MACHINE, strKeyPath, arrSubKeys
    If IsArray(arrSubKeys) Then
        For Each subkey In arrSubKeys
            objReg.GetStringValue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey, "ProfileImagePath", strProfileImagePath
            If strProfileImagePath <> "" Then
                strProfileImagePath = objShell.ExpandEnvironmentStrings(strProfileImagePath)
                strUsername = objFSO.GetFileName(strProfileImagePath)
                If LCase(strUsername) <> "localservice" And LCase(strUsername) <> "networkservice" And LCase(strUsername) <> "systemprofile" Then
                    If Not objProfilesDictionary.Exists(LCase(strProfileImagePath)) Then
                        objProfilesDictionary.Add LCase(strProfileImagePath), strUsername
                    End If
                End If
            End If
        Next
    End If

    ' Method 3: Filesystem Directory Enumeration Fallback
    If objFSO.FolderExists(strSystemDrive & "\Documents and Settings") Then
        strProfilesBase = strSystemDrive & "\Documents and Settings"
    Else
        strProfilesBase = strSystemDrive & "\Users"
    End If

    If objFSO.FolderExists(strProfilesBase) Then
        Set objProfilesFolder = objFSO.GetFolder(strProfilesBase)
        For Each objSubFolder In objProfilesFolder.SubFolders
            strUsername = objSubFolder.Name
            If LCase(strUsername) <> "localservice" And LCase(strUsername) <> "networkservice" And LCase(strUsername) <> "public" And LCase(strUsername) <> "all users" And LCase(strUsername) <> "default" And LCase(strUsername) <> "default user" Then
                If Not objProfilesDictionary.Exists(LCase(objSubFolder.Path)) Then
                    objProfilesDictionary.Add LCase(objSubFolder.Path), strUsername
                End If
            End If
        Next
    End If

    ' Iterate over all discovered user profiles
    Dim arrProfiles, i
    arrProfiles = objProfilesDictionary.Keys

    For i = 0 To UBound(arrProfiles)
        strProfilePath = arrProfiles(i)
        strUsername = objProfilesDictionary.Item(strProfilePath)
        
        LogMessage vbCrLf & ">>> Extracting User Profile Artifacts for: " & strUsername & " [" & strProfilePath & "]"
        strUserRegDir = strDestLog & "\Registry\Users\" & strUsername
        CreateFolderIfMissing strUserRegDir

        ' ----------------------------------------------------------------------
        ' Extract NTUSER.DAT & UsrClass.dat using SafeExtractHive
        ' ----------------------------------------------------------------------
        If ENABLE_USER_HIVES Then
            ' 1. NTUSER.DAT Extraction
            SafeExtractHive strProfilePath & "\NTUSER.DAT", strUserRegDir & "\NTUSER.DAT", "NTUSER.DAT (" & strUsername & ")"
            
            ' 2. UsrClass.dat Extraction (Legacy XP/2003 vs Modern Vista-Win11)
            If Left(strOSVersion, 3) = "5.2" Or Left(strOSVersion, 3) = "5.1" Then
                SafeExtractHive strProfilePath & "\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat", _
                                strUserRegDir & "\UsrClass.dat", "UsrClass.dat (" & strUsername & ")"
            Else
                SafeExtractHive strProfilePath & "\AppData\Local\Microsoft\Windows\UsrClass.dat", _
                                strUserRegDir & "\UsrClass.dat", "UsrClass.dat (" & strUsername & ")"
            End If
        End If

        ' ----------------------------------------------------------------------
        ' Extract Recent LNK Shortcuts & Jump Lists
        ' ----------------------------------------------------------------------
        If ENABLE_USER_RECENT_LNK Then
            Dim strRecentPath, objRecentDir, objFileItem, strDestRecentDir
            strDestRecentDir = strUserRegDir & "\Recent"
            CreateFolderIfMissing strDestRecentDir
            
            ' Determine physical Recent path
            If objFSO.FolderExists(strProfilePath & "\AppData\Roaming\Microsoft\Windows\Recent") Then
                strRecentPath = strProfilePath & "\AppData\Roaming\Microsoft\Windows\Recent"
            ElseIf objFSO.FolderExists(strProfilePath & "\Recent") Then
                strRecentPath = strProfilePath & "\Recent"
            Else
                strRecentPath = ""
            End If
            
            If strRecentPath <> "" Then
                LogMessage "Collecting Recent shortcuts from: " & strRecentPath
                Set objRecentDir = objFSO.GetFolder(strRecentPath)
                
                ' Iterate files to bypass hidden/system attribute exclusions
                For Each objFileItem In objRecentDir.Files
                    If LCase(objFSO.GetExtensionName(objFileItem.Name)) = "lnk" Then
                        objFSO.CopyFile objFileItem.Path, strDestRecentDir & "\" & objFileItem.Name, True
                    End If
                Next
                
                ' Collect AutomaticDestinations Jump Lists (Modern OS)
                If objFSO.FolderExists(strRecentPath & "\AutomaticDestinations") Then
                    CreateFolderIfMissing strDestRecentDir & "\AutomaticDestinations"
                    objFSO.CopyFile strRecentPath & "\AutomaticDestinations\*.*", strDestRecentDir & "\AutomaticDestinations\", True
                End If
                
                ' Collect CustomDestinations Jump Lists (Modern OS)
                If objFSO.FolderExists(strRecentPath & "\CustomDestinations") Then
                    CreateFolderIfMissing strDestRecentDir & "\CustomDestinations"
                    objFSO.CopyFile strRecentPath & "\CustomDestinations\*.*", strDestRecentDir & "\CustomDestinations\", True
                End If
            End If
        End If

        ' ----------------------------------------------------------------------
        ' Browser History Extraction
        ' ----------------------------------------------------------------------
        If ENABLE_BROWSER_HISTORY Then
            strUserBrowserDir = strDestLog & "\BrowserHistory\" & strUsername
            CreateFolderIfMissing strUserBrowserDir
            
            ' Legacy Internet Explorer index.dat containers (Server 2003 / XP)
            If Left(strOSVersion, 3) = "5.2" Or Left(strOSVersion, 3) = "5.1" Then
                CreateFolderIfMissing strUserBrowserDir & "\IE_Legacy"
                SafeExtractHive strProfilePath & "\Local Settings\History\History.IE5\index.dat", strUserBrowserDir & "\IE_Legacy\History_index.dat", "IE History index.dat"
                SafeExtractHive strProfilePath & "\Local Settings\Temporary Internet Files\Content.IE5\index.dat", strUserBrowserDir & "\IE_Legacy\Cache_index.dat", "IE Cache index.dat"
                SafeExtractHive strProfilePath & "\Cookies\index.dat", strUserBrowserDir & "\IE_Legacy\Cookies_index.dat", "IE Cookies index.dat"
            End If
            
            ' Chromium-based browsers: Google Chrome
            Dim strChromeDefault
            strChromeDefault = strProfilePath & "\AppData\Local\Google\Chrome\User Data\Default"
            If objFSO.FolderExists(strChromeDefault) Then
                CreateFolderIfMissing strUserBrowserDir & "\Chrome"
                SafeExtractHive strChromeDefault & "\History", strUserBrowserDir & "\Chrome\History", "Chrome History"
                SafeExtractHive strChromeDefault & "\Web Data", strUserBrowserDir & "\Chrome\Web Data", "Chrome Web Data"
                
                ' Modern Chrome (v96+) Network\Cookies vs Legacy Cookies
                If objFSO.FileExists(strChromeDefault & "\Network\Cookies") Then
                    SafeExtractHive strChromeDefault & "\Network\Cookies", strUserBrowserDir & "\Chrome\Cookies", "Chrome Network Cookies"
                ElseIf objFSO.FileExists(strChromeDefault & "\Cookies") Then
                    SafeExtractHive strChromeDefault & "\Cookies", strUserBrowserDir & "\Chrome\Cookies", "Chrome Legacy Cookies"
                End If
            End If
            
            ' Chromium-based browsers: Microsoft Edge
            Dim strEdgeDefault
            strEdgeDefault = strProfilePath & "\AppData\Local\Microsoft\Edge\User Data\Default"
            If objFSO.FolderExists(strEdgeDefault) Then
                CreateFolderIfMissing strUserBrowserDir & "\Edge"
                SafeExtractHive strEdgeDefault & "\History", strUserBrowserDir & "\Edge\History", "Edge History"
                SafeExtractHive strEdgeDefault & "\Web Data", strUserBrowserDir & "\Edge\Web Data", "Edge Web Data"
                
                ' Modern Edge Network\Cookies vs Legacy Cookies
                If objFSO.FileExists(strEdgeDefault & "\Network\Cookies") Then
                    SafeExtractHive strEdgeDefault & "\Network\Cookies", strUserBrowserDir & "\Edge\Cookies", "Edge Network Cookies"
                ElseIf objFSO.FileExists(strEdgeDefault & "\Cookies") Then
                    SafeExtractHive strEdgeDefault & "\Cookies", strUserBrowserDir & "\Edge\Cookies", "Edge Legacy Cookies"
                End If
            End If
            
            ' Mozilla Firefox (places.sqlite database)
            Dim strFFBase, objFFFolder, objFFProfile
            If Left(strOSVersion, 3) = "5.2" Or Left(strOSVersion, 3) = "5.1" Then
                strFFBase = strProfilePath & "\Application Data\Mozilla\Firefox\Profiles"
            Else
                strFFBase = strProfilePath & "\AppData\Roaming\Mozilla\Firefox\Profiles"
            End If
            
            If objFSO.FolderExists(strFFBase) Then
                CreateFolderIfMissing strUserBrowserDir & "\Firefox"
                Set objFFFolder = objFSO.GetFolder(strFFBase)
                For Each objFFProfile In objFFFolder.SubFolders
                    SafeExtractHive objFFProfile.Path & "\places.sqlite", strUserBrowserDir & "\Firefox\" & objFFProfile.Name & "_places.sqlite", "Firefox places.sqlite (" & objFFProfile.Name & ")"
                Next
            End If
        End If
    Next
End If

LogMessage vbCrLf & "=== Triage Collection Complete. Saved to: " & strDestLog & " ==="
objLogFile.Close

' ==============================================================================
' HELPER FUNCTIONS
' ==============================================================================

Sub LogMessage(msg)
    WScript.Echo msg
    objLogFile.WriteLine "[" & Now() & "] " & msg
End Sub

Sub CreateFolderIfMissing(path)
    On Error Resume Next
    Dim arrParts, strCurrent, k
    If Not objFSO.FolderExists(path) Then
        arrParts = Split(path, "\")
        strCurrent = arrParts(0)
        For k = 1 To UBound(arrParts)
            strCurrent = strCurrent & "\" & arrParts(k)
            If Not objFSO.FolderExists(strCurrent) Then
                objFSO.CreateFolder(strCurrent)
            End If
        Next
    End If
End Sub

Sub ExecuteAndLog(cmd, outputFile)
    On Error Resume Next
    Dim strComspec, strFullCmd
    strComspec = objShell.ExpandEnvironmentStrings("%comspec%")
    strFullCmd = strComspec & " /c " & cmd & " > """ & outputFile & """"
    LogMessage "Executing CLI Command: " & cmd & " -> Output: " & outputFile
    objShell.Run strFullCmd, 0, True
End Sub

Function CleanProcessPath(rawPath)
    On Error Resume Next
    Dim clean, arr, strSystemRoot
    clean = Trim(rawPath)
    
    ' Resolve \SystemRoot\ prefix to environment directory
    strSystemRoot = objShell.ExpandEnvironmentStrings("%SystemRoot%")
    If LCase(Left(clean, 12)) = "\systemroot\" Then
        clean = strSystemRoot & "\" & Mid(clean, 13)
    End If
    
    ' Handle quoted paths
    If Left(clean, 1) = """" Then
        arr = Split(clean, """")
        If UBound(arr) >= 1 Then clean = arr(1)
    ' Handle unquoted paths containing parameters
    ElseIf InStr(clean, " ") > 0 Then
        If Not objFSO.FileExists(clean) Then
            arr = Split(clean, " ")
            clean = arr(0)
        End If
    End If
    
    clean = objShell.ExpandEnvironmentStrings(clean)
    CleanProcessPath = clean
End Function

Function GetUserShellFolder(strValueName)
    On Error Resume Next
    Dim strPath
    ' Read localized/redirected user folder paths directly from registry
    strPath = objShell.RegRead("HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\" & strValueName)
    GetUserShellFolder = strPath
End Function

Sub SafeExtractHive(strSourceFile, strDestFile, strArtifactName)
    On Error Resume Next
    Dim objTargetFile
    
    ' 1. Validate physical existence on disk before attempting copy
    If Not objFSO.FileExists(strSourceFile) Then
        LogMessage "SKIPPING: " & strArtifactName & " does not exist at: " & strSourceFile
        Exit Sub
    End If
    
    ' 2. Ensure destination folder exists
    CreateFolderIfMissing objFSO.GetParentFolderName(strDestFile)
    
    ' 3. Attempt standard copy first (fast and exact for unlocked files / inactive users)
    Err.Clear
    objFSO.CopyFile strSourceFile, strDestFile, True
    
    If Err.Number = 0 Then
        LogMessage "Standard Copy Succeeded for " & strArtifactName & ": " & strSourceFile
    Else
        ' 4. File is locked by OS/Kernel -> Fallback to RawCopy
        Err.Clear
        LogMessage "File locked by OS (" & strArtifactName & "). Invoking RawCopy fallback..."
        If CopyLockedFile(strSourceFile, strDestFile) Then
            LogMessage "RawCopy Succeeded for locked " & strArtifactName
        Else
            LogMessage "FAILED to acquire " & strArtifactName & " via RawCopy."
            ' Cleanup zero-byte or corrupt residue if RawCopy aborted
            If objFSO.FileExists(strDestFile) Then
                Set objTargetFile = objFSO.GetFile(strDestFile)
                If objTargetFile.Size = 0 Then objFSO.DeleteFile strDestFile, True
            End If
        End If
    End If
End Sub

Function CopyLockedFile(strSourcePath, strDestinationPath)
    On Error Resume Next
    Dim strRawCopyPath, strParentDir, strRawCopyCmd, intExitCode
    
    ' Select 64-bit or 32-bit RawCopy binary based on architecture detection
    If is64BitOS And objFSO.FileExists(strScriptDir & "\RawCopy64.exe") Then
        strRawCopyPath = strScriptDir & "\RawCopy64.exe"
    ElseIf objFSO.FileExists(strScriptDir & "\RawCopy.exe") Then
        strRawCopyPath = strScriptDir & "\RawCopy.exe"
    Else
        strRawCopyPath = strScriptDir & "\RawCopy64.exe"
    End If
    
    If Not objFSO.FileExists(strRawCopyPath) Then
        LogMessage "ERROR: RawCopy binary not found at: " & strRawCopyPath
        CopyLockedFile = False
        Exit Function
    End If
    
    ' Ensure destination directory structure exists recursively
    strParentDir = objFSO.GetParentFolderName(strDestinationPath)
    CreateFolderIfMissing strParentDir
    
    ' Construct and execute RawCopy command line
    strRawCopyCmd = """" & strRawCopyPath & """ /FileNamePath:""" & strSourcePath & """ /OutputPath:""" & strParentDir & """"
    intExitCode = objShell.Run(strRawCopyCmd, 0, True)
    
    If intExitCode = 0 Then
        LogMessage "RawCopy Succeeded: " & strRawCopyCmd
        CopyLockedFile = True
    Else
        LogMessage "FAILED to copy locked file via RawCopy (ExitCode " & intExitCode & "): " & strRawCopyCmd
        CopyLockedFile = False
    End If
End Function