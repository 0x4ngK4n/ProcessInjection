#include <windows.h>
#include <tlhelp32.h>
#include "cwl.h"
#include <stdio.h>
//#include <wchar.h>


int EnumNT() {
    ULONG init_size = 0x20480;
	DWORD ret_len = 0;
	NTSTATUS status;
	_NtQuerySystemInformation pNtQuerySystemInformation = 
			(_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQuerySystemInformation");
	if (pNtQuerySystemInformation == NULL) {
		printf("[-] Failed to load NtQuerySystemInformation \n");
		exit(-1);
	}

	PSYSTEM_PROCESS_INFORMATION sys_info_class = (PSYSTEM_PROCESS_INFORMATION)malloc(init_size);
	while (pNtQuerySystemInformation(SystemProcessInformation, sys_info_class, init_size, &ret_len) == STATUS_INFO_LENGTH_MISMATCH) {
		init_size *= 2;
		//sys_info_class = (PSYSTEM_PROCESS_INFORMATION)realloc(sys_info_class, init_size);
		sys_info_class = (PSYSTEM_PROCESS_INFORMATION)realloc(sys_info_class, init_size);
	}

	PSYSTEM_PROCESS_INFORMATION temp_sys_info_class = (PSYSTEM_PROCESS_INFORMATION)sys_info_class;
	while (temp_sys_info_class->NextEntryOffset != NULL) {
		temp_sys_info_class = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)temp_sys_info_class + temp_sys_info_class->NextEntryOffset);
		printf("[+] Process id: %x \n", temp_sys_info_class->UniqueProcessId);
		wprintf(L"[+] Process Image Name: %s \n", temp_sys_info_class->ImageName.pBuffer);
		printf("[+] Number of Threads: %d \n", temp_sys_info_class->NumberOfThreads);
		printf("\n");
	}

	system("pause");
    return 0;
}


void EnumProcess() {
    HANDLE hSnapShot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };

    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if(Process32First(hSnapShot, &pe32)) {
        do
        {
            /* code */
            wprintf(L"Process name: %s\n", pe32.szExeFile);
            wprintf(L"Process id %d\n", pe32.th32ProcessID);
        } while (Process32Next(hSnapShot, &pe32));

        system("pause");
    }
}

int main() {
    //EnumProcess();
    EnumNT();

    return 0;
}