#include <Windows.h>
#include <ntdef.h>

/*
 Resources:
 - https://cocomelonc.github.io/tutorial/2021/12/13/malware-injection-12.html
*/

#define InitializeObjectAttributes(p,n,a,r,s) { \
  (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
  (p)->RootDirectory = (r); \
  (p)->Attributes = (a); \
  (p)->ObjectName = (n); \
  (p)->SecurityDescriptor = (s); \
  (p)->SecurityQualityOfService = NULL; \
}

// NtCreateSection definition
typedef NTSTATUS(NTAPI* pNtCreateSection)(
    PHANDLE             SectionHandle,
    ACCESS_MASK         DesiredAddress,
    POBJECT_ATTRIBUTES  ObjectAttributes,
    PLARGE_INTEGER      MaximumSize,
    ULONG               PageAttributes,
    ULONG               SectionAttributes,
    HANDLE              FileHandle
);

typedef enum _SECTION_INHERIT {
    ViewShare=1,
    ViewUnmap=2
} SECTION_INHERIT, *PSECTION_INHERIT;

// NtMapViewOfSection definition
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    HANDLE              SectionHandle,
    HANDLE              ProcessHandle,
    PVOID               *BaseAddress OPTIONAL,
    ULONG               ZeroBits OPTIONAL,
    ULONG               CommitSize,
    PLARGE_INTEGER      SectionOffset OPTIONAL,
    PSIZE_T             ViewSize,
    SECTION_INHERIT     InheritDisposition,
    ULONG               AllocationType OPTIONAL,
    ULONG               Protect
);

// NtCreateThreadEx
typedef NTSTATUS(NTAPI* pNtCreateThreadEx) (
    PHANDLE         hThread,
    ACCESS_MASK     DesiredAccess,
    PVOID           ObjectAttributes,
    HANDLE          ProcessHandle,
    PVOID           lpStartAddress,
    PVOID           lpParameter,
    ULONG           Flags,
    SIZE_T          StackZeroBits,
    SIZE_T          SizeOfStackCommit,
    SIZE_T          SizeOfStackReserve,
    PVOID           lpBytesBuffer
);

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
  HANDLE             ProcessHandle,
  PVOID              *BaseAddress,
  ULONG              ZeroBits,
  PSIZE_T            RegionSize,
  ULONG              AllocationType,
  ULONG              Protect
);

typedef struct _CLIENT_ID {
  PVOID              UniqueProcess;
  PVOID              UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(NTAPI* pNtOpenProcess)(
  PHANDLE            ProcessHandle,
  ACCESS_MASK        AccessMask,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PCLIENT_ID         ClientID
);

typedef NTSTATUS (NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PULONG NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

typedef NTSTATUS (NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
);

typedef struct _INITIAL_TEB {
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackCommit;
    PVOID StackCommitMax;
    PVOID StackReserved;
} INITIAL_TEB, *PINITIAL_TEB;

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
  );