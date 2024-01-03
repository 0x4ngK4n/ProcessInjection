#include <Windows.h>
#include <ntdef.h>

/*
 Resources:
 - https://github.com/cocomelonc/meow/blob/master/2021-12-11-malware-injection-11/hack.cpp
*/

#define InitializeObjectAttributes(p,n,a,r,s) { \
  (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
  (p)->RootDirectory = (r); \
  (p)->Attributes = (a); \
  (p)->ObjectName = (n); \
  (p)->SecurityDescriptor = (s); \
  (p)->SecurityQualityOfService = NULL; \
}

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
  HANDLE             ProcessHandle,
  PVOID              *BaseAddress,
  ULONG              ZeroBits,
  PSIZE_T            RegionSize,
  ULONG              AllocationType,
  ULONG              Protect
);

// dt nt!_UNICODE_STRING
/*
    typedef struct _UNICODE_STRING
    {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    } UNICODE_STRING, * PUNICODE_STRING;
*/

// dt nt!_OBJECT_ATTRIBUTES
/* apparently defined in ntdef.h!
typedef struct _OBJECT_ATTRIBUTES {
  ULONG              Length;
  HANDLE             RootDirectory;
  PUNICODE_STRING    ObjectName;
  ULONG              Attributes;
  PVOID              SecurityDescriptor;
  PVOID              SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
*/

//typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES

// dt nt!_CLIENT_ID
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

/*

VOID InitializeObjectAttributes(
    POBJECT_ATTRIBUTES p, // A pointer to the OBJECT_ATTRIBUTES structure to initialize.
    PUNICODE_STRING n, // A pointer to a Unicode string that contains the name of the object for which a handle is to be opened.
    ULONG a, // This specifies the flag that is applicable to the object handle.
    HANDLE r, // A handle to the root object directory for the path name specified in the ObjectName parameter. If ObjectName is a fully qualified object name, RootDirectory is NULL.
    PSECURITY_DESCRIPTOR s // Specifies a security descriptor to apply to an object when it is created. This parameter is optional. Drivers can specify NULL to accept the default security for the object.
);

*/


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


/*
  typedef NTSTATUS (NTAPI* pNtCreateThread)(
      PHANDLE ThreadHandle,
      ACCESS_MASK DesiredAccess,
      POBJECT_ATTRIBUTES ObjectAttributes,
      HANDLE ProcessHandle,
      PCLIENT_ID ClientId,
      PCONTEXT ThreadContext,
      PINITIAL_TEB InitialTeb,
      BOOLEAN CreateSuspended
  );
*/

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