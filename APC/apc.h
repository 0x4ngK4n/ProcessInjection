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