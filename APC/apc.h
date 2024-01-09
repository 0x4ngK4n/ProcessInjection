#include <windows.h>

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
  HANDLE             ProcessHandle,
  PVOID              *BaseAddress,
  ULONG              ZeroBits,
  PSIZE_T            RegionSize,
  ULONG              AllocationType,
  ULONG              Protect
);