#ifdef __cplusplus
#ifndef _DEBUG
#define DFR(module, function) \
	DECLSPEC_IMPORT decltype(function) module##$##function;

#define DFR_LOCAL(module, function) \
	DECLSPEC_IMPORT decltype(function) module##$##function; \
	decltype(module##$##function) *##function = module##$##function;
#else
#define DFR_LOCAL(module, function)
#define DFR(module, function) \
	decltype(function) *module##$##function = function;
#endif // end of _DEBUG
#endif // end of __cplusplus

WINBASEAPI NTSTATUS NTAPI NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PULONG RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);
WINBASEAPI NTSTATUS NTAPI NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);