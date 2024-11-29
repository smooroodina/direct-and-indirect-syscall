// #include <ntifs.h>
#include <windows.h>  
#include <sddl.h> // ConvertSidToStringSid
#include <stdio.h>
#include "syscalls.h"


// Declare global variables to hold syscall numbers
DWORD wNtCreateUserProcess;

int main() {
    HANDLE processHandle = NULL, threadHandle = NULL;  // Declare a handle of the process
    UNICODE_STRING applicationPath;
    // Get a handle to the ntdll.dll library
    HANDLE hNtdll = GetModuleHandleA("ntdll.dll");
    
    RtlInitUnicodeString_t RtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(hNtdll, "RtlInitUnicodeString");

    RtlCreateProcessParametersEx_t RtlCreateProcessParametersEx = (RtlCreateProcessParametersEx_t)GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");

    UINT_PTR pNtCreateUserProcess = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateUserProcess");
    wNtCreateUserProcess = ((unsigned char*)(pNtCreateUserProcess + 4))[0];


    // Target program to run
    RtlInitUnicodeString(&applicationPath, L"C:\\Windows\\System32\\calc.exe");

    RTL_USER_PROCESS_PARAMETERS* processParams = NULL;
    NTSTATUS status = RtlCreateProcessParametersEx(
        &processParams,
        &applicationPath,
        NULL, // DLL path
        NULL, // Current Directory
        &applicationPath, // Command line
        NULL, // Environment
        NULL, // Window title
        NULL, // Desktop info
        NULL, // Shell info
        NULL, // Runtime data
        RTL_USER_PROCESS_PARAMETERS_NORMALIZED
    );

    if (!NT_SUCCESS(status)) {
        printf("Failed to create process parameters: 0x%x\n", status);
        return 1;
    }

    status = NtCreateUserProcess(
        &processHandle,
        &threadHandle,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        NULL, // Process object attributes
        NULL, // Thread object attributes
        0,    // Process flags
        0,    // Thread flags
        processParams,
        NULL, // CreateInfo
        NULL  // AttributeList
    );

    if (NT_SUCCESS(status)) {
        printf("Process created successfully.\n");
        CloseHandle(processHandle);
        CloseHandle(threadHandle);
    } else {
        printf("Failed to create process: 0x%x\n", status);
        // >.\run_proc.exe
        // Failed to create process: 0xc0000005
        // 원인을 모르겠음.
    }
}
