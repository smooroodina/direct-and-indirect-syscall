#ifndef _SYSCALLS_H  // If _SYSCALLS_H is not defined then define it and the contents below. This is to prevent double inclusion.
#define _SYSCALLS_H  // Define _SYSCALLS_H

#include <windows.h>  // Include the Windows API header
#include <ntdef.h>

#ifdef __cplusplus   // If this header file is included in a C++ file, then this section will be true
extern "C" {         // This is to ensure that the names of the functions are not mangled by the C++ compiler and are in C linkage format
#endif
    // from `winternl.h`
    #define FILE_OVERWRITE_IF               0x00000005
    #define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020

    //from `ntstatus.h`
    #define STATUS_SUCCESS ((NTSTATUS)0x00000000)


    typedef struct _IO_STATUS_BLOCK {
    #pragma warning(push)
    #pragma warning(disable: 4201) // we'll always use the Microsoft compiler
        union {
            NTSTATUS Status;
            PVOID Pointer;
        } DUMMYUNIONNAME;
        ULONG_PTR Information;
    } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

    typedef VOID (NTAPI *PIO_APC_ROUTINE) (
        IN PVOID ApcContext,
        IN PIO_STATUS_BLOCK IoStatusBlock,
        IN ULONG Reserved
    );
    typedef VOID (NTAPI *RtlInitUnicodeString_t)(
        PUNICODE_STRING DestinationString,
        PCWSTR SourceString
    );

    extern NTSTATUS NtCreateFile(
        PHANDLE FileHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock,
        PLARGE_INTEGER AllocationSize,
        ULONG FileAttributes,
        ULONG ShareAccess,
        ULONG CreateDisposition,
        ULONG CreateOptions,
        PVOID EaBuffer,
        ULONG EaLength
    );

    extern NTSTATUS NtOpenFile(
        PHANDLE FileHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock,
        ULONG ShareAccess,
        ULONG OpenOptions
    );
    
    extern NTSTATUS NtWriteFile(
        HANDLE FileHandle,
        HANDLE Event,
        PIO_APC_ROUTINE ApcRoutine,
        PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        PVOID Buffer,
        ULONG Length,
        PLARGE_INTEGER ByteOffset,
        PULONG Key
    );
    
    extern NTSTATUS NtClose(
        HANDLE Handle
    );

#ifdef __cplusplus  // End of the 'extern "C"' block if __cplusplus was defined
}
#endif

#endif // _SYSCALLS_H  // End of the _SYSCALLS_H definition
