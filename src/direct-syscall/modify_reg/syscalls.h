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
    #pragma warning(pop)

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

    extern NTSTATUS NtCreateKey(
        PHANDLE KeyHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        ULONG TitleIndex,
        PUNICODE_STRING Class,
        ULONG CreateOptions,
        PULONG Disposition
    );

    extern NTSTATUS NtOpenKey(
        PHANDLE KeyHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes
    );
    
    extern NTSTATUS NtSetValueKey(
        HANDLE KeyHandle,
        PUNICODE_STRING ValueName,
        ULONG TitleIndex,
        ULONG Type,
        PVOID Data,
        ULONG DataSize
    );
    
    extern NTSTATUS NtDeleteValueKey(
        HANDLE KeyHandle,
        PUNICODE_STRING ValueName
    );

#ifdef __cplusplus  // End of the 'extern "C"' block if __cplusplus was defined
}
#endif

#endif // _SYSCALLS_H  // End of the _SYSCALLS_H definition
