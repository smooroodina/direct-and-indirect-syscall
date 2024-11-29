// #include <ntifs.h>
#include <windows.h>  
#include <stdio.h>
#include "syscalls.h"

// Declare global variables to hold syscall numbers
DWORD wNtCreateFile;
DWORD wNtOpenFile;
DWORD wNtWriteFile;
DWORD wNtClose;


int main() {
    HANDLE fileHandle = NULL;  // Declare a handle of the file to be recieved after create new one
    SIZE_T fileSize = 0x1000;  // Declare the size of the file (4096 bytes)
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING filePath;

    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);
    printf("Current directory: \"%s\"\n", currentDir);

    int len = MultiByteToWideChar(CP_ACP, 0, currentDir, -1, NULL, 0);
    wchar_t* wCurrentDir = (wchar_t*)malloc(len * sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP, 0, currentDir, -1, wCurrentDir, len);

    const wchar_t* fileName = L"testScript.bat";
    wchar_t fileFullPath[MAX_PATH];
    snwprintf(fileFullPath, sizeof(fileFullPath), L"\\??\\%s\\%s", wCurrentDir, fileName);
    wprintf(L"Full path for new file: \"%ls\"\n", fileFullPath);
 
    
    IO_STATUS_BLOCK ioStatusBlock;


    // Get a handle to the ntdll.dll library
    HANDLE hNtdll = GetModuleHandleA("ntdll.dll");

    RtlInitUnicodeString_t RtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(hNtdll, "RtlInitUnicodeString");

    UINT_PTR pNtCreateFile = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateFile");
    wNtCreateFile = ((unsigned char*)(pNtCreateFile + 4))[0];

    UINT_PTR pNtOpenFile = (UINT_PTR)GetProcAddress(hNtdll, "NtOpenFile");
    wNtOpenFile = ((unsigned char*)(pNtOpenFile + 4))[0];

    UINT_PTR pNtWriteFile = (UINT_PTR)GetProcAddress(hNtdll, "NtWriteFile");
    wNtWriteFile = ((unsigned char*)(pNtWriteFile + 4))[0];

    UINT_PTR pNtClose = (UINT_PTR)GetProcAddress(hNtdll, "NtClose");
    wNtClose = ((unsigned char*)(pNtClose + 4))[0];


    RtlInitUnicodeString(&filePath, fileFullPath);
    
    InitializeObjectAttributes(
        &objAttr,
        &filePath,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    // Shellscript(or python script) for create new file at current path
    unsigned char shellScript[] = \
    "@echo off\r\n"
    "echo Hello from Batch Script!\r\n"
    "echo Batch was here! > C:\\Users\\hhj\\hello_batch.txt\r\n";

    unsigned char pythonScript[] = \
    "import os\n"
    "print(\"Hello from Python Script!\")\n"
    "with open(\"C:\\\\Users\\\\hhj\\\\hello_python.txt\", \"w\") as f:\n"
    "    f.write(\"Python was here!\\n\")\n";

    
    NTSTATUS status = NtCreateFile(&fileHandle, FILE_WRITE_DATA|SYNCHRONIZE, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (status == STATUS_SUCCESS) {
        printf("File created successfully!\n");

        const char* data = shellScript;
        status = NtWriteFile(
            fileHandle,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            (PVOID)data,
            (ULONG)strlen(data),
            NULL,
            NULL
        );

        if (status == STATUS_SUCCESS) {
            printf("Data written successfully!\n");
        } else {
            printf("Failed to write data. NTSTATUS: 0x%08X\n", status);
        }

        NtClose(fileHandle);
    } else {
        printf("Failed to create file. NTSTATUS: 0x%08X\n", status);
    }
}
