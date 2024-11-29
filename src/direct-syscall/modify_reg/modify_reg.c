// #include <ntifs.h>
#include <windows.h>  
#include <sddl.h> // ConvertSidToStringSid
#include <stdio.h>
#include "syscalls.h"


// Declare global variables to hold syscall numbers
DWORD wNtCreateKey;
DWORD wNtOpenKey;
DWORD wNtSetValueKey;
DWORD wNtDeleteValueKey;

void GetCurrentUserSid(wchar_t** sidString) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        wprintf(L"Failed to open process token. Error: %lu\n", GetLastError());
        return;
    }

    DWORD tokenInfoLength = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &tokenInfoLength);
    PTOKEN_USER tokenUser = (PTOKEN_USER)malloc(tokenInfoLength);

    if (!GetTokenInformation(token, TokenUser, tokenUser, tokenInfoLength, &tokenInfoLength)) {
        wprintf(L"Failed to get token information. Error: %lu\n", GetLastError());
        CloseHandle(token);
        free(tokenUser);
        return;
    }

    // Convert SID to a string
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, sidString)) {
        wprintf(L"Failed to convert SID to string. Error: %lu\n", GetLastError());
    } else {
        wprintf(L"Current User SID: %s\n", *sidString);
    }

    CloseHandle(token);
    free(tokenUser);
}

int main() {
    HANDLE keyHandle = NULL;  // Declare a handle of the file to be recieved after create new one
    SIZE_T fileSize = 0x1000;  // Declare the size of the file (4096 bytes)
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING regPath;

    wchar_t* sidString = NULL;
    GetCurrentUserSid(&sidString);
    wchar_t regFullPath[MAX_PATH];
    swprintf(regFullPath, 512, L"\\Registry\\User\\%ls\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", sidString);
    wprintf(L"Registry Full Path: %ls\n", regFullPath);

    
    IO_STATUS_BLOCK ioStatusBlock;


    // Get a handle to the ntdll.dll library
    HANDLE hNtdll = GetModuleHandleA("ntdll.dll");
    
    RtlInitUnicodeString_t RtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(hNtdll, "RtlInitUnicodeString");

    UINT_PTR pNtCreateKey = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateKey");
    wNtCreateKey = ((unsigned char*)(pNtCreateKey + 4))[0];

    UINT_PTR pNtOpenKey = (UINT_PTR)GetProcAddress(hNtdll, "NtOpenKey");
    wNtOpenKey = ((unsigned char*)(pNtOpenKey + 4))[0];

    UINT_PTR pNtSetValueKey = (UINT_PTR)GetProcAddress(hNtdll, "NtSetValueKey");
    wNtSetValueKey = ((unsigned char*)(pNtSetValueKey + 4))[0];

    UINT_PTR pNtDeleteValueKey = (UINT_PTR)GetProcAddress(hNtdll, "NtDeleteValueKey");
    wNtDeleteValueKey = ((unsigned char*)(pNtDeleteValueKey + 4))[0];


    RtlInitUnicodeString(&regPath, regFullPath);
    
    InitializeObjectAttributes(
        &objAttr,
        &regPath,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    // Registry value to create at HKEY_CURRENT_USER\...
    // to register WinCalculator as a startup program.
    wchar_t data[] = L"C:\\Windows\\System32\\calc.exe";

    NTSTATUS status = NtCreateKey(&keyHandle, KEY_ALL_ACCESS, &objAttr, 0, NULL, 0, NULL);

    if (!NT_SUCCESS(status)) {
        printf("Failed to create registry key: 0x%x\n", status);
        return -1;
    }

    UNICODE_STRING valueName;
    RtlInitUnicodeString(&valueName, L"TestAutoRun");

    status = NtSetValueKey(keyHandle, &valueName, 0, REG_SZ, data, sizeof(data));

    if (NT_SUCCESS(status)) {
        printf("Registry value set successfully.\n");
    } else {
        printf("Failed to set registry value: 0x%x\n", status);
    }

    CloseHandle(keyHandle);

    // `컴퓨터\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
    // 레지스트리 경로에 `TestAutoRun`이라는 이름의 레지스트리 키가 생겼는지 확인.
}
