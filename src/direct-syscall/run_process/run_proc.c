// #include <ntifs.h>
#include <windows.h>  
#include <sddl.h> // ConvertSidToStringSid
#include <stdio.h>
#include "syscalls.h"


// Declare global variables to hold syscall numbers
DWORD wNtCreateUserProcess;

int main() {
    HANDLE processHandle = NULL, threadHandle = NULL;  // Declare a handle of the process
    UNICODE_STRING applicationPath, NtImagePath;
    // Get a handle to the ntdll.dll library
    HANDLE hNtdll = GetModuleHandleA("ntdll.dll");
    
    RtlInitUnicodeString_t RtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(hNtdll, "RtlInitUnicodeString");

    RtlCreateProcessParametersEx_t RtlCreateProcessParametersEx = (RtlCreateProcessParametersEx_t)GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");

    RtlAllocateHeap_t RtlAllocateHeap = (RtlAllocateHeap_t)GetProcAddress(hNtdll, "RtlAllocateHeap");

    RtlProcessHeap_t RtlProcessHeap = (RtlProcessHeap_t)GetProcAddress(hNtdll, "RtlProcessHeap");

    UINT_PTR pNtCreateUserProcess = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateUserProcess");
    wNtCreateUserProcess = ((unsigned char*)(pNtCreateUserProcess + 4))[0];


    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);
    printf("Current directory: \"%s\"\n", currentDir);

    int len = MultiByteToWideChar(CP_ACP, 0, currentDir, -1, NULL, 0);
    wchar_t* wCurrentDir = (wchar_t*)malloc(len * sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP, 0, currentDir, -1, wCurrentDir, len);

    const wchar_t* fileName = L"testScript.bat";
    wchar_t fileFullPath[MAX_PATH];
    snwprintf(fileFullPath, sizeof(fileFullPath), L"\\??\\%ls\\%ls", wCurrentDir, fileName);
    wprintf(L"Full path for new file: \"%ls\"\n", fileFullPath);

    // Target program to run
    // L"C:\\Windows\\System32\\calc.exe"
    RtlInitUnicodeString(&applicationPath, L"C:\\Windows\\System32\\calc.exe");
    RtlInitUnicodeString(&NtImagePath, L"\\??\\C:\\Windows\\System32\\calc.exe");

    //RtlInitUnicodeString(&applicationPath, fileFullPath);

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

    PS_CREATE_INFO CreateInfo = { 0 };
    CreateInfo.Size = sizeof(CreateInfo);
	CreateInfo.State = PsCreateInitialState;

    PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
    // Create necessary attributes
	PCLIENT_ID clientId = (PCLIENT_ID)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE));
	PSECTION_IMAGE_INFORMATION SecImgInfo = (PSECTION_IMAGE_INFORMATION)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SECTION_IMAGE_INFORMATION));
	PPS_STD_HANDLE_INFO stdHandleInfo = (PPS_STD_HANDLE_INFO)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_STD_HANDLE_INFO));

	AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);
	AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_CLIENT_ID;
	AttributeList->Attributes[0].Size = sizeof(CLIENT_ID);
	AttributeList->Attributes[0].ValuePtr = clientId;

	AttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_IMAGE_INFO;
	AttributeList->Attributes[1].Size = sizeof(SECTION_IMAGE_INFORMATION);
	AttributeList->Attributes[1].ValuePtr = SecImgInfo;

	AttributeList->Attributes[2].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList->Attributes[2].Size = NtImagePath.Length;
	AttributeList->Attributes[2].ValuePtr = NtImagePath.Buffer;

	AttributeList->Attributes[3].Attribute = PS_ATTRIBUTE_STD_HANDLE_INFO;
	AttributeList->Attributes[3].Size = sizeof(PS_STD_HANDLE_INFO);
	AttributeList->Attributes[3].ValuePtr = stdHandleInfo;

	DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

	// Add process mitigation attribute
	AttributeList->Attributes[4].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS;
	AttributeList->Attributes[4].Size = sizeof(DWORD64);
	AttributeList->Attributes[4].ValuePtr = &policy;

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
        &CreateInfo, // CreateInfo 없으면 0xc0000005
        AttributeList  // AttributeList 없으면 0xc000000d
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
