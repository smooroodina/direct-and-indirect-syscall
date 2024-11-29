EXTERN wNtCreateFile: DWORD
EXTERN wNtOpenFile: DWORD
EXTERN wNtWriteFile: DWORD
EXTERN wNtClose: DWORD


.CODE  ; Start the code section

NtCreateFile PROC
    mov r10, rcx
    mov eax, wNtCreateFile
    syscall
    ret
NtCreateFile ENDP

NtWriteFile PROC
    mov r10, rcx
    mov eax, wNtWriteFile
    syscall
    ret
NtWriteFile ENDP

NtOpenFile PROC
    mov r10, rcx
    mov eax, wNtOpenFile
    syscall
    ret
NtOpenFile ENDP

NtClose PROC
    mov r10, rcx
    mov eax, wNtClose
    syscall
    ret
NtClose ENDP


END  ; End of the module
