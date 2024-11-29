EXTERN wNtCreateKey: DWORD
EXTERN wNtOpenKey: DWORD
EXTERN wNtSetValueKey: DWORD
EXTERN wNtDeleteValueKey: DWORD


.CODE  ; Start the code section

NtCreateKey PROC
    mov r10, rcx
    mov eax, wNtCreateKey
    syscall
    ret
NtCreateKey ENDP

NtOpenKey PROC
    mov r10, rcx
    mov eax, wNtOpenKey
    syscall
    ret
NtOpenKey ENDP

NtSetValueKey PROC
    mov r10, rcx
    mov eax, wNtSetValueKey
    syscall
    ret
NtSetValueKey ENDP

NtDeleteValueKey PROC
    mov r10, rcx
    mov eax, wNtDeleteValueKey
    syscall
    ret
NtDeleteValueKey ENDP


END  ; End of the module
