EXTERN wNtCreateUserProcess: DWORD


.CODE  ; Start the code section

NtCreateUserProcess PROC
    mov r10, rcx
    mov eax, wNtCreateUserProcess
    syscall
    ret
NtCreateUserProcess ENDP


END  ; End of the module
