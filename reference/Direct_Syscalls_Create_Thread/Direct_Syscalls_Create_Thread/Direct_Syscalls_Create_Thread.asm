	.file	"Direct_Syscalls_Create_Thread.c"
	.text
	.globl	wNtAllocateVirtualMemory
	.bss
	.align 4
wNtAllocateVirtualMemory:
	.space 4
	.globl	wNtWriteVirtualMemory
	.align 4
wNtWriteVirtualMemory:
	.space 4
	.globl	wNtCreateThreadEx
	.align 4
wNtCreateThreadEx:
	.space 4
	.globl	wNtWaitForSingleObject
	.align 4
wNtWaitForSingleObject:
	.space 4
	.section .rdata,"dr"
.LC0:
	.ascii "ntdll.dll\0"
.LC1:
	.ascii "NtAllocateVirtualMemory\0"
.LC2:
	.ascii "NtWriteVirtualMemory\0"
.LC3:
	.ascii "NtCreateThreadEx\0"
.LC4:
	.ascii "NtWaitForSingleObject\0"
	.text
	.globl	main
	.def	main;	.scl	2;	.type	32;	.endef
	.seh_proc	main
main:
	pushq	%rbp
	.seh_pushreg	%rbp
	pushq	%rbx
	.seh_pushreg	%rbx
	subq	$184, %rsp
	.seh_stackalloc	184
	leaq	176(%rsp), %rbp
	.seh_setframe	%rbp, 176
	.seh_endprologue
	call	__main
	movq	$0, -48(%rbp)
	movq	$4096, -56(%rbp)
	leaq	.LC0(%rip), %rax
	movq	%rax, %rcx
	movq	__imp_GetModuleHandleA(%rip), %rax
	call	*%rax
	movq	%rax, -8(%rbp)
	movq	-8(%rbp), %rax
	leaq	.LC1(%rip), %rdx
	movq	%rax, %rcx
	movq	__imp_GetProcAddress(%rip), %rax
	call	*%rax
	movq	%rax, -16(%rbp)
	movq	-16(%rbp), %rax
	addq	$4, %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	movl	%eax, wNtAllocateVirtualMemory(%rip)
	movq	-8(%rbp), %rax
	leaq	.LC2(%rip), %rdx
	movq	%rax, %rcx
	movq	__imp_GetProcAddress(%rip), %rax
	call	*%rax
	movq	%rax, -24(%rbp)
	movq	-24(%rbp), %rax
	addq	$4, %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	movl	%eax, wNtWriteVirtualMemory(%rip)
	movq	-8(%rbp), %rax
	leaq	.LC3(%rip), %rdx
	movq	%rax, %rcx
	movq	__imp_GetProcAddress(%rip), %rax
	call	*%rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	addq	$4, %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	movl	%eax, wNtCreateThreadEx(%rip)
	movq	-8(%rbp), %rax
	leaq	.LC4(%rip), %rdx
	movq	%rax, %rcx
	movq	__imp_GetProcAddress(%rip), %rax
	call	*%rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	addq	$4, %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	movl	%eax, wNtWaitForSingleObject(%rip)
	movl	$780355836, -63(%rbp)
	movl	$3026478, -60(%rbp)
	leaq	-56(%rbp), %rdx
	leaq	-48(%rbp), %rax
	movl	$64, 40(%rsp)
	movl	$12288, 32(%rsp)
	movq	%rdx, %r9
	movl	$0, %r8d
	movq	%rax, %rdx
	movq	$-1, %rcx
	call	NtAllocateVirtualMemory
	movq	-48(%rbp), %rbx
	movq	__imp_GetCurrentProcess(%rip), %rax
	call	*%rax
	movq	%rax, %rcx
	leaq	-63(%rbp), %rdx
	leaq	-68(%rbp), %rax
	movq	%rax, 32(%rsp)
	movl	$7, %r9d
	movq	%rdx, %r8
	movq	%rbx, %rdx
	call	NtWriteVirtualMemory
	movq	-48(%rbp), %rbx
	movq	__imp_GetCurrentProcess(%rip), %rax
	call	*%rax
	movq	%rax, %rdx
	leaq	-80(%rbp), %rax
	movq	$0, 80(%rsp)
	movq	$0, 72(%rsp)
	movq	$0, 64(%rsp)
	movq	$0, 56(%rsp)
	movl	$0, 48(%rsp)
	movq	$0, 40(%rsp)
	movq	%rbx, 32(%rsp)
	movq	%rdx, %r9
	movl	$0, %r8d
	movl	$536870912, %edx
	movq	%rax, %rcx
	call	NtCreateThreadEx
	movq	-80(%rbp), %rax
	movl	$0, %r8d
	movl	$0, %edx
	movq	%rax, %rcx
	call	NtWaitForSingleObject
	movl	$0, %eax
	addq	$184, %rsp
	popq	%rbx
	popq	%rbp
	ret
	.seh_endproc
	.def	__main;	.scl	2;	.type	32;	.endef
	.ident	"GCC: (Rev3, Built by MSYS2 project) 14.1.0"
	.def	NtAllocateVirtualMemory;	.scl	2;	.type	32;	.endef
	.def	NtWriteVirtualMemory;	.scl	2;	.type	32;	.endef
	.def	NtCreateThreadEx;	.scl	2;	.type	32;	.endef
	.def	NtWaitForSingleObject;	.scl	2;	.type	32;	.endef
