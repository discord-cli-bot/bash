.text

.globl osaibot_syscall_tramp
osaibot_syscall_tramp:
	syscall

.globl osaibot_end_syscall
osaibot_end_syscall:
	add $-8,%rsp
	ret
