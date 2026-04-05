#원래 내려고 했던 python 파일
from pwnable import *

target = 0x21DD09E

#주어진 해시값을 5로 나눔
quo = target // 5
remind = target % 5

#첫 네 부분은 몫*4, 마지막 부분은 몫+나머지를 해야 나눠지는 수가 나오겠죠
find = [quo] * 4
rest = find.append(quo + remind)

payload = b""
for v in find :
    payload += p32(v)


#원격 접속 내에서 제출용
./col $(python3 -c 'from pwn import *; target=0x21DD09EC; q=target//5; r=target%5; sys.stdout.buffer.write((p32(q)*4 + p32(q+r)))')