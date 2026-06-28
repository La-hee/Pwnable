
#확인한 각 레지스터 값
rsi = "3Kp*3+Ndjx_)@kdN"
rdi = ":vT3?[Z}cV'of8?C"
r8 = "6iu7(iUBpD$9KlIC"
rdx = "^62(Ay&3`r7j|Q}>"

answer = []

#enuerate -> 'hello'같은 문자열을 0 h 1 e 같이 문자 따로 숫자 따로 나눠줌 기본 내장 함수
for i, al in enumerate(rdx) :
    al = ord(al)
    
    al ^= ord(rsi[i])
    al ^= ord(r8[i])
    al ^= ord(rdi[i])
    al ^= 0x20
    
    answer.append(chr(al))
    
    i += 1

#한 번에 묶어서 한 문자열로 출력
print("".join(answer))
    
    



