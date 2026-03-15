
#시리얼 키를 이름으로 변환하는 함수
def main() :

    v7 = [0x10, 0x20, 0x30]

    v8 = str(input("v8입력: "))
    key = ""

    for i in range(0, int(len(v8)), 2) :
        val = int(v8[i:i+2], 16)
        current = v7[(i//2) % 3]
    
        xor = chr(val ^ current)
    
        key += xor

    
    print(f"{key}")
    


if __name__ == "__main__" :
    main()
