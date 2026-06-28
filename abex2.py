


def main() :
   name = input('시리얼로 변환할 이름 입력: ')
   serial =""
   
   for i in range(4) :
       char = name[i]
       
       change = ord(char) + 100
       val = hex(change)[2:].upper()
       
       serial += val

   print(serial)
   


if __name__ == "__main__" :
    main()
    