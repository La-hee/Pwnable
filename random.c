//문제 정답인 key값을 구하는 함수
//출력 key값을 그대로 복사해 random파일의 입력으로 넣으면 된다!
#include <stdio.h>
#include <stdlib.h>

int main() {
unsigned int seed = rand();
unsigned int exploit = 0xcafebabe;

unsigned int key = seed ^ exploit;

  //시드값 확인
printf("seed : %d \n", seed);
  //key값 출력
printf("key : %d", key);
}
