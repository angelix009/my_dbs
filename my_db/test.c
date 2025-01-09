#include <stdio.h>

void func1(void)
{
    printf("test1\n");
}

void func2(void)
{
    printf("test2\n");
}

int main(void)
{
    puts("before breakpoint");
    __asm__("int3");
    func1();
    func2();
    puts("after breakpoint");
    return 0;
}
