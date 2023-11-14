#include "out.c"

int main()
{
    int32_t v_6 = 30;
    int32_t v_8 = 40;

    uint64_t p_5 = 10;
    int32_t *p_6 = &v_6;
    const uint32_t p_7 = 20;
    int32_t *p_8 = &v_8;
    printf("The value of num is: %d\n", func_4(p_5, p_6, p_7, p_8));
    printf("The value of *p_6 is: %d\n", *p_6);
    printf("The value of *p_8 is: %d\n", *p_8);
}