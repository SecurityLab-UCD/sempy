#include "out.c"

int main()
{
    int32_t v_1 = 2000000;
    int32_t *p_1 = &v_1;
    printf("The value of num is: %d\n", func_1(p_1));
    printf("The value of *p_1 is: %d\n", *p_1);
}