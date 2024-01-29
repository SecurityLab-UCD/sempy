#include "./test_func.c"

int32_t main()
{
    int32_t v_1 = 2000000;
    int32_t *p_1 = &v_1;
    int32_t res =  func_1(p_1);
    printf("%u\n", res);
    return res;
}