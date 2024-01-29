#include "./test_func.c"


int32_t main()
{
    int32_t v_1 = 2;
    int32_t *p_1 = &v_1;
    int32_t v_2 = 2;
    int32_t *p_2 = &v_2;

    uint64_t v_3 = 3;
    uint64_t v_4 = 4;

    uint64_t res = func_4(v_3, p_1, v_4, p_2);

    printf("%lu\n", res);
    return res;
}