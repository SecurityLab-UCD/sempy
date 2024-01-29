#include "./test_func.c"

int32_t main()
{
    uint64_t v_1 = 1;
    uint64_t *p_1 = &v_1;

    uint64_t v_2 = 2;
    uint64_t v_3 = 3;
    uint64_t v_4 = 4;
    uint64_t v_5 = 5;
    uint64_t v_6 = 6;
    uint64_t v_7 = 7;
    uint64_t v_8 = 8;
    uint64_t v_9 = 9;
    uint64_t *p_9 = &v_9;


    uint64_t res = func_1(
        p_1,
        v_2,
        v_3,
        v_4,
        v_5,
        v_6,
        v_7,
        v_8,
        p_9);

    printf("%lu\n", res);
    return res;
}