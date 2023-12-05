#include "./test_func.c"

int32_t main()
{
    uint64_t v_1 = 1;
    uint64_t *p_1 = &v_1;

    uint64_t v_2 = 1;
    uint64_t v_3 = -1;
    uint64_t v_4 = 1;
    uint64_t v_5 = -1;
    uint64_t v_6 = 1;
    uint64_t v_7 = 1;
    uint64_t v_8 = 1;
    uint64_t v_9 = -1;
    uint64_t v_10 = -1;

    uint64_t res = func_1(
        p_1,
        v_2,
        v_3,
        v_4,
        v_5,
        v_6,
        v_7,
        v_8,
        v_9);

    printf("%lu\n", res);
    return res;
}