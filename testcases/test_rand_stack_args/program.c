#include "./test_func.c"

int32_t main()
{
    uint64_t v_1 = 24047144;
    uint64_t *p_1 = &v_1;

    uint64_t v_2 = 43228604;
    uint64_t v_3 = -921521;
    uint64_t v_4 = 827519;
    uint64_t v_5 = -524606;
    uint64_t v_6 = 582689;
    uint64_t v_7 = 199105;
    uint64_t v_8 = 77008;
    uint64_t v_9 = -588857;
    uint64_t v_10 = -487722;

    uint64_t res = func_1(
        p_1,
        v_2,
        v_3,
        v_4,
        v_5,
        v_6,
        v_7,
        v_8,
        v_9,
        v_10);

    printf("%lu\n", res);
    return res;
}