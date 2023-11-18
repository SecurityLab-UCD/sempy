#include "csmith.h"

int64_t func_1(uint32_t *p_1,
               uint32_t v_2,
               uint64_t v_3,
               uint64_t v_4,
               uint64_t v_5,
               uint64_t v_6,
               uint64_t v_7)
{
    *p_1 = safe_add_func_uint32_t_u_u(*p_1, 1);
    int64_t res = -1;
    res = safe_add_func_uint32_t_u_u(*p_1, res);
    res = safe_add_func_uint32_t_u_u(v_2, res);
    res = safe_add_func_uint32_t_u_u(v_3, res);
    res = safe_add_func_uint32_t_u_u(v_4, res);
    res = safe_add_func_uint32_t_u_u(v_5, res);
    res = safe_add_func_uint32_t_u_u(v_6, res);
    res = safe_add_func_uint32_t_u_u(v_7, res);
    
    return res;
}

int32_t main()
{
    int32_t v_1 = 1;
    int32_t *p_1 = &v_1;

    int32_t v_2 = 2;
    uint64_t v_3 = 3;
    uint64_t v_4 = 4;
    uint64_t v_5 = 5;
    uint64_t v_6 = 6;
    uint64_t v_7 = 7;

    uint64_t res = func_1(
        p_1,
        v_2,
        v_3,
        v_4,
        v_5,
        v_6,
        v_7);

    printf("%lu\n", res);
    return res;
}