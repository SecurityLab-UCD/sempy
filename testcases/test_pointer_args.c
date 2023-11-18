#include "csmith.h"

int32_t  func_1(uint32_t* p_1) {
    *p_1 = safe_add_func_uint32_t_u_u(*p_1, 1);
    return *p_1;
}

int32_t main()
{
    int32_t v_1 = 2000000;
    int32_t *p_1 = &v_1;
    int32_t res =  func_1(p_1);
    printf("%u\n", res);
    return res;
}