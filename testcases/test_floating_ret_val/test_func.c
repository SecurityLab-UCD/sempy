#include "csmith.h"

float_t func_1(
    int32_t dividend,
    int32_t divisor
)
{    
    float_t res = safe_div_func_int32_t_s_s(dividend, divisor);
    res = safe_div_func_float_f_f(res, 1);
    return divisor;
}
