#include "csmith.h"

float_t func_1(
    float_t dividend,
    float_t divisor
)
{    
    float_t res = safe_div_func_float_f_f(dividend, divisor);
    res = safe_add_func_float_f_f(res, 1);
    return res;
}
