#include "csmith.h"

int64_t func_1(uint64_t *p_1,
               uint64_t v_2,
               uint64_t v_3,
               uint64_t v_4,
               uint64_t v_5,
               uint64_t v_6,
               uint64_t v_7,
               uint64_t v_8,
               uint64_t v_9)
{
    int64_t res = -1;

    // The following gives output 0
    //res = v_4 / res;
    //res = v_8 / res;
    
    // This produce output 1
    res = v_7 / res;

    return res;
}
