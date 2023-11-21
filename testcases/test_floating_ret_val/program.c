#include "./test_func.c"

int32_t main()
{
    float_t dividend = 1;
    float_t divisor = 3;
    float_t res = func_1(dividend, divisor);

    printf("%f\n", res);
    return res;
}