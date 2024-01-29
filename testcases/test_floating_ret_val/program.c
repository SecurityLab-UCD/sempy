#include "./test_func.c"

int32_t main()
{
    int32_t dividend = 5;
    int32_t divisor = 2;
    float_t res = func_1(dividend, divisor);

    printf("%f\n", res);
    return res;
}