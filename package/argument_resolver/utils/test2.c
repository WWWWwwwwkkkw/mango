#include <stdio.h>

// 第一个函数，返回一个常数值
int get_value() {
    return 10;
}

// 第二个函数，执行加法操作
int add_values(int a, int b) {
    return a + b;
}

int main() {
    // 获取来自另一个函数的值
    int value_from_another_function = get_value();
    
    // 执行加法操作
    int result = add_values(value_from_another_function, 5);
    
    // 打印结果
    printf("The result of the addition is: %d\n", result);
    
    return 0;
}
