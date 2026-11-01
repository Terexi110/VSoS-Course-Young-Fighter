#include <stdio.h>
#include <string.h>

int check(const char *s) {
    unsigned char t[] = {0x26,0x65,0x3c,0x73,0x41,0x68,0x52,0x68,0x30,0x6e};
    if (strlen(s) != 10) return 0;
    for (int i = 0; i < 10; i++) {
        unsigned char c = s[9 - i];        // берём символы с конца
        c = (c ^ (i * 3)) + 5;             // XOR с номером*3, потом +5
        if (c != t[i]) return 0;
    }
    return 1;
}

int main(void) {
    char buf[64];
    printf("Password: ");
    if (scanf("%63s", buf) != 1) return 1;
    if (check(buf)) puts("Correct! flag{th1nk_b4ckw4rds}");
    else puts("Wrong");
    return 0;
}
