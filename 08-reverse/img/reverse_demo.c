#include <stdio.h>
#include <string.h>

// Проверка пароля: каждый символ XOR 0x2A должен дать эталон target[].
// Правильный пароль: secret99  (при верном вводе печатается флаг)
int check(const char *s) {
    unsigned char target[8] = {0x59,0x4f,0x49,0x58,0x4f,0x5e,0x13,0x13};
    if (strlen(s) != 8) return 0;
    for (int i = 0; i < 8; i++) {
        if (((unsigned char)s[i] ^ 0x2A) != target[i]) return 0;
    }
    return 1;
}

int main(void) {
    char buf[64];
    printf("Enter password: ");
    if (scanf("%63s", buf) != 1) return 1;
    if (check(buf)) printf("Correct! flag{r3v3rs3_m3}\n");
    else            printf("Wrong\n");
    return 0;
}
