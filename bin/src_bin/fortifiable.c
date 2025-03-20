#include <stdio.h>
#include <string.h>

int main() {
    char buf[10];
    strcpy(buf, "Hi!");  // Fonction fortifiable
    printf("%s\n", buf);
    return 0;
}

