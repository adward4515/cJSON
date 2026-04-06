#include "cJSON.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    unsigned char *buf;
    while (__AFL_LOOP(10000)) {
        ssize_t size = read(0, NULL, 0);
        char input[8192];
        memset(input, 0, sizeof(input));
        read(0, input, sizeof(input) - 1);

        cJSON *json = cJSON_Parse(input);
        if (json != NULL) {
            char *rendered = cJSON_Print(json);
            if (rendered) {
                free(rendered);
            }
            cJSON_Delete(json);
        }
    }
    return 0;
}
