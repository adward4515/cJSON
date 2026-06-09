#include "cJSON.h"
#include "cJSON_Utils.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__AFL_FUZZ_INIT();

int main(void)
{
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000))
    {
        size_t size = __AFL_FUZZ_TESTCASE_LEN;

        if (size < 4)
            continue;

        /* ============================================================
         * Target 1
         * cJSON_Minify
         * ============================================================ */
        {
            char *minify_buf = (char *)malloc(size + 1);

            if (minify_buf)
            {
                memcpy(minify_buf, buf, size);
                minify_buf[size] = '\0';

                cJSON_Minify(minify_buf);

                cJSON *tmp = cJSON_Parse(minify_buf);

                if (tmp)
                {
                    cJSON_Delete(tmp);
                }

                free(minify_buf);
            }
        }

        /* ============================================================
         * 建立 Null-Terminated Input
         * ============================================================ */
        char *input = (char *)malloc(size + 1);

        if (!input)
            continue;

        memcpy(input, buf, size);
        input[size] = '\0';

        /* ============================================================
         * Target 2
         * ParseWithOpts
         * ============================================================ */
        {
            const char *endptr = NULL;

            cJSON *opt_json =
                cJSON_ParseWithOpts(
                    input,
                    &endptr,
                    0);

            if (opt_json)
            {
                cJSON_Delete(opt_json);
            }

            opt_json =
                cJSON_ParseWithOpts(
                    input,
                    &endptr,
                    1);

            if (opt_json)
            {
                cJSON_Delete(opt_json);
            }
        }

        /* ============================================================
         * 主解析流程
         * ============================================================ */
        cJSON *json1 = cJSON_Parse(input);

        free(input);

        if (!json1)
            continue;

        /* ============================================================
         * Target 3
         * Print Round Trip
         * ============================================================ */

        {
            char *printed = cJSON_Print(json1);

            if (printed)
            {
                cJSON *again = cJSON_Parse(printed);

                if (again)
                {
                    cJSON_Delete(again);
                }

                free(printed);
            }
        }

        {
            char *printed =
                cJSON_PrintUnformatted(json1);

            if (printed)
            {
                cJSON *again = cJSON_Parse(printed);

                if (again)
                {
                    cJSON_Delete(again);
                }

                free(printed);
            }
        }

        {
            char *printed =
                cJSON_PrintBuffered(
                    json1,
                    256,
                    1);

            if (printed)
            {
                cJSON *again = cJSON_Parse(printed);

                if (again)
                {
                    cJSON_Delete(again);
                }

                free(printed);
            }
        }

        /* ============================================================
         * Target 4
         * SortObject
         * ============================================================ */

#ifdef CJSON_UTILS_H

        if (cJSON_IsObject(json1))
        {
            cJSONUtils_SortObject(json1);
        }

#endif

        /* ============================================================
         * 建立 json2
         * ============================================================ */

        cJSON *json2 =
            cJSON_Duplicate(json1, 1);

        if (json2)
        {
            /*
             * 根據型別做變異
             */

            if (cJSON_IsObject(json2))
            {
                cJSON_AddStringToObject(
                    json2,
                    "fuzz_str",
                    "AFL_MUTATION");

                cJSON_AddNumberToObject(
                    json2,
                    "fuzz_num",
                    (double)size);
            }
            else if (cJSON_IsArray(json2))
            {
                cJSON_AddItemToArray(
                    json2,
                    cJSON_CreateNumber(
                        (double)size));

                if (cJSON_GetArraySize(json2) > 0)
                {
                    cJSON_DeleteItemFromArray(
                        json2,
                        0);
                }
            }

            /* ========================================================
             * Target 5
             * Compare
             * ======================================================== */

            cJSON_Compare(
                json1,
                json2,
                1);

            cJSON_Compare(
                json1,
                json2,
                0);

            /* ========================================================
             * Target 6
             * RFC6902 GeneratePatches
             * ======================================================== */

            cJSON *patches =
                cJSONUtils_GeneratePatches(
                    json1,
                    json2);

            if (patches)
            {
                cJSON *json1_copy =
                    cJSON_Duplicate(
                        json1,
                        1);

                if (json1_copy)
                {
                    cJSONUtils_ApplyPatches(
                        json1_copy,
                        patches);

                    cJSON_Delete(
                        json1_copy);
                }

                cJSON_Delete(
                    patches);
            }

            /* ========================================================
             * Target 7
             * RFC7386 Merge Patch
             * ======================================================== */

            cJSON *merge_patch =
                cJSONUtils_GenerateMergePatch(
                    json1,
                    json2);

            if (merge_patch)
            {
                cJSON *json1_copy =
                    cJSON_Duplicate(
                        json1,
                        1);

                if (json1_copy)
                {
                    json1_copy =
                        cJSONUtils_MergePatch(
                            json1_copy,
                            merge_patch);

                    if (json1_copy)
                    {
                        cJSON_Delete(
                            json1_copy);
                    }
                }

                cJSON_Delete(
                    merge_patch);
            }

            cJSON_Delete(json2);
        }

        /* ============================================================
         * Target 8
         * RFC6901 Pointer
         * ============================================================ */

        if (json1->child)
        {
            cJSON *target = json1->child;

            /*
             * 嘗試往後走幾步
             * 增加不同節點覆蓋率
             */

            if ((size & 1) && target->next)
                target = target->next;

            if ((size & 2) && target->next)
                target = target->next;

            char *ptr =
                cJSONUtils_FindPointerFromObjectTo(
                    json1,
                    target);

            if (ptr)
            {
                cJSON *result =
                    cJSONUtils_GetPointer(
                        json1,
                        ptr);

                (void)result;

                free(ptr);
            }
        }

        cJSON_Delete(json1);
    }

    return 0;
}
