#define _CRT_SECURE_NO_WARNINGS

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "types.h"

#define XXH_INLINE_ALL
#include "vendor/xxhash/xxhash.h"

static u64
Hash_XXH64(String key)
{
  return XXH3_64bits(key.data, key.len);
}

static bool
Char_IsAlpha(char c)
{
  return ((unsigned char)((c&0xDF) - 'A') <= (unsigned char)('Z' - 'A'));
}

#include "separate_chaining.h"
#include "separate_chaining_w_arrays.h"
#include "separate_chaining_one_array.h"
#include "open_addressing_linear_probing.h"

int
main(int argc, char** argv)
{
  OALP_Table table;
  OALP_Table_Create(Hash_XXH64, 1ULL << 16, &table);
  for (size_t run = 0; run < 100; ++run)
  {
    OALP_Table_Clear(&table);

    if (argc != 2)
    {
      fprintf(stderr, "Usage: hash_bench [path to text file]\n");
      return -1;
    }
    else
    {
      FILE* txt_file;
      if (fopen_s(&txt_file, argv[1], "rb") != 0)
      {
        fprintf(stderr, "Failed to open file\n");
        return -1;
      }
      else
      {
        fseek(txt_file, 0, SEEK_END);
        size_t txt_file_size = ftell(txt_file);
        rewind(txt_file);
    
        char* txt_buffer = (char*)malloc(txt_file_size+1);

        if (txt_buffer == 0 || fread(txt_buffer, txt_file_size, 1, txt_file) != 1) return -1;
        else
        {
          txt_buffer[txt_file_size] = 0;

          for (char* cur = txt_buffer;;)
          {
            while (*cur != 0 && !Char_IsAlpha(*cur)) ++cur;
            if (*cur == 0) break;

            char* start = cur;
            while (Char_IsAlpha(*cur)) ++cur;

            String word = { .data = start, .len = cur - start };

            u64 count = 0;
            OALP_Table_Get(&table, word, &count);
            OALP_Table_Put(&table, word, count + 1);
          }
        }

        fclose(txt_file);
      }
    }
  }

  OALP_Table_Destroy(&table);

  return 0;
}
