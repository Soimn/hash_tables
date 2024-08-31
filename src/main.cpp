#include "unordered_map.hpp"

#include <stdio.h>

static bool
Char_IsAlpha(char c)
{
  return ((unsigned char)((c&0xDF) - 'A') <= (unsigned char)('Z' - 'A'));
}

int
main(int argc, char** argv)
{
  std::unordered_map<String, u64, String_Hash_XXH64, String_Eq> map;
  map.reserve(1ULL << 15);
  for (size_t run = 0; run < 200; ++run)
  {
    map.clear();

    if (argc != 2)
    {
      fprintf(stderr, "Usage: hash_bench_cpp [path to text file]\n");
      return -1;
    }
    else
    {
      FILE* txt_file;
      if (fopen_s(&txt_file, argv[1], "rb") != 0) return -1;
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

            map[String(start, cur - start)] += 1;
          }
        }

        fclose(txt_file);
      }
    }
  }

  return 0;
}
