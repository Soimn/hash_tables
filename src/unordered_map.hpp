#include <unordered_map>
#include <stdint.h>

#define XXH_INLINE_ALL
#include "vendor/xxhash/xxhash.h"

typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct String
{
  char* data;
  u64 len;

  String(char* cstring)
  {
    this->data = cstring;
    this->len  = 0;
    for (char* scan = cstring; *scan != 0; ++scan) ++this->len;
  }

  bool operator==(const String& s1) const
  {
    bool result = (this->len == s1.len);

    for (u64 i = 0; i < this->len && result; ++i) result = (this->data[i] == s1.data[i]);

    return result;
  }
};

class String_Hash_XXH64
{
public:
  u64 operator()(const String& key) const
  {
    return XXH3_64bits(key.data, key.len);
  }
};

class String_Eq
{
public:
  bool operator()(const String& s0, const String& s1) const
  {
    return s0 == s1;
  }
};

struct Key_Data_Pair
{
  String key;
  void* data;
};

