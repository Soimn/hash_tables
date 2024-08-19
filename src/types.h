typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define ARRAY_SIZE(A) (sizeof(A)/sizeof(0[A]))
#define CONCAT__(A, B) A##B
#define CONCAT_(A, B) CONCAT__(A, B)
#define CONCAT(A, B) CONCAT_(A, B)

typedef struct String
{
  char* data;
  u64 len;
} String;

#define STRING(S) (String){ .data = (S), .len = sizeof(S)-1 }

static bool
String_Match(String s0, String s1)
{
  bool result = (s0.len == s1.len);

  for (u64 i = 0; i < s0.len && result; ++i) result = (s0.data[i] == s1.data[i]);

  return result;
}

typedef u64 Hash_Func(String key);

typedef struct Key_Data_Pair
{
  String key;
  void* data;
} Key_Data_Pair;
