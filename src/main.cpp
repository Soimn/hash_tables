// I really wish C had proper metaprogramming, because this is getting ridiculous

#include <windows.h>
#include <stdio.h>
#include <unordered_map>
#include <vector>

#include <vendor/ankerl/unordered_dense.h>

#define XXH_INLINE_ALL
#include "vendor/xxhash/xxhash.h"

typedef signed __int8  s8;
typedef signed __int16 s16;
typedef signed __int32 s32;
typedef signed __int64 s64;

typedef unsigned __int8  u8;
typedef unsigned __int16 u16;
typedef unsigned __int32 u32;
typedef unsigned __int64 u64;

typedef float f32;
typedef double f64;

#define ARRAY_SIZE(A) (sizeof(A)/sizeof(0[A]))

#define CONCAT__(A, B) A##B
#define CONCAT_(A, B) CONCAT__(A, B)
#define CONCAT(A, B) CONCAT_(A, B)

#define USE_SSO 0
#define USE_FNV1A 0

#if !USE_SSO
struct String
{
  u64 len;
  u8* data;

  String(u8* data, u64 len)
  {
    this->data = data;
    this->len  = len;
  }

  u16 Prefix() const
  {
    u16 result;
    if      (this->len > 1) result = *(u16*)this->data;
    else if (this->len > 0) result = this->data[0];
    else                    result = 0;
    return result;
  }

  u64 Hash() const
  {
    u64 len  = this->len;
    u8* data = this->data;
    
#if USE_FNV1A
    return FNV1A(data, len);
#else
    return XXH3_64bits(data, len);
#endif
  }

  bool operator == (const String& s1) const
  {
    bool result = (this->len == s1.len);

    for (u64 i = 0; i < this->len && result; ++i)
    {
      result = (this->data[i] == s1.data[i]);
    }

    return result;
  }
};
#else
struct String
{
  u64 len;
  u8* data;

  String(u8* data, u64 len)
  {
    if (len <= 16)
    {
      this->len  = 0;
      this->data = 0;
      memcpy(&this->len, data, 8);
      memcpy(&this->data, data + 8, 8);
      this->len |= (1ULL << 63);
    }
    else
    {
      this->data = data;
      this->len  = len;
    }
  }

  u64 Hash() const
  {
    u64 len  = this->len;
    u8* data = this->data;
    if ((s64)this->len < 0)
    {
      len = 16;
      data = (u8*)&this->len;
    }
    
#if USE_FNV1A
    return FNV1A(data, len);
#else
    return XXH3_64bits(data, len);
#endif
  }

  bool operator == (const String& s1) const
  {
    if ((s64)this->len < 0 && (s64)s1.len < 0)
    {
      return (this->len == s1.len && this->data == s1.data);
    }
    else
    {
      u64 s0_len  = this->len;
      u8* s0_data = this->data;
      if ((s64)this->len < 0)
      {
        s0_len = 16;
        s0_data = (u8*)&this->len;
      }

      u64 s1_len  = s1.len;
      u8* s1_data = s1.data;
      if ((s64)s1.len < 0)
      {
        s1_len = 16;
        s1_data = (u8*)&s1.len;
      }

      bool result = (s0_len == s1_len && (s0_data[0]&0x7F) == (s1_data[0]&0x7F));

      for (u64 i = 1; i < s0_len && result; ++i)
      {
        result = (s0_data[i] == s1_data[i]);
      }

      return result;
    }
  }
};
#endif

static u64
FNV1A(u8* data, u64 len)
{
  u64 hash = 14695981039346656037;
  for (u64 i = 0; i < len; ++i)
  {
    hash ^= data[i];
    hash *= 1099511628211;
  }

  return hash;
}

static inline u64
FNV1A_MapToIdx(u64 hash, u64 bits)
{
  return ((hash >> bits) ^ hash) & ((1ULL << bits)-1);
}

template <>
struct ankerl::unordered_dense::hash<String>
{
  using is_avalanching = void;

  [[nodiscard]] auto operator () (const String& s) const noexcept -> u64
  {
    return s.Hash();
  }
};

static bool
Char_IsAlpha(u8 c)
{
  return ((u8)((c&0xDF) - 'A') <= (u8)('Z' - 'A'));
}

static bool
Char_IsDigit(u8 c)
{
  return ((u8)(c - '0') < (u8)10);
}

#define TOKEN_KIND__BLOCK_SIZE_LG2 6
#define TOKEN_KIND__BLOCK(N) ((N) << TOKEN_KIND__BLOCK_SIZE_LG2)
#define TOKEN_KIND__BLOCK_IDX(N) ((N) >> TOKEN_KIND__BLOCK_SIZE_LG2)
#define TOKEN_KIND__ASS_BIT TOKEN_KIND__BLOCK(8)

#define TOKEN_KIND__IS_BINARY(K) ((u32)((K) - Token__FirstBinary) <= (u32)(Token__PastLastBinary - Token__FirstBinary))
#define TOKEN_KIND__IS_BINARY_ASSIGNMENT(K) ((u32)((K) - Token__FirstAssignment) <= (u32)(Token__PastLastAssignment - Token__FirstAssignment))

typedef enum Token_Kind
{
  Token_Error = 0,
  Token_Invalid,
  Token_EOF,

  Token_Mul = TOKEN_KIND__BLOCK(3),                       // *
  Token__FirstBinary = Token_Mul,
  Token__FirstMulLevel = Token__FirstBinary,
  Token_Div,                                              // /
  Token_Rem,                                              // %
  Token_And,                                              // &
  Token_Shl,                                              // <<
  Token_Shr,                                              // >>
  Token__PastLastMulLevel,

  Token_Add = TOKEN_KIND__BLOCK(4),                       // +
  Token__FirstAddLevel = Token_Add,
  Token_Sub,                                              // -
  Token_Or,                                               // |
  Token_Xor,                                              // ~
  Token__PastLastAddLevel,

  Token_EQEQ = TOKEN_KIND__BLOCK(5),                      // ==
  Token__FirstCmpLevel = Token_EQEQ,
  Token_LNotEQ,                                           // !=
  Token_Le,                                               // <
  Token_LeEQ,                                             // <=
  Token_Ge,                                               // >
  Token_GeEQ,                                             // >=
  Token__PastLastCmpLevel,

  Token_LAnd = TOKEN_KIND__BLOCK(6),                      // &&
  Token__FirstLAndLevel = Token_LAnd,
  Token__PastLastLAndLevel,

  Token_LOr = TOKEN_KIND__BLOCK(7),                       // ||
  Token__FirstLOrLevel = Token_LOr,
  Token__PastLastLOrLevel,
  Token__PastLastBinary = Token__PastLastLOrLevel,

  Token_MulEQ = TOKEN_KIND__BLOCK(8 + 3),                 // *=
  Token__FirstAssignment = Token_MulEQ,
  Token__FirstMulLevelAssignment = Token__FirstAssignment,
  Token_DivEQ,                                            // /=
  Token_RemEQ,                                            // %=
  Token_AndEQ,                                            // &=
  Token_ShlEQ,                                            // <<=
  Token_ShrEQ,                                            // >>=
  Token__PastLastMulLevelAssignment,

  Token_AddEQ = TOKEN_KIND__BLOCK(8 + 4),                 // +=
  Token__FirstAddLevelAssignment = Token_AddEQ,
  Token_SubEQ,                                            // -=
  Token_OrEQ,                                             // |=
  Token_XorEQ,                                            // ~=
  Token__PastLastAddLevelAssignment,

  Token_EQ,                                               // =
  Token__PastLastAssignment,

  Token_LNot,                                             // !
  Token_Cash,                                             // $
  Token_QMark,                                            // ?
  Token_Colon,                                            // :
  Token_Comma,                                            // ,
  Token_Semicolon,                                        // ;
  Token_Hat,                                              // ^
  Token_OpenParen,                                        // (
  Token_CloseParen,                                       // )
  Token_OpenBracket,                                      // [
  Token_CloseBracket,                                     // ]
  Token_OpenBrace,                                        // {
  Token_CloseBrace,                                       // }
  Token_Dot,                                              // .
  Token_Pound,                                            // #

  Token_Ident,
  Token_String,
  Token_Char,
  Token_Int,
} Token_Kind;

typedef struct Token
{
  Token_Kind kind;
  u32 offset;
  u32 len;
  u32 line;
  u32 col;

  union
  {
    u64 integer;
    f64 floating;
    String string;
  };
} Token;

typedef struct Lexer
{
  u8* input;
  u8* cursor;
  u8* start_of_line;
  u32 line;
  Token token;
} Lexer;

static bool
Lexer_Init(char* filename, Lexer* lexer)
{
  *lexer = {
    0,
    0,
    0,
    1,
    { Token_Invalid },
  };

  HANDLE file = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
  LARGE_INTEGER size;

  if (file != INVALID_HANDLE_VALUE && GetFileSizeEx(file, &size) && size.HighPart == 0)
  {
    lexer->input = (u8*)VirtualAlloc(0, size.LowPart + 1, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

    DWORD read_bytes = 0;
    if (lexer->input != 0 && ReadFile(file, lexer->input, size.LowPart, &read_bytes, 0) && read_bytes == size.LowPart)
    {
      lexer->input[size.LowPart] = 0;

      lexer->cursor        = lexer->input;
      lexer->start_of_line = lexer->input;
      lexer->token         = { Token_Invalid };
    }
  }

  CloseHandle(file);

  return lexer;
}

static void
Lexer_Reset(Lexer* lexer)
{
  lexer->cursor        = lexer->input;
  lexer->start_of_line = lexer->input;
  lexer->token         = { Token_Invalid };
}

static Token
Lexer_NextToken(Lexer* lexer)
{
  if (lexer->token.kind == Token_Error || lexer->token.kind == Token_EOF) return lexer->token;

  Token token = { Token_Error };

  bool encountered_errors = false;

  for (;;)
  {
    // NOTE: All characters in the range [0x1, 0x20] are considered whitespace
    while ((u8)(*lexer->cursor-1) < (u8)0x20)
    {
      if (*lexer->cursor == '\n')
      {
        lexer->line         += 1;
        lexer->start_of_line = lexer->cursor + 1;
      }

      ++lexer->cursor;
    }

    if (lexer->cursor[0] == '/' && lexer->cursor[1] == '/')
    {
      lexer->cursor += 2;
      while (*lexer->cursor != 0 && *lexer->cursor != '\n') ++lexer->cursor;
    }
    else if (lexer->cursor[0] == '/' && lexer->cursor[1] == '*')
    {
      lexer->cursor += 2;
      while (lexer->cursor[0] != 0 && !(lexer->cursor[0] == '*' && lexer->cursor[1] == '/'))
      {
        if (*lexer->cursor == '\n')
        {
          lexer->line         += 1;
          lexer->start_of_line = lexer->cursor + 1;
        }

        ++lexer->cursor;
      }
    }
    else break;
  }

  u8* start_of_token = lexer->cursor;

  if (*lexer->cursor == 0) token.kind = Token_EOF;
  else
  {
    u8 c = *lexer->cursor;
    lexer->cursor += 1;

    u8 c1_eq      = (*lexer->cursor == '=');
    u32 c1_eq_bit = (*lexer->cursor == '=' ? TOKEN_KIND__ASS_BIT : 0);

    switch (c)
    {
			case '$': token.kind = Token_Cash;         break;
			case '?': token.kind = Token_QMark;        break;
			case ':': token.kind = Token_Colon;        break;
			case ',': token.kind = Token_Comma;        break;
			case ';': token.kind = Token_Semicolon;    break;
			case '^': token.kind = Token_Hat;          break;
			case '(': token.kind = Token_OpenParen;    break;
			case ')': token.kind = Token_CloseParen;   break;
			case '[': token.kind = Token_OpenBracket;  break;
			case ']': token.kind = Token_CloseBracket; break;
			case '{': token.kind = Token_OpenBrace;    break;
			case '}': token.kind = Token_CloseBrace;   break;
			case '.': token.kind = Token_Dot;          break;
			case '#': token.kind = Token_Pound;        break;

      case '*': { token.kind = (Token_Kind)(Token_Mul | c1_eq_bit); lexer->cursor += c1_eq; } break;
      case '/': { token.kind = (Token_Kind)(Token_Div | c1_eq_bit); lexer->cursor += c1_eq; } break;
      case '%': { token.kind = (Token_Kind)(Token_Rem | c1_eq_bit); lexer->cursor += c1_eq; } break;
      case '~': { token.kind = (Token_Kind)(Token_Xor | c1_eq_bit); lexer->cursor += c1_eq; } break;
      case '+': { token.kind = (Token_Kind)(Token_Add | c1_eq_bit); lexer->cursor += c1_eq; } break;
      case '-': { token.kind = (Token_Kind)(Token_Sub | c1_eq_bit); lexer->cursor += c1_eq; } break;

      case '=':
      {
        token.kind     = (c1_eq ? Token_EQEQ : Token_EQ);
        lexer->cursor += c1_eq;
      } break;

      case '!':
      {
        token.kind     = (c1_eq ? Token_LNotEQ : Token_LNot);
        lexer->cursor += c1_eq;
      } break;

      case '&':
      {
        if (lexer->cursor[0] == '&')
        {
          token.kind     = Token_LAnd;
          lexer->cursor += 1;
        }
        else
        {
          token.kind     = (Token_Kind)(Token_And | c1_eq_bit);
          lexer->cursor += c1_eq;
        }
      } break;

      case '|':
      {
        if (lexer->cursor[0] == '|')
        {
          token.kind     = Token_LOr;
          lexer->cursor += 1;
        }
        else
        {
          token.kind     = (Token_Kind)(Token_Or | c1_eq_bit);
          lexer->cursor += c1_eq;
        }
      } break;

      case '<':
      {
        if (lexer->cursor[0] == '<')
        {
          if (lexer->cursor[1] == '=')
          {
            token.kind = Token_ShlEQ;
            lexer->cursor += 2;
          }
          else
          {
            token.kind = Token_Shl;
            lexer->cursor += 1;
          }
        }
        else
        {
          token.kind     = (Token_Kind)(Token_Le + c1_eq);
          lexer->cursor += c1_eq;
        }
      } break;

      case '>':
      {
        if (lexer->cursor[0] == '>')
        {
          if (lexer->cursor[1] == '=')
          {
            token.kind = Token_ShrEQ;
            lexer->cursor += 2;
          }
          else
          {
            token.kind = Token_Shr;
            lexer->cursor += 1;
          }
        }
        else
        {
          token.kind     = (Token_Kind)(Token_Ge + c1_eq);
          lexer->cursor += c1_eq;
        }
      } break;

      default:
      {
        if (c == '_' || Char_IsAlpha(c))
        {
          while (*lexer->cursor == '_' || Char_IsAlpha(*lexer->cursor) || Char_IsDigit(*lexer->cursor)) ++lexer->cursor;

          String ident_string(start_of_token, lexer->cursor - start_of_token);

          token.kind   = Token_Ident;
          token.string = ident_string;
        }
        else if (Char_IsDigit(c))
        {
          u64 base    = 10;
          u64 integer = c & 0xF;

          if (c == '0' && (*lexer->cursor&0xDF) == 'X')
          {
            base        = 16;
            integer     = 0;
            ++lexer->cursor;
          }
          else if (c == '0')
          {
            base = 8;
          }

          for (;;)
          {
            u64 digit = 0;
            if      (Char_IsDigit(*lexer->cursor) && (*lexer->cursor&0xF) < base)        digit = *lexer->cursor & 0xF;
            else if (base == 16 && (u8)((*lexer->cursor&0xDF) - 'A') <= (u8)('F' - 'A')) digit = 9 + (*lexer->cursor & 0x7);
            else break;

            integer = integer*base + digit;
            ++lexer->cursor;
          }

          if      ((lexer->cursor[0]&0xDF) == 'U' && (lexer->cursor[1]&0xDF) == 'L' && (lexer->cursor[2]&0xDF) == 'L') lexer->cursor += 3;
          else if ((lexer->cursor[0]&0xDF) == 'U' && (lexer->cursor[1]&0xDF) == 'L')                                   lexer->cursor += 2;
          else if ((lexer->cursor[0]&0xDF) == 'U')                                                                     lexer->cursor += 1;
          else if ((lexer->cursor[0]&0xDF) == 'L' && (lexer->cursor[1]&0xDF) == 'L' && (lexer->cursor[2]&0xDF) == 'U') lexer->cursor += 3;
          else if ((lexer->cursor[0]&0xDF) == 'L' && (lexer->cursor[1]&0xDF) == 'U')                                   lexer->cursor += 2;
          else if ((lexer->cursor[0]&0xDF) == 'L')                                                                     lexer->cursor += 1;

          token.kind    = Token_Int;
          token.integer = integer;
        }
        else if (c == '"' || c == '\'')
        {
          while (*lexer->cursor != 0 && *lexer->cursor != c)
          {
            if (lexer->cursor[0] == '\\' && lexer->cursor[1] != 0) lexer->cursor += 2;
            else                                                   lexer->cursor += 1;
          }

          if (*lexer->cursor == 0)
          {
            fprintf(stderr, "Unterminated string\n");
            ExitProcess(-1);
          }

          String string(start_of_token, lexer->cursor - (start_of_token+1));
          lexer->cursor += 1;

          token.kind   = Token_String;
          token.string = string;
        }
        else
        {
          token.kind = Token_Invalid;
        }
      } break;
    }
  }

  token.offset   = (u32)(start_of_token - lexer->input);
  token.len      = (u32)(lexer->cursor - start_of_token);
  token.line     = lexer->line;
  token.col      = (u32)(start_of_token - lexer->start_of_line) + 1;

  if (encountered_errors) token.kind = Token_Error;

  lexer->token = token;

  return token;
}

#define MAX_STRING_COUNT_LG2 23
#define MAX_STRING_COUNT (1ULL << 23)

typedef struct LP__Entry
{
  u64 hash;
  u32 id;
  String string;
} LP__Entry;

typedef struct LP_Table
{
  u32 table_mask;
  u32 entry_count;
  LP__Entry* entries;
} LP_Table;

static LP_Table
LP_Create(u8 table_size_lg2)
{
  u32 table_size = 1UL << table_size_lg2;

  LP__Entry* entries = (LP__Entry*)VirtualAlloc(0, table_size*sizeof(LP__Entry), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  return { table_size-1, 0, entries };
}

static void
LP_Destroy(LP_Table* table)
{
  VirtualFree(table->entries, 0, MEM_RELEASE);
  *table = {};
}

static void
LP_Clear(LP_Table* table)
{
  memset(table->entries, 0, (table->table_mask+1)*sizeof(LP__Entry));
  table->entry_count = 0;
}

static u32
LP_Put(LP_Table* table, String s)
{
  u64 hash = s.Hash();
  u64 idx  = hash & table->table_mask;

  if (hash == 0) hash = 1;

  while (table->entries[idx].hash != 0)
  {
    if (table->entries[idx].hash == hash && table->entries[idx].string == s) break;
    idx += 1;
    if (idx > table->table_mask) idx = 0;
  }

  if (table->entries[idx].hash == 0)
  {
    table->entries[idx] = {
      hash,
      table->entry_count,
      s,
    };

    table->entry_count += 1;
  }

  return table->entries[idx].id;
}

typedef struct QP__Entry
{
  u64 hash;
  u32 id;
  String string;
} QP__Entry;

typedef struct QP_Table
{
  u32 table_mask;
  u32 entry_count;
  QP__Entry* entries;
} QP_Table;

static QP_Table
QP_Create(u8 table_size_lg2)
{
  u32 table_size = 1UL << table_size_lg2;

  QP__Entry* entries = (QP__Entry*)VirtualAlloc(0, table_size*sizeof(QP__Entry), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  return { table_size-1, 0, entries };
}

static void
QP_Destroy(QP_Table* table)
{
  VirtualFree(table->entries, 0, MEM_RELEASE);
  *table = {};
}

static void
QP_Clear(QP_Table* table)
{
  memset(table->entries, 0, (table->table_mask+1)*sizeof(QP__Entry));
  table->entry_count = 0;
}

static u32
QP_Put(QP_Table* table, String s)
{
  u64 hash = s.Hash();
  u64 idx  = hash & table->table_mask;
  u64 step = 1;

  if (hash == 0) hash = 1;

  while (table->entries[idx].hash != 0)
  {
    if (table->entries[idx].hash == hash && table->entries[idx].string == s) break;
    idx = (idx + step++) & table->table_mask;
  }

  if (table->entries[idx].hash == 0)
  {
    table->entries[idx] = {
      hash,
      table->entry_count,
      s,
    };

    table->entry_count += 1;
  }

  return table->entries[idx].id;
}

typedef struct LPI__Entry
{
  u64 hash;
  u32 id;
} LPI__Entry;

typedef struct LPI_Table
{
  u32 table_mask;
  u32 entry_count;
  LPI__Entry* entries;
  String* strings;
} LPI_Table;

static LPI_Table
LPI_Create(u8 table_size_lg2)
{
  u32 table_size = 1UL << table_size_lg2;

  LPI__Entry* entries = (LPI__Entry*)VirtualAlloc(0, table_size*sizeof(LPI__Entry), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  String* strings     = (String*)VirtualAlloc(0, table_size*sizeof(String), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  return { table_size-1, 0, entries, strings };
}

static void
LPI_Destroy(LPI_Table* table)
{
  VirtualFree(table->entries, 0, MEM_RELEASE);
  VirtualFree(table->strings, 0, MEM_RELEASE);
  *table = {};
}

static void
LPI_Clear(LPI_Table* table)
{
  memset(table->entries, 0, (table->table_mask+1)*sizeof(LPI__Entry));
  table->entry_count = 0;
}

static u32
LPI_Put(LPI_Table* table, String s)
{
  u64 hash = s.Hash();
  u64 idx  = hash & table->table_mask;

  if (hash == 0) hash = 1;

  while (table->entries[idx].hash != 0)
  {
    if (table->entries[idx].hash == hash && table->strings[table->entries[idx].id] == s) break;
    idx += 1;
    if (idx > table->table_mask) idx = 0;
  }

  if (table->entries[idx].hash == 0)
  {
    table->entries[idx] = {
      hash,
      table->entry_count,
    };

    table->strings[table->entry_count] = s;

    table->entry_count += 1;
  }

  return table->entries[idx].id;
}

typedef struct QPI__Entry
{
  u64 hash;
  u32 id;
} QPI__Entry;

typedef struct QPI_Table
{
  u32 table_mask;
  u32 entry_count;
  QPI__Entry* entries;
  String* strings;
} QPI_Table;

static QPI_Table
QPI_Create(u8 table_size_lg2)
{
  u32 table_size = 1UL << table_size_lg2;

  QPI__Entry* entries = (QPI__Entry*)VirtualAlloc(0, table_size*sizeof(QPI__Entry), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  String* strings     = (String*)VirtualAlloc(0, table_size*sizeof(String), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  return { table_size-1, 0, entries, strings };
}

static void
QPI_Destroy(QPI_Table* table)
{
  VirtualFree(table->entries, 0, MEM_RELEASE);
  VirtualFree(table->strings, 0, MEM_RELEASE);
  *table = {};
}

static void
QPI_Clear(QPI_Table* table)
{
  memset(table->entries, 0, (table->table_mask+1)*sizeof(QPI__Entry));
  table->entry_count = 0;
}

static u32
QPI_Put(QPI_Table* table, String s)
{
  u64 hash = s.Hash();
  u64 idx  = hash & table->table_mask;
  u64 step = 1;

  if (hash == 0) hash = 1;

  while (table->entries[idx].hash != 0)
  {
    if (table->entries[idx].hash == hash && table->strings[table->entries[idx].id] == s) break;
    idx = (idx + step++) & table->table_mask;
  }

  if (table->entries[idx].hash == 0)
  {
    table->entries[idx] = {
      hash,
      table->entry_count,
    };

    table->strings[table->entry_count] = s;

    table->entry_count += 1;
  }

  return table->entries[idx].id;
}

typedef struct LPIP__Entry
{
  u64 hash;
  u32 id;
  u16 prefix;
} LPIP__Entry;

typedef struct LPIP_Table
{
  u32 table_mask;
  u32 entry_count;
  LPIP__Entry* entries;
  String* strings;
} LPIP_Table;

static LPIP_Table
LPIP_Create(u8 table_size_lg2)
{
  u32 table_size = 1UL << table_size_lg2;

  LPIP__Entry* entries = (LPIP__Entry*)VirtualAlloc(0, table_size*sizeof(LPIP__Entry), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  String* strings     = (String*)VirtualAlloc(0, table_size*sizeof(String), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  return { table_size-1, 0, entries, strings };
}

static void
LPIP_Destroy(LPIP_Table* table)
{
  VirtualFree(table->entries, 0, MEM_RELEASE);
  VirtualFree(table->strings, 0, MEM_RELEASE);
  *table = {};
}

static void
LPIP_Clear(LPIP_Table* table)
{
  memset(table->entries, 0, (table->table_mask+1)*sizeof(LPIP__Entry));
  table->entry_count = 0;
}

static u32
LPIP_Put(LPIP_Table* table, String s)
{
  u64 hash = s.Hash();
  u64 idx  = hash & table->table_mask;

  if (hash == 0) hash = 1;

  u16 s_prefix = s.Prefix();
  while (table->entries[idx].hash != 0)
  {
    if (table->entries[idx].hash == hash && table->entries[idx].prefix == s_prefix && table->strings[table->entries[idx].id] == s) break;
    idx += 1;
    if (idx > table->table_mask) idx = 0;
  }

  if (table->entries[idx].hash == 0)
  {
    table->entries[idx] = {
      hash,
      table->entry_count,
      s.Prefix(),
    };

    table->strings[table->entry_count] = s;

    table->entry_count += 1;
  }

  return table->entries[idx].id;
}

typedef struct QPIP__Entry
{
  u64 hash;
  u32 id;
  u16 prefix;
} QPIP__Entry;

typedef struct QPIP_Table
{
  u32 table_mask;
  u32 entry_count;
  QPIP__Entry* entries;
  String* strings;
} QPIP_Table;

static QPIP_Table
QPIP_Create(u8 table_size_lg2)
{
  u32 table_size = 1UL << table_size_lg2;

  QPIP__Entry* entries = (QPIP__Entry*)VirtualAlloc(0, table_size*sizeof(QPIP__Entry), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  String* strings     = (String*)VirtualAlloc(0, table_size*sizeof(String), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  return { table_size-1, 0, entries, strings };
}

static void
QPIP_Destroy(QPIP_Table* table)
{
  VirtualFree(table->entries, 0, MEM_RELEASE);
  VirtualFree(table->strings, 0, MEM_RELEASE);
  *table = {};
}

static void
QPIP_Clear(QPIP_Table* table)
{
  memset(table->entries, 0, (table->table_mask+1)*sizeof(QPIP__Entry));
  table->entry_count = 0;
}

static u32
QPIP_Put(QPIP_Table* table, String s)
{
  u64 hash = s.Hash();
  u64 idx  = hash & table->table_mask;
  u64 step = 1;

  if (hash == 0) hash = 1;

  u16 s_prefix = s.Prefix();
  while (table->entries[idx].hash != 0)
  {
    if (table->entries[idx].hash == hash && table->entries[idx].prefix == s_prefix && table->strings[table->entries[idx].id] == s) break;
    idx = (idx + step++) & table->table_mask;
  }

  if (table->entries[idx].hash == 0)
  {
    table->entries[idx] = {
      hash,
      table->entry_count,
      s.Prefix(),
    };

    table->strings[table->entry_count] = s;

    table->entry_count += 1;
  }

  return table->entries[idx].id;
}

typedef struct LPP__Entry
{
  u64 hash;
  u32 id;
  u16 prefix;
  String string;
} LPP__Entry;

typedef struct LPP_Table
{
  u32 table_mask;
  u32 entry_count;
  LPP__Entry* entries;
} LPP_Table;

static LPP_Table
LPP_Create(u8 table_size_lg2)
{
  u32 table_size = 1UL << table_size_lg2;

  LPP__Entry* entries = (LPP__Entry*)VirtualAlloc(0, table_size*sizeof(LPP__Entry), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  return { table_size-1, 0, entries };
}

static void
LPP_Destroy(LPP_Table* table)
{
  VirtualFree(table->entries, 0, MEM_RELEASE);
  *table = {};
}

static void
LPP_Clear(LPP_Table* table)
{
  memset(table->entries, 0, (table->table_mask+1)*sizeof(LPP__Entry));
  table->entry_count = 0;
}

static u32
LPP_Put(LPP_Table* table, String s)
{
  u64 hash = s.Hash();
  u64 idx  = hash & table->table_mask;

  if (hash == 0) hash = 1;

  u16 s_prefix = s.Prefix();
  while (table->entries[idx].hash != 0)
  {
    if (table->entries[idx].hash == hash && table->entries[idx].prefix == s_prefix && table->entries[idx].string == s) break;
    idx += 1;
    if (idx > table->table_mask) idx = 0;
  }

  if (table->entries[idx].hash == 0)
  {
    table->entries[idx] = {
      hash,
      table->entry_count,
      s.Prefix(),
      s,
    };

    table->entry_count += 1;
  }

  return table->entries[idx].id;
}

typedef struct QPP__Entry
{
  u64 hash;
  u32 id;
  u16 prefix;
  String string;
} QPP__Entry;

typedef struct QPP_Table
{
  u32 table_mask;
  u32 entry_count;
  QPP__Entry* entries;
} QPP_Table;

static QPP_Table
QPP_Create(u8 table_size_lg2)
{
  u32 table_size = 1UL << table_size_lg2;

  QPP__Entry* entries = (QPP__Entry*)VirtualAlloc(0, table_size*sizeof(QPP__Entry), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  return { table_size-1, 0, entries };
}

static void
QPP_Destroy(QPP_Table* table)
{
  VirtualFree(table->entries, 0, MEM_RELEASE);
  *table = {};
}

static void
QPP_Clear(QPP_Table* table)
{
  memset(table->entries, 0, (table->table_mask+1)*sizeof(QPP__Entry));
  table->entry_count = 0;
}

static u32
QPP_Put(QPP_Table* table, String s)
{
  u64 hash = s.Hash();
  u64 idx  = hash & table->table_mask;
  u64 step = 1;

  if (hash == 0) hash = 1;

  u16 s_prefix = s.Prefix();
  while (table->entries[idx].hash != 0)
  {
    if (table->entries[idx].hash == hash && table->entries[idx].prefix == s_prefix && table->entries[idx].string == s) break;
    idx = (idx + step++) & table->table_mask;
  }

  if (table->entries[idx].hash == 0)
  {
    table->entries[idx] = {
      hash,
      table->entry_count,
      s.Prefix(),
      s,
    };

    table->entry_count += 1;
  }

  return table->entries[idx].id;
}

typedef struct QPS__Entry
{
  u64 hash;
  u32 id;
  u16 len;
  u16 pad;
  u8* data;
  u8* ptr_pad;
} QPS__Entry;

typedef struct QPS_Table
{
  u32 table_mask;
  u32 entry_count;
  QPS__Entry* entries;
} QPS_Table;

static QPS_Table
QPS_Create(u8 table_size_lg2)
{
  u32 table_size = 1UL << table_size_lg2;

  QPS__Entry* entries = (QPS__Entry*)VirtualAlloc(0, table_size*sizeof(QPS__Entry), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  return { table_size-1, 0, entries };
}

static void
QPS_Destroy(QPS_Table* table)
{
  VirtualFree(table->entries, 0, MEM_RELEASE);
  *table = {};
}

static void
QPS_Clear(QPS_Table* table)
{
  memset(table->entries, 0, (table->table_mask+1)*sizeof(QPS__Entry));
  table->entry_count = 0;
}

static u32
QPS_Put(QPS_Table* table, String s)
{
  u64 hash = s.Hash();
  u64 idx  = hash & table->table_mask;
  u64 step = 1;

  if (hash == 0) hash = 1;

  while (table->entries[idx].hash != 0)
  {
    if (table->entries[idx].hash == hash)
    {
      bool does_match = ((u64)table->entries[idx].len == s.len);

      u8* entry_str = (table->entries[idx].len <= 18 ? (u8*)&table->entries[idx].pad : table->entries[idx].data);

      for (u16 i = 0; i < table->entries[idx].len && does_match; ++i) does_match = (entry_str[i] == s.data[i]);

      if (does_match) break;
    }

    idx = (idx + step++) & table->table_mask;
  }

  if (table->entries[idx].hash == 0)
  {
    table->entries[idx] = {
      hash,
      table->entry_count,
      (u16)s.len,
      0,
      0,
    };

    if (s.len <= 18) memcpy(&table->entries[idx].pad, s.data, s.len);
    else             table->entries[idx].data = s.data;

    table->entry_count += 1;
  }

  return table->entries[idx].id;
}

typedef struct QPGCC__Entry
{
  u64 hash;
  u8* data;
  u32 id;
  u16 len;
  u8 pad[10];
} QPGCC__Entry;

typedef struct QPGCC_Table
{
  u32 table_mask;
  u32 entry_count;
  QPGCC__Entry* entries;
} QPGCC_Table;

static QPGCC_Table
QPGCC_Create(u8 table_size_lg2)
{
  u32 table_size = 1UL << table_size_lg2;

  QPGCC__Entry* entries = (QPGCC__Entry*)VirtualAlloc(0, table_size*sizeof(QPGCC__Entry), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  return { table_size-1, 0, entries };
}

static void
QPGCC_Destroy(QPGCC_Table* table)
{
  VirtualFree(table->entries, 0, MEM_RELEASE);
  *table = {};
}

static void
QPGCC_Clear(QPGCC_Table* table)
{
  memset(table->entries, 0, (table->table_mask+1)*sizeof(QPGCC__Entry));
  table->entry_count = 0;
}

static u32
QPGCC_Put(QPGCC_Table* table, String s)
{
  u64 hash = s.Hash();
  u64 idx  = hash & table->table_mask;
  u64 step = 1;

  if (hash == 0) hash = 1;

  while (table->entries[idx].hash != 0)
  {
    if (table->entries[idx].hash == hash)
    {
      bool does_match = ((u64)table->entries[idx].len == s.len);

      for (u16 i = 0; i < table->entries[idx].len && does_match; ++i) does_match = (table->entries[idx].data[i] == s.data[i]);

      if (does_match) break;
    }

    idx = (idx + step++) & table->table_mask;
  }

  if (table->entries[idx].hash == 0)
  {
    table->entries[idx] = {
      hash,
      s.data,
      table->entry_count,
      (u16)s.len,
      {},
    };

    if (s.len <= 10)
    {
      memcpy(table->entries[idx].pad, s.data, s.len);
      table->entries[idx].data = table->entries[idx].pad;
    }

    table->entry_count += 1;
  }

  return table->entries[idx].id;
}

#define MIN_TIME_TTL 4

typedef struct Result
{
  char* name;
  u64 time;
} Result;

void
SortResults(Result* results, u32 len)
{
  if (len <= 1) return;

  u64 pivot = results[len-1].time;

  u32 j = 0;
  for (u32 i = 0; i < len; ++i)
  {
    if (results[i].time <= pivot)
    {
      Result tmp = results[j];
      results[j] = results[i];
      results[i] = tmp;
      ++j;
    }
  }

  SortResults(results, j-1);
  SortResults(results + j, len - j);
}

#define TEST_TABLE(IDX, NAME, PREFIX)                                                     \
  {                                                                                       \
    printf(NAME "\n");                                                                    \
    u32 result_array_len = 0;                                                             \
                                                                                          \
    CONCAT(PREFIX, _Table) table = CONCAT(PREFIX, _Create)(MAX_STRING_COUNT_LG2);         \
                                                                                          \
    u64 min_time = ~(u64)0;                                                               \
    for (u64 min_time_age = 0; min_time_age < MIN_TIME_TTL; ++min_time_age)               \
    {                                                                                     \
      result_array_len = 0;                                                               \
                                                                                          \
      for (u8* scan = lexer.input; *scan != 0; ++scan)                                    \
      {                                                                                   \
        _mm_clflushopt(scan);                                                             \
        for (u32 i = 0; i < 64; ++i, ++scan)                                              \
        {                                                                                 \
          if (*scan == 0) break;                                                          \
        }                                                                                 \
      }                                                                                   \
                                                                                          \
      u64 start = __rdtsc();                                                              \
                                                                                          \
      Token token = { Token_Invalid };                                                    \
      while (token.kind != Token_Error && token.kind != Token_EOF)                        \
      {                                                                                   \
        token = Lexer_NextToken(&lexer);                                                  \
        Token_Kind id = token.kind;                                                       \
        if (token.kind == Token_Ident)                                                    \
        {                                                                                 \
          id = (Token_Kind)CONCAT(PREFIX, _Put)(&table, token.string);                    \
        }                                                                                 \
        result_array[result_array_len++] = id;                                            \
      }                                                                                   \
                                                                                          \
      u64 end = __rdtsc();                                                                \
                                                                                          \
      u64 time = end - start;                                                             \
                                                                                          \
      if (time < min_time)                                                                \
      {                                                                                   \
        min_time     = time;                                                              \
        min_time_age = 0;                                                                 \
      }                                                                                   \
                                                                                          \
      Lexer_Reset(&lexer);                                                                \
      CONCAT(PREFIX, _Clear)(&table);                                                     \
                                                                                          \
      printf("\rmin time: %llu (%llu)                  ", min_time, min_time_age);        \
    }                                                                                     \
                                                                                          \
    CONCAT(PREFIX, _Destroy)(&table);                                                     \
                                                                                          \
    printf("\rmin time: %llu                           \n", min_time);                    \
    results[IDX] = { NAME, min_time };                                                    \
                                                                                          \
    if (result_array_len != validation_array_len) __debugbreak();                         \
    for (u32 i = 0; i < result_array_len; ++i)                                            \
    {                                                                                     \
      if (result_array[i] != validation_array[i]) __debugbreak();                         \
    }                                                                                     \
  }                                                                                       \

int
main(int argc, char** argv)
{
  Lexer lexer{};
  if (argc != 2 || !Lexer_Init(argv[1], &lexer))
  {
    fprintf(stderr, "Invalid Arguments. Usage: hash_bench [path to c code file]\n");
    return -1;
  }

  u32 validation_array_cap = (1UL << 28);
  u32 validation_array_len = 0;
  Token_Kind* validation_array = (Token_Kind*)VirtualAlloc(0, validation_array_cap*sizeof(Token_Kind), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  Token_Kind* result_array = (Token_Kind*)VirtualAlloc(0, validation_array_cap*sizeof(Token_Kind), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

  Result results[11] = {};

  {
    printf("ankerl\n");
    u32 result_array_len = 0;

    auto ankerl_map = ankerl::unordered_dense::map<String, u32>();
    ankerl_map.reserve(MAX_STRING_COUNT);

    u64 min_time = ~(u64)0;
    for (u64 min_time_age = 0; min_time_age < MIN_TIME_TTL; ++min_time_age)
    {
      result_array_len = 0;

      for (u8* scan = lexer.input; *scan != 0; ++scan)
      {
        _mm_clflushopt(scan);
        for (u32 i = 0; i < 64; ++i, ++scan)
        {
          if (*scan == 0) break;
        }
      }

      u64 start = __rdtsc();

      u32 string_idx = 0;
      Token token = { Token_Invalid };
      while (token.kind != Token_Error && token.kind != Token_EOF)
      {
        token = Lexer_NextToken(&lexer);

        Token_Kind id = token.kind;

        if (token.kind == Token_Ident)
        {
          auto it = ankerl_map.find(token.string);
          if (it != ankerl_map.end()) id = (Token_Kind)it->second;
          else
          {
            ankerl_map.try_emplace(token.string, string_idx);
            id = (Token_Kind)string_idx;
            string_idx += 1;
          }
        }

        result_array[result_array_len++] = id;
      }

      u64 end = __rdtsc();

      u64 time = end - start;

      if (time < min_time)
      {
        min_time     = time;
        min_time_age = 0;
      }

      Lexer_Reset(&lexer);
      ankerl_map.clear();

      printf("\rmin time: %llu (%llu)                  ", min_time, min_time_age);
    }

    printf("\rmin time: %llu                           \n", min_time);
    results[0] = { "ankerl", min_time };

    validation_array_len = result_array_len;
    memcpy(validation_array, result_array, validation_array_len*sizeof(u32));
  }

  TEST_TABLE(1,  "quadratic probing [triangle numbers]",                   QP);
  TEST_TABLE(2,  "quadratic probing [triangle numbers], gcc small string", QPGCC);
  TEST_TABLE(3,  "quadratic probing [triangle numbers], small string",     QPS);
  TEST_TABLE(4,  "linear probing",                                         LP);
  TEST_TABLE(5,  "linear probing, prefix",                                 LPP);
  TEST_TABLE(6,  "quadratic probing [triangle numbers], prefix",           QPP);
  TEST_TABLE(7,  "linear probing, indirect",                               LPI);
  TEST_TABLE(8,  "quadratic probing [triangle numbers], indirect",         QPI);
  TEST_TABLE(9,  "linear probing, indirect, prefix",                       LPIP);
  TEST_TABLE(10, "quadratic probing [triangle numbers], indirect, prefix", QPIP);

  SortResults(results, ARRAY_SIZE(results));

  for (u32 i = 0; i < ARRAY_SIZE(results); ++i)
  {
    printf("%19llu - %s\n", results[i].time, results[i].name);
  }

  return 0;
}
