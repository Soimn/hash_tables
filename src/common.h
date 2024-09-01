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

struct String
{
  u8* data;
  u64 len;

  String(char* cstring)
  {
    this->data = (u8*)cstring;
    this->len  = 0;
    for (char* scan = cstring; *scan != 0; ++scan) ++this->len;
  }

  String(char* data, u64 len)
  {
    this->data = (u8*)data;
    this->len  = len;
  }

  String(u8* data, u64 len)
  {
    this->data = data;
    this->len  = len;
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

static Token Lexer_NextToken(Lexer* lexer);
static Lexer
Lexer_Init(char* filename)
{
  Lexer lexer = {
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
    lexer.input = (u8*)VirtualAlloc(0, size.LowPart + 1, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

    DWORD read_bytes = 0;
    if (lexer.input != 0 && ReadFile(file, lexer.input, size.LowPart, &read_bytes, 0) && read_bytes == size.LowPart)
    {
      lexer.input[size.LowPart] = 0;
      lexer.cursor = lexer.input;
      lexer.start_of_line = lexer.input;

      Lexer_NextToken(&lexer);
    }
  }

  CloseHandle(file);

  return lexer;
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
