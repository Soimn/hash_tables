typedef struct OALP_Table_Entry
{
  u64 hash;
  String key;
  u64 data;
} OALP_Table_Entry;

typedef struct OALP_Table
{
  Hash_Func* hash_func;
  OALP_Table_Entry* entries;
  u64 mask;
  u64 entry_count;
} OALP_Table;

#define OALP_TABLE_EMPTY_SLOT 0
#define OALP_LOAD_FACTOR_PERCENT 70

static bool
OALP_Table_Create(Hash_Func* hash_func, u64 initial_size, OALP_Table* table)
{
  initial_size -= 1;
  initial_size |= initial_size >> 1;
  initial_size |= initial_size >> 2;
  initial_size |= initial_size >> 4;
  initial_size |= initial_size >> 8;
  initial_size |= initial_size >> 16;
  initial_size += 1;

  OALP_Table_Entry* entries = calloc(initial_size, sizeof(OALP_Table_Entry));

  if (entries == 0) return false;
  else
  {
    *table = (OALP_Table){
      .hash_func    = hash_func,
      .entries      = entries,
      .mask         = initial_size-1,
    };

    return true;
  }
}

static void
OALP_Table_Clear(OALP_Table* table)
{
  memset(table->entries, 0, sizeof(OALP_Table_Entry)*(table->mask+1));
  table->entry_count = 0;
}

static void
OALP_Table_Destroy(OALP_Table* table)
{
  free(table->entries);
  *table = (OALP_Table){0};
}

static u64
OALP_Table__HashKey(OALP_Table* table, String key)
{
  u64 hash = table->hash_func(key);
  if (hash == OALP_TABLE_EMPTY_SLOT) hash = OALP_TABLE_EMPTY_SLOT + 1;
  return hash;
}

static u64
OALP_Table__Probe(OALP_Table* table, u64 hash, String key)
{
  for (u64 idx = hash & table->mask;; idx = (idx + 1) & table->mask)
  {
    if ((u64)table->entries[idx].hash == OALP_TABLE_EMPTY_SLOT || table->entries[idx].hash == hash && String_Match(table->entries[idx].key, key))
    {
      return idx;
    }
  }
}

static bool
OALP_Table_Put(OALP_Table* table, String key, u64 data)
{
  u64 hash = OALP_Table__HashKey(table, key);
  u64 idx = OALP_Table__Probe(table, hash, key);

  if ((u64)table->entries[idx].hash != OALP_TABLE_EMPTY_SLOT) table->entries[idx].data = data;
  else
  {
    table->entries[idx] = (OALP_Table_Entry){
      .hash = hash,
      .key  = key,
      .data = data,
    };

    table->entry_count += 1;
  }

  // table->entry_count/table->size > OALP_LOAD_FACTOR_PERCENT/100
  if (table->entry_count*100 > OALP_LOAD_FACTOR_PERCENT*(table->mask+1))
  {
    __debugbreak();
    // TODO: resize
    return false;
  }
  
  return true;
}

static bool
OALP_Table_Get(OALP_Table* table, String key, u64* data)
{
  u64 hash = OALP_Table__HashKey(table, key);
  u64 idx = OALP_Table__Probe(table, hash, key);

  if ((u64)table->entries[idx].hash == OALP_TABLE_EMPTY_SLOT) return false;
  else
  {
    *data = table->entries[idx].data;
    return true;
  }
}
