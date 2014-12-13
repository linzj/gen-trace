#include "gt_string.h"

struct MyNode
{
  VgHashNode super;
  HChar str[1];
};

struct MyLookupNode
{
  VgHashNode super;
  const HChar *str;
};

static UWord
str_hash (const HChar *s)
{
  UWord hash_value = 0;
  for (; *s; s++)
    hash_value = (HASH_CONSTANT * hash_value + *s);
  return hash_value;
}

static Word
lookup_func (const void *node1, const void *node2)
{
  const struct MyLookupNode *lookup = node1;
  const struct MyNode *node = node2;
  return VG_ (strcmp)(lookup->str, (char *)node->str);
}

static VgHashTable s_string_hash_table;

static HChar *
new_string (const HChar *str, Word key)
{
  int len;
  struct MyNode *new_node;

  len = VG_ (strlen)(str);
  new_node = VG_ (malloc)("gentrace.fnname", sizeof (struct MyNode) + len + 1);
  new_node->super.key = key;
  new_node->super.next = 0;
  VG_ (strcpy)(new_node->str, str);
  VG_ (HT_add_node)(s_string_hash_table, new_node);
  return new_node->str;
}

HChar *
gt_find_string (const HChar *str)
{
  struct MyLookupNode lookup_node;
  struct MyNode *found;
  lookup_node.super.key = str_hash (str);
  lookup_node.str = str;

  found = VG_ (HT_gen_lookup)(s_string_hash_table, &lookup_node, lookup_func);
  if (found)
    {
      return found->str;
    }
  return new_string (str, lookup_node.super.key);
}

void
gt_init_string (void)
{
  s_string_hash_table = VG_ (HT_construct)("fnname table");
}

void
gt_destroy_string (void)
{
  VG_ (HT_destruct)(s_string_hash_table, VG_ (free));
}
