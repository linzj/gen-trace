#include "config_reader.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <algorithm>
#include <functional>
#include <cctype>
#include <locale>

using namespace std;

// trim from start
static inline std::string &
ltrim (std::string &s)
{
  s.erase (s.begin (),
           std::find_if (s.begin (), s.end (),
                         std::not1 (std::ptr_fun<int, int> (std::isspace))));
  return s;
}

// trim from end
static inline std::string &
rtrim (std::string &s)
{
  s.erase (
      std::find_if (s.rbegin (), s.rend (),
                    std::not1 (std::ptr_fun<int, int> (std::isspace))).base (),
      s.end ());
  return s;
}

bool
config_reader::handle_line (const char *str)
{
  bool to_return = true;
  switch (state_)
    {
    case READ_MODULE_NAME:
      module_name_.assign (str);
      rtrim (module_name_);
      size_for_config_ += module_name_.size () + 1;
      state_ = READ_WHERE_LOG;
      break;
    case READ_WHERE_LOG:
      where_to_log_.assign (str);
      rtrim (where_to_log_);
      size_for_config_ += where_to_log_.size () + 1;
      state_ = READ_SYM_BASE;
      break;
    case READ_SYM_BASE:
      {
        long int sym_base;
        sym_base = strtol (str, NULL, 16);
        if (errno != 0)
          {
            to_return = false;
            break;
          }
        current_slot_.sym_base = sym_base;
        state_ = READ_SYM_SIZE;
      }
      break;
    case READ_SYM_SIZE:
      {
        long int sym_size;
        sym_size = strtol (str, NULL, 16);
        if (errno != 0)
          {
            to_return = false;
            break;
          }
        current_slot_.sym_size = sym_size;
        state_ = READ_SYM_NAME;
      }
      break;
    case READ_SYM_NAME:
      {
        string name (str);
        rtrim (name);
        current_slot_.sym_name = name;
        slot_array_.push_back (current_slot_);
        size_for_config_ += sizeof (code_modify_desc) + name.size () + 1;
        state_ = READ_SYM_BASE;
      }
      break;
    default:
      assert (false);
      break;
    }
  return to_return;
}

config_reader::config_reader ()
    : state_ (READ_MODULE_NAME), size_for_config_ (sizeof (config_desc))
{
}

class AccumulateAllocator
{
  char *buffer_;
  char *end_;

public:
  AccumulateAllocator (char *buffer, size_t s)
      : buffer_ (buffer), end_ (buffer + s)
  {
  }
  void *
  alloc (size_t s)
  {
    if (buffer_ + s > end_)
      {
        assert (false);
        return NULL;
      }
    char *ret = buffer_;
    buffer_ += s;
    return ret;
  }
  bool
  end () const
  {
    return buffer_ == end_;
  }
};

config_desc *
config_reader::accumulate ()
{
  char *buffer = static_cast<char *> (malloc (size_for_config_));
  if (!buffer)
    {
      return NULL;
    }
  AccumulateAllocator allocator (buffer, size_for_config_);
  config_desc *ret
      = static_cast<config_desc *> (allocator.alloc (sizeof (config_desc)));
  char *module_name
      = static_cast<char *> (allocator.alloc (module_name_.size () + 1));
  strcpy (module_name, module_name_.c_str ());
  char *where_to_keep_log
      = static_cast<char *> (allocator.alloc (where_to_log_.size () + 1));
  strcpy (where_to_keep_log, where_to_log_.c_str ());
  code_modify_desc *desc_array = static_cast<code_modify_desc *> (
      allocator.alloc (sizeof (code_modify_desc) * slot_array_.size ()));
  ret->module_name = module_name;
  ret->where_to_keep_log = where_to_keep_log;
  ret->desc_array = desc_array;
  ret->desc_array_size = slot_array_.size ();
  // work out desc_array
  code_modify_desc *indexer = desc_array;
  for (vector<read_slot>::iterator i = slot_array_.begin ();
       i != slot_array_.end (); ++i, ++indexer)
    {
      read_slot &r = *i;
      indexer->code_point = reinterpret_cast<void *> (r.sym_base);
      indexer->size = r.sym_size;
      char *sym_name
          = static_cast<char *> (allocator.alloc (r.sym_name.size () + 1));
      strcpy (sym_name, r.sym_name.c_str ());
      indexer->name = sym_name;
    }
  assert (allocator.end ());
  return ret;
}
