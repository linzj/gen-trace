#include "config_reader.h"
#include "log.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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

static inline size_t
align_to_word (size_t s)
{
  return (s + sizeof (intptr_t) - 1) & (~(sizeof (intptr_t) - 1));
}

bool
config_reader::handle_line (const char *str)
{
  line_++;
  bool to_return = true;
  switch (state_)
    {
    case READ_WHERE_LOG:
      where_to_log_.assign (str);
      rtrim (where_to_log_);
      size_for_config_ += where_to_log_.size () + 1;
      size_for_config_ = align_to_word (size_for_config_);
      state_ = READ_SLEEP_SEC;
      break;
    case READ_SLEEP_SEC:
      {
        long int sleep_sec;
        sleep_sec = strtol (str, NULL, 10);
        if (errno != 0)
          {
            LOGE ("strtol fails %s for %s, line %d, at input line %u\n",
                  strerror (errno), str, __LINE__, line_);
            to_return = false;
            break;
          }
        sleep_sec_ = sleep_sec;
        state_ = READ_MODULE_START;
      }
      break;
    case READ_MODULE_START:
      if (strncmp (str, "module start", 12))
        {
          LOGE ("corrupted config file. unexpected input %s, at line = %u\n",
                str, line_);
          to_return = false;
          break;
        }
      state_ = READ_MODULE_NAME;
      break;
    case READ_MODULE_NAME:
      {
        std::string module_name (str);
        rtrim (module_name);
        size_for_config_ += module_name.size () + 1 + sizeof (config_module);
        size_for_config_ = align_to_word (size_for_config_);
        name_stack_.push_back (module_name);
        last_pos_array_.push_back (slot_array_.size ());
        state_ = READ_SYM_BASE;
      }
      break;
    case READ_SYM_BASE:
      if (str[0] == 'm' && 0 == strncmp ("module end", str, 10))
        {
          state_ = READ_MODULE_START;
          break;
        }
      {
        long int sym_base;
        errno = 0;
        sym_base = strtol (str, NULL, 16);
        if (errno != 0)
          {
            LOGE ("strtol fails %s for %s, line %d, at input line %u\n",
                  strerror (errno), str, __LINE__, line_);
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
        sym_size = strtol (str, NULL, 10);
        if (errno != 0)
          {
            LOGE ("strtol fails %s for %s, line %d, at input line %u\n",
                  strerror (errno), str, __LINE__, line_);
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
        size_for_config_ = align_to_word (size_for_config_);
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
    : state_ (READ_WHERE_LOG), size_for_config_ (sizeof (config_desc)),
      line_ (0)
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
    s = align_to_word (s);
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
  char *where_to_keep_log
      = static_cast<char *> (allocator.alloc (where_to_log_.size () + 1));
  strcpy (where_to_keep_log, where_to_log_.c_str ());
  struct config_module *modules = static_cast<struct config_module *> (
      allocator.alloc (sizeof (config_module) * name_stack_.size ()));
  assert (name_stack_.size () == last_pos_array_.size ());
  int slot_end = slot_array_.size ();
  int sym_count = slot_end;
  code_modify_desc *desc_array = static_cast<code_modify_desc *> (
      allocator.alloc (sizeof (code_modify_desc) * sym_count));
  code_modify_desc *indexer = desc_array;
  for (size_t i = 0; i < last_pos_array_.size (); ++i)
    {
      int reverse_index = last_pos_array_.size () - i - 1;
      std::string &_module_name = name_stack_[reverse_index];
      char *module_name
          = static_cast<char *> (allocator.alloc (_module_name.size () + 1));
      strcpy (module_name, _module_name.c_str ());
      int slot_start = last_pos_array_[reverse_index];
      code_modify_desc *desc_array_local_start = indexer;
      // work out desc_array
      for (int j = slot_start; j < slot_end; ++j, ++indexer)
        {
          read_slot &r = slot_array_[j];
          indexer->code_point = reinterpret_cast<void *> (r.sym_base);
          indexer->size = r.sym_size;
          char *sym_name
              = static_cast<char *> (allocator.alloc (r.sym_name.size () + 1));
          strcpy (sym_name, r.sym_name.c_str ());
          indexer->name = sym_name;
          indexer->ignore = false;
        }

      modules[i].module_name = module_name;
      modules[i].desc_array = desc_array_local_start;
      modules[i].desc_array_size = slot_end - slot_start;

      slot_end = slot_start;
    }

  ret->where_to_keep_log = where_to_keep_log;
  ret->sleep_sec = sleep_sec_;
  ret->num_of_modules = last_pos_array_.size ();
  ret->modules = modules;
  ret->all_desc = desc_array;
  ret->num_of_all_desc = sym_count;
  assert (allocator.end ());
  return ret;
}
