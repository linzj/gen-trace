#ifndef CONFIG_READER_H
#define CONFIG_READER_H
#include <memory>
#include <string>
#include <vector>
#include <stdint.h>
#include "code_modify.h"

struct config_module
{
  char *module_name;
  code_modify_desc *desc_array;
  int desc_array_size;
};

struct config_desc
{
  char *where_to_keep_log;
  int sleep_sec;
  int num_of_modules;
  struct config_module *modules;
  code_modify_desc *all_desc;
  int num_of_all_desc;
};

class config_reader
{
public:
  enum State
  {
    READ_WHERE_LOG,
    READ_SLEEP_SEC,
    READ_MODULE_START,
    READ_MODULE_NAME,
    READ_SYM_BASE,
    READ_SYM_SIZE,
    READ_SYM_NAME,
  };
  config_reader ();
  bool handle_line (const char *str);
  config_desc *accumulate ();

private:
  State state_;
  std::string where_to_log_;
  int sleep_sec_;

  struct read_slot
  {
    intptr_t sym_base;
    size_t sym_size;
    std::string sym_name;
  };
  read_slot current_slot_;
  std::vector<read_slot> slot_array_;
  std::vector<int> last_pos_array_;
  std::vector<std::string> name_stack_;
  size_t size_for_config_;
  size_t line_;
};

#endif /* CONFIG_READER_H */
