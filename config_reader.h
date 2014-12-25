#ifndef CONFIG_READER_H
#define CONFIG_READER_H
#include <memory>
#include <string>
#include <vector>
#include <stdint.h>
#include "code_modify.h"
struct config_desc
{
  char *module_name;
  char *where_to_keep_log;
  int sleep_sec;
  code_modify_desc *desc_array;
  int desc_array_size;
};

class config_reader
{
public:
  enum State
  {
    READ_WHERE_LOG,
    READ_SLEEP_SEC,
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
  std::string module_name_;
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
  size_t size_for_config_;
};

#endif /* CONFIG_READER_H */
