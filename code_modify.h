#ifndef CODE_MODIFY_H
#define CODE_MODIFY_H
#pragma once
#include <stddef.h>
struct mem_modify_instr;
typedef void (*pfn_called_callback)(void *original_ret, const char *name);
typedef void *(*pfn_ret_callback)(const char *name);

struct code_context
{
  const char *function_name;
  // code_len_to_replace describes the len of code
  // is to be overwrited. It is not necessity equals
  // to lowered_original_code_len, which is a lowered
  // version of original code. Lowered means find the
  // other way to interpret.
  int code_len_to_replace;
  int lowered_original_code_len;
  // the code point.
  // FIXME: needs to rename to target_code_point.
  void *code_point;
  // trampoline code.
  void *trampoline_code_start;
  void *trampoline_code_end;
  pfn_called_callback called_callback;
  pfn_ret_callback return_callback;
  // This field is record the data by check code procedure,
  // and released after build_trampoline.
  void *machine_defined2;
};

class code_manager
{
public:
  virtual ~code_manager ();

  virtual code_context *new_context (const char *function_name) = 0;
  virtual void *new_code_mem (void *hint, size_t s) = 0;
  // FIXME: need a delete code mem function.
};

class target_client
{
public:
  enum check_code_status
  {
    check_code_okay,
    check_code_not_accept,
    check_code_back_edge,
    check_code_too_small,
    check_code_memory,
    check_code_build_machine_define2,
  };
  enum build_trampoline_status
  {
    build_trampoline_okay,
    build_trampoline_memory,
    build_trampoline_jump_dist,
  };
  virtual ~target_client ();

  // check if code accept to modify, and turn the context via the 2nd argument.
  virtual check_code_status check_code (void *, const char *, int code_size,
                                        code_manager *, code_context **) = 0;
  virtual build_trampoline_status
  build_trampoline (code_manager *, code_context *,
                    pfn_called_callback called_callback,
                    pfn_ret_callback return_callback) = 0;
  virtual mem_modify_instr *modify_code (code_context *) = 0;
};

struct code_modify_desc
{
  void *code_point;
  const char *name;
  int size;
};

int code_modify (const code_modify_desc *code_points, int count_of,
                 pfn_called_callback called_callback,
                 pfn_ret_callback return_callback);
bool code_modify_init (target_client *);
// set the file name for fail logging;
void code_modify_set_log_for_fail (const char *log_for_fail_name);
#endif /* CODE_MODIFY_H */
