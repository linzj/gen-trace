#ifndef CODE_MODIFY_H
#define CODE_MODIFY_H
#pragma once
#include <stddef.h>
struct mem_modify_instr;
typedef void (*pfn_called_callback)(void *original_ret, const char *name);
typedef void *(*pfn_ret_callback)(void);

struct code_context
{
  const char *function_name;
  // machine relavant.
  void *machine_defined;
  // the code point.
  // FIXME: needs to rename to target_code_point.
  void *code_point;
  // trampoline code.
  void *trampoline_code_start;
  void *trampoline_code_end;
  pfn_called_callback called_callback;
  pfn_ret_callback return_callback;
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
  virtual ~target_client ();

  // check if code accept to modify, and turn the context via the 2nd argument.
  virtual bool check_code (void *, const char *, int code_size, code_manager *,
                           code_context **) = 0;
  virtual bool build_trampoline (code_manager *, code_context *) = 0;
  virtual mem_modify_instr *modify_code (code_context *,
                                         pfn_called_callback called_callback,
                                         pfn_ret_callback return_callback) = 0;
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
