#ifndef CODE_MODIFY_H
#define CODE_MODIFY_H
#pragma once
#include <stddef.h>
struct mem_modify_instr;

struct code_context
{
  // machine relavant.
  void *machine_defined;
  // the code point.
  void *code_point;
  // trampoline code.
  void *trampoline_code_start;
  void *trampoline_code_end;
  void *called_callback;
  void *return_callback;
};

class code_manager
{
public:
  virtual ~code_manager ();

  virtual code_context *new_context () = 0;
  virtual void *new_code_mem (size_t s) = 0;
};

class target_client
{
public:
  virtual ~target_client ();

  // check if code accept to modify, and turn the context via the 2nd argument.
  virtual bool check_code (void *, code_manager *, code_context **) = 0;
  virtual bool build_trampoline (code_manager *, code_context *) = 0;
  virtual mem_modify_instr *modify_code (code_context *, void *called_callback,
                                         void *return_callback) = 0;
};

int code_modify (void **code_points, int count_of, void *called_callback,
                 void *return_callback);
bool code_modify_init (target_client *(*)(void));
#endif /* CODE_MODIFY_H */
