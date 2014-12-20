#ifndef CODE_MODIFY_H
#define CODE_MODIFY_H
#pragma once
#include <stddef.h>
struct mem_modify_instr;

struct code_context
{
  void *target_defined;
  void *code_start;
  void *code_end;
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

  virtual void is_code_accept (void *) = 0;
  virtual code_context *build_code_context (code_manager *, void *target) = 0;
  virtual mem_modify_instr *get_modify_instr (code_context *) = 0;
};

int code_modify (void **code_points, int count_of);
bool code_modify_init (target_client *(*)(void));
#endif /* CODE_MODIFY_H */
