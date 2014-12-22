#include "mem_modify.h"
#include "code_modify.h"
#include <assert.h>
#include <stdlib.h>
#include <memory.h>

class test_target_client : public target_client
{
public:
private:
  char to_modify[9];
  virtual bool
  check_code (void *target, const char *name, int code_size,
              code_manager *code_manager, code_context **ppcontext)
  {
    code_context *context;
    *ppcontext = context = code_manager->new_context (name);
    context->code_point = target;
    return true;
  }
  virtual bool
  build_trampoline (code_manager *code_manager, code_context *context)
  {
    code_context *c = context;
    assert (c != 0);
    void *code = code_manager->new_code_mem (9);
    assert (code != 0);
    c->trampoline_code_start = code;
    c->trampoline_code_end = static_cast<char *> (code) + 9;
    return c;
  }
  virtual mem_modify_instr *
  modify_code (code_context *context, void *called_callback,
               void *return_callback)
  {
    mem_modify_instr *instr = static_cast<mem_modify_instr *> (
        calloc (1, sizeof (mem_modify_instr) + 9));
    assert (instr != NULL);
    instr->where = to_modify;
    instr->size = 9;
    context->called_callback = called_callback;
    context->return_callback = return_callback;
    memcpy (instr->data, "123456789", 9);
    return instr;
  }

public:
  bool
  isOkay ()
  {
    return memcmp (to_modify, "123456789", 9) == 0;
  }
};

static target_client *
init (void)
{
  return new test_target_client ();
}

int
main ()
{
  assert (code_modify_init (init) == true);
  void *code_point = reinterpret_cast<void *> (main);
  const char *name = "main";
  code_modify_desc desc = { code_point, name };
  assert (1 == code_modify (&desc, 1, (void *)main, (void *)main));
}
