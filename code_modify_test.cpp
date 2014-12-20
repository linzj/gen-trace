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
  is_code_accept (void *)
  {
    return true;
  }
  virtual code_context *
  build_code_context (code_manager *m, void *target)
  {
    code_context *c = m->new_context ();
    assert (c != 0);
    void *code = m->new_code_mem (9);
    assert (code != 0);
    c->trampoline_code_start = code;
    c->trampoline_code_end = static_cast<char *> (code) + 9;
    return c;
  }
  virtual mem_modify_instr *
  get_modify_instr (code_context *c)
  {
    mem_modify_instr *instr = static_cast<mem_modify_instr *> (
        calloc (1, sizeof (mem_modify_instr) + 9));
    assert (instr != NULL);
    instr->where = to_modify;
    instr->size = 9;
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
  assert (1 == code_modify (&code_point, 1));
}
