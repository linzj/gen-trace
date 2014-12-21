#ifndef X64_TARGET_CLIENT_H
#define X64_TARGET_CLIENT_H
#include "code_modify.h"

class x64_target_client : public target_client
{
public:
  x64_target_client ();
  ~x64_target_client ();

private:
  virtual bool check_code (void *, code_manager *, code_context **);
  virtual bool build_trampoline (code_manager *, code_context *);
  virtual mem_modify_instr *modify_code (code_context *, void *called_callback,
                                         void *return_callback);
};

#endif /* X64_TARGET_CLIENT_H */
