#ifndef X64_TARGET_CLIENT_H
#define X64_TARGET_CLIENT_H
#include "code_modify.h"

class x64_target_client : public target_client
{
public:
  x64_target_client ();
  ~x64_target_client ();

private:
  virtual bool check_code (void *, const char *, int code_size, code_manager *,
                           code_context **);
  virtual bool build_trampoline (code_manager *, code_context *,
                                 pfn_called_callback called_callback,
                                 pfn_ret_callback return_callback);
  virtual mem_modify_instr *modify_code (code_context *);
};

#endif /* X64_TARGET_CLIENT_H */
