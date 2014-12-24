#ifndef X64_TARGET_CLIENT_H
#define X64_TARGET_CLIENT_H
#include "code_modify.h"
#include "base_target_client.h"

class x64_target_client : public base_target_client
{
public:
  x64_target_client ();
  ~x64_target_client ();

private:
  virtual int byte_needed_to_modify ();
  virtual disassembler *new_disassembler ();
  virtual dis_client *new_code_check_client();
  virtual dis_client *new_backedge_check_client(intptr_t base, intptr_t hookend);
  virtual char * template_start();
  virtual char * template_ret_start();
  virtual char * template_end();
  virtual int max_tempoline_insert_space ();
  virtual bool check_jump_dist (intptr_t target_code_point, intptr_t trampoline_code_start);
  virtual void flush_code (void *code_start, int len);
  virtual mem_modify_instr *modify_code (code_context *);
};

#endif /* X64_TARGET_CLIENT_H */
