#ifndef ARM_TARGET_CLIENT_H
#define ARM_TARGET_CLIENT_H
#include "base_target_client.h"

class arm_target_client : public base_target_client
{
public:
  arm_target_client ();
  ~arm_target_client ();

private:
  virtual int byte_needed_to_modify (intptr_t target_code_point);
  virtual disassembler *new_disassembler ();
  virtual dis_client *new_code_check_client ();
  virtual dis_client *new_backedge_check_client (intptr_t base,
                                                 intptr_t hookend);
  virtual char *template_start (intptr_t target_code_point);
  virtual char *template_ret_start (intptr_t target_code_point);
  virtual char *template_end (intptr_t target_code_point);
  virtual int max_tempoline_insert_space ();
  virtual bool check_jump_dist (intptr_t target_code_point,
                                intptr_t trampoline_code_start);
  virtual void flush_code (void *code_start, int len);
  virtual void copy_original_code (void *trampoline_code_start,
                                   void *target_code_point, int len);
  virtual mem_modify_instr *modify_code (code_context *);
};

#endif /* ARM_TARGET_CLIENT_H */
