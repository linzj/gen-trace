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
  virtual check_code_dis_client *new_code_check_client (void *);
  virtual dis_client *new_backedge_check_client (intptr_t base,
                                                 intptr_t hookend);
  virtual char *template_start (intptr_t target_code_point);
  virtual char *template_end (intptr_t target_code_point);
  virtual bool check_jump_dist (intptr_t target_code_point,
                                intptr_t trampoline_code_start);
  virtual void flush_code (void *code_start, int len);
  virtual void copy_original_code (void *trampoline_code_start,
                                   check_code_result_buffer *b);
  virtual mem_modify_instr *modify_code (target_session *);
  virtual bool use_target_code_point_as_hint (void);
  virtual void add_jump_to_original (char *code_start, int offset,
                                     code_context *code_context);
  virtual int jump_back_instr_len (code_context *);
};

#endif /* ARM_TARGET_CLIENT_H */
