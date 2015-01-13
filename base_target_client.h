#ifndef BASE_TARGET_CLIENT_H
#define BASE_TARGET_CLIENT_H
#include <stdint.h>
#include "code_modify.h"
class dis_client;
class disassembler;
// This class serve as the template of all other target client.
// not mandatory.
class base_target_client : public target_client
{
private:
  virtual check_code_status check_code (void *, const char *, int code_size,
                                        code_manager *, code_context **);
  virtual build_trampoline_status
  build_trampoline (code_manager *, code_context *,
                    pfn_called_callback called_callback,
                    pfn_ret_callback return_callback);

protected:
  virtual int byte_needed_to_modify (intptr_t target_code_point) = 0;
  virtual disassembler *new_disassembler () = 0;
  virtual dis_client *new_code_check_client (void *code_point) = 0;
  virtual dis_client *new_backedge_check_client (intptr_t base,
                                                 intptr_t hookend) = 0;
  virtual char *template_start (intptr_t target_client) = 0;
  virtual char *template_ret_start (intptr_t target_code_point) = 0;
  virtual char *template_end (intptr_t target_code_point) = 0;
  virtual int max_tempoline_insert_space () = 0;
  virtual bool check_jump_dist (intptr_t target_code_point,
                                intptr_t trampoline_code_start) = 0;
  virtual void flush_code (void *code_start, int len) = 0;
  virtual void copy_original_code (void *trampoline_code_start,
                                   void *target_code_point, int len,
                                   code_context *context) = 0;
  // This predication show if this machine will use near jump, aka, jump
  // using pc, and need target code point as hint.
  // Default implementation will return true.
  virtual bool use_target_code_point_as_hint (void);
  virtual bool build_machine_define2 (code_context *context,
                                      dis_client *code_check_client);
  virtual void release_machine_define2 (code_context *context);

private:
  bool check_for_back_edge (disassembler *, char *start, char *hook_end,
                            char *code_end);
  friend class release_machine_define2_helper;
};
#endif /* BASE_TARGET_CLIENT_H */
