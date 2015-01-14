#include <memory>
#include <memory.h>
#include <string.h>
#include "base_target_client.h"
#include "disassembler.h"
#include "dis_client.h"
#include "log.h"

bool
base_target_client::check_for_back_edge (disassembler *dis, char *start,
                                         char *hook_end, char *code_end)
{
  std::auto_ptr<dis_client> backedge_check_client (
      new_backedge_check_client (reinterpret_cast<intptr_t> (start),
                                 reinterpret_cast<intptr_t> (hook_end)));
  dis->set_client (backedge_check_client.get ());
  for (char *i = hook_end;
       i < code_end && backedge_check_client->is_accept ();)
    {
      int len = dis->instruction_decode (i);
      i += len;
    }
  return backedge_check_client->is_accept ();
}

target_client::check_code_status
base_target_client::check_code (void *code_point, const char *name,
                                int code_size, code_manager *m,
                                code_context **ppcontext)
{
  std::unique_ptr<check_code_dis_client> code_check_client (
      new_code_check_client (code_point));
  std::unique_ptr<disassembler> dis (new_disassembler ());
  dis->set_client (code_check_client.get ());
  int _byte_needed_to_modify
      = byte_needed_to_modify (reinterpret_cast<intptr_t> (code_point));
  char *start = static_cast<char *> (code_point);
  int current = 0;
  if (code_size < _byte_needed_to_modify)
    return check_code_too_small;
  while (current < _byte_needed_to_modify && code_check_client->is_accept ())
    {
      int len = dis->instruction_decode (start);
      current += len;
      start += len;
    }
  if (code_check_client->is_accept () == false)
    {
      return check_code_not_accept;
    }
  if (!check_for_back_edge (dis.get (), static_cast<char *> (code_point),
                            start,
                            static_cast<char *> (code_point) + code_size))
    {
      return check_code_back_edge;
    }
  code_context *context;
  context = m->new_context (name);
  if (context == NULL)
    return check_code_memory;
  context->code_point = code_point;
  context->code_len_to_replace = current;
  context->lowered_original_code_len
      = code_check_client->lowered_original_code_len (current);
  *ppcontext = context;
  if (!build_machine_define2 (context, code_check_client.get ()))
    {
      return check_code_build_machine_define2;
    }
  return check_code_okay;
}

class release_machine_define2_helper
{
public:
  release_machine_define2_helper (code_context *context,
                                  base_target_client *client)
      : context_ (context), client_ (client)
  {
  }
  ~release_machine_define2_helper ()
  {
    client_->release_machine_define2 (context_);
  }

private:
  code_context *context_;
  base_target_client *client_;
};

target_client::build_trampoline_status
base_target_client::build_trampoline (code_manager *m, code_context *context,
                                      pfn_called_callback called_callback,
                                      pfn_ret_callback return_callback)
{
  release_machine_define2_helper _dummy (context, this);
  const intptr_t target_code_point
      = reinterpret_cast<intptr_t> (context->code_point);
  char *const _template_start = template_start (target_code_point);
  char *const _template_end = template_end (target_code_point);
  const int template_code_size
      = (char *)_template_end - (char *)_template_start
        + context->lowered_original_code_len + jump_back_instr_len (context);
  int template_size = template_code_size + sizeof (intptr_t) * 4;
  template_size = (template_size + sizeof (intptr_t) - 1)
                  & ~(sizeof (intptr_t) - 1);
  void *hint;
  if (use_target_code_point_as_hint ())
    {
      hint = context->code_point;
    }
  else
    {
      hint = NULL;
    }
  void *code_mem = m->new_code_mem (hint, template_size);
  if (!code_mem)
    {
      return build_trampoline_memory;
    }
  // check if we can jump to our code.
  intptr_t code_mem_int = reinterpret_cast<intptr_t> (code_mem);
  intptr_t code_start = code_mem_int + sizeof (intptr_t) * 4;
  // FIXME: need to delete code mem before returns
  if (!check_jump_dist (target_code_point, code_start))
    return build_trampoline_jump_dist;

  context->trampoline_code_start = reinterpret_cast<char *> (code_start);
  context->trampoline_code_end = reinterpret_cast<char *> (code_start)
                                 + template_code_size;
  // copy the hook template to code mem.
  const int template_code_size_no_copy = (char *)_template_end
                                         - (char *)_template_start;
  memcpy (reinterpret_cast<void *> (code_start), (char *)_template_start,
          template_code_size_no_copy);

  // copy the original target code to trampoline
  char *copy_start = reinterpret_cast<char *> (code_start)
                     + template_code_size_no_copy;

  copy_original_code (copy_start, context);
  int lowered_original_code_len = context->lowered_original_code_len;
  add_jump_to_original (copy_start + lowered_original_code_len,
                        -(lowered_original_code_len
                          + template_code_size_no_copy
                          + sizeof (intptr_t) * 2),
                        context);
  context->called_callback = called_callback;
  context->return_callback = return_callback;
  const char *function_name = context->function_name;
  const void **modify_pointer
      = static_cast<const void **> (context->trampoline_code_start);
  modify_pointer[-4] = function_name;
  modify_pointer[-3] = (void *)called_callback;
  modify_pointer[-2] = reinterpret_cast<void *> (
      target_code_point + context->code_len_to_replace);
  modify_pointer[-1] = (void *)return_callback;

  flush_code (code_mem, template_size);
  return build_trampoline_okay;
}

bool
base_target_client::use_target_code_point_as_hint (void)
{
  return true;
}

bool
base_target_client::build_machine_define2 (code_context *context,
                                           dis_client *code_check_client)
{
  context->machine_defined2 = reinterpret_cast<void *> (-1);
  return true;
}

void
base_target_client::release_machine_define2 (code_context *context)
{
  context->machine_defined2 = NULL;
}
