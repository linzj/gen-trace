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

std::unique_ptr<target_session>
base_target_client::create_session ()
{
  return std::unique_ptr<target_session> (new target_session);
}

check_code_result_buffer *
base_target_client::check_code (void *code_point, const char *name,
                                int code_size)
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
    return alloc_check_code_result_buffer (code_point, name,
                                           check_code_too_small, 0);
  while (current < _byte_needed_to_modify && code_check_client->is_accept ())
    {
      int len = dis->instruction_decode (start);
      current += len;
      start += len;
    }
  if (code_check_client->is_accept () == false)
    {
      check_code_result_buffer *b = alloc_check_code_result_buffer (
          code_point, name, check_code_not_accept, sizeof (intptr_t));
      *reinterpret_cast<intptr_t *> (b + 1)
          = reinterpret_cast<intptr_t> (start);
      return b;
    }
  if (!check_for_back_edge (dis.get (), static_cast<char *> (code_point),
                            start,
                            static_cast<char *> (code_point) + code_size))
    {
      return alloc_check_code_result_buffer (code_point, name,
                                             check_code_back_edge, 0);
    }
  return build_check_okay (code_point, name, current,
                           code_check_client.get ());
}

target_client::build_trampoline_status
base_target_client::build_trampoline (code_manager *m, target_session *session,
                                      pfn_called_callback called_callback,
                                      pfn_ret_callback return_callback)
{
  code_context *context = session->code_context ();
  check_code_result_buffer *b = session->check_code_result_buffer ();
  const intptr_t target_code_point
      = reinterpret_cast<intptr_t> (context->code_point);
  char *const _template_start = template_start (target_code_point);
  char *const _template_end = template_end (target_code_point);
  const int template_code_size
      = (char *)_template_end - (char *)_template_start
        + b->lowered_original_code_len + jump_back_instr_len (context);
  int template_size = template_code_size + sizeof (intptr_t) * 4;
  template_size
      = (template_size + sizeof (intptr_t) - 1) & ~(sizeof (intptr_t) - 1);
  void *hint;
  if (use_target_code_point_as_hint ())
    {
      hint = context->code_point;
    }
  else
    {
      hint = nullptr;
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
  context->trampoline_code_end
      = reinterpret_cast<char *> (code_start) + template_code_size;
  // copy the hook template to code mem.
  const int template_code_size_no_copy
      = (char *)_template_end - (char *)_template_start;
  memcpy (reinterpret_cast<void *> (code_start), (char *)_template_start,
          template_code_size_no_copy);

  // copy the original target code to trampoline
  char *copy_start
      = reinterpret_cast<char *> (code_start) + template_code_size_no_copy;

  copy_original_code (copy_start, b);
  int lowered_original_code_len = b->lowered_original_code_len;
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
  modify_pointer[-2]
      = reinterpret_cast<void *> (target_code_point + b->code_len_to_replace);
  modify_pointer[-1] = (void *)return_callback;

  flush_code (code_mem, template_size);
  return build_trampoline_okay;
}

bool
base_target_client::use_target_code_point_as_hint (void)
{
  return true;
}

check_code_result_buffer *
base_target_client::build_check_okay (void *code, const char *name,
                                      int code_len_to_replace,
                                      check_code_dis_client *code_check_client)
{
  size_t s = code_check_client->extend_buffer_size ();
  check_code_result_buffer *b
      = alloc_check_code_result_buffer (code, name, check_code_okay, s);
  b->code_len_to_replace = code_len_to_replace;
  b->lowered_original_code_len
      = code_check_client->lowered_original_code_len (code_len_to_replace);
  if (s != 0)
    code_check_client->fill_buffer (b + 1);
  return b;
}

check_code_result_buffer *
base_target_client::alloc_check_code_result_buffer (
    void *code_point, const char *name,
    enum target_client::check_code_status status, size_t s)
{
  check_code_result_buffer *b = static_cast<check_code_result_buffer *> (
      malloc (s + sizeof (check_code_result_buffer)));
  if (!b)
    {
      return nullptr;
    }
  b->code_point = code_point;
  b->name = name;
  b->status = status;
  b->size = s;
  return b;
}
