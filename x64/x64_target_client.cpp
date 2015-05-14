#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "x64_target_client.h"
#include "dis.h"
#include "dis_client.h"
#include "mem_modify.h"
#include "log.h"

// jmp *xxxx;
const static int max_positive_jump = 0x7fffffff;
const static int max_negative_jump = 0x80000000;
const static int nop = 0x90;
const static int byte_needed_to_modify_const = 5;
// 0000000000000000 <foo()>:
//    0:	55                   	push   %rbp
//    1:	48 89 e5             	mov    %rsp,%rbp
//    4:	e9 00 00 00 00       	jmpq   9 <foo()+0x9>
//    9:	5d                   	pop    %rbp
//    a:	c3                   	retq

x64_target_client::x64_target_client () {}
x64_target_client::~x64_target_client () {}

class x64_dis_client : public check_code_dis_client
{
public:
  x64_dis_client () : is_accept_ (true) {}
  inline bool
  is_accept ()
  {
    return is_accept_;
  }

private:
  virtual void on_instr (const char *, char *start, size_t s);
  virtual void on_addr (intptr_t);
  virtual int lowered_original_code_len (int code_len_to_replace);
  virtual size_t extend_buffer_size ();
  virtual void fill_buffer (void *);
  bool is_accept_;
};

void
x64_dis_client::on_instr (const char *dis_str, char *start, size_t s)
{
  bool check_pass = false;
  // check the instr.
  struct
  {
    const char *instr_name;
    int size;
  } check_list[]
      = { { "mov", 3 },  { "add", 3 },  { "sub", 3 },    { "div", 3 },
          { "push", 4 }, { "pop", 3 },  { "mul", 3 },    { "div", 3 },
          { "xor", 3 },  { "pxor", 4 }, { "cvtsi2", 6 }, { "cltd", 4 },
          { "or", 2 },   { "and", 3 },  { "cmp", 3 },    { "shr", 3 },
          { "shl", 3 },  { "test", 4 } };
  for (size_t i = 0; i < sizeof (check_list) / sizeof (check_list[0]); ++i)
    {
      if (strncmp (dis_str, check_list[i].instr_name, check_list[i].size) == 0)
        {
          check_pass = true;
          break;
        }
    }
  if (!check_pass)
    {
      is_accept_ = false;
      return;
    }
  // check if rip position independent code is here.
  if (strstr (dis_str, "rip"))
    {
      is_accept_ = false;
    }
}

void x64_dis_client::on_addr (intptr_t) {}

int
x64_dis_client::lowered_original_code_len (int code_len_to_replace)
{
  return code_len_to_replace;
}

size_t
x64_dis_client::extend_buffer_size ()
{
  return 0;
}

void
x64_dis_client::fill_buffer (void *)
{
  __builtin_unreachable ();
}

class x64_test_back_egde_client : public dis_client
{
public:
  x64_test_back_egde_client (intptr_t base, intptr_t hook_end);

  bool
  is_accept ()
  {
    return is_accept_;
  }

private:
  virtual void on_instr (const char *, char *start, size_t s);
  virtual void on_addr (intptr_t);
  bool is_accept_;
  intptr_t base_;
  intptr_t hook_end_;
};

x64_test_back_egde_client::x64_test_back_egde_client (intptr_t base,
                                                      intptr_t hook_end)
    : is_accept_ (true), base_ (base), hook_end_ (hook_end)
{
}

void
x64_test_back_egde_client::on_instr (const char *, char *start, size_t s)
{
}

void
x64_test_back_egde_client::on_addr (intptr_t ref)
{
  if (ref < hook_end_ && ref >= base_)
    {
      is_accept_ = false;
    }
}

mem_modify_instr *
x64_target_client::modify_code (target_session *session)
{
  code_context *context = session->code_context ();
  check_code_result_buffer *b = session->check_code_result_buffer ();
  const intptr_t target_code_point
      = reinterpret_cast<intptr_t> (context->code_point);
  int code_len_to_replace = b->code_len_to_replace;
  mem_modify_instr *instr = static_cast<mem_modify_instr *> (
      malloc (sizeof (mem_modify_instr) + code_len_to_replace - 1));
  instr->where = context->code_point;
  instr->size = code_len_to_replace;
  char *modify_intr_pointer = reinterpret_cast<char *> (&instr->data[0]);
  memset (modify_intr_pointer, 0x90, code_len_to_replace);
  modify_intr_pointer[0] = 0xe9;
  intptr_t jump_dist
      = reinterpret_cast<intptr_t> (context->trampoline_code_start)
        - reinterpret_cast<intptr_t> (target_code_point
                                      + byte_needed_to_modify_const);
  int jump_dist_int = static_cast<int> (jump_dist);
  memcpy (&modify_intr_pointer[1], &jump_dist_int, sizeof (int));
  return instr;
}

extern "C" {
extern void template_for_hook (void);
extern void template_for_hook_end (void);
}

int x64_target_client::byte_needed_to_modify (intptr_t)
{
  return byte_needed_to_modify_const;
}

disassembler *
x64_target_client::new_disassembler ()
{
  return new disasm::Disassembler ();
}

check_code_dis_client *
x64_target_client::new_code_check_client (void *)
{
  return new x64_dis_client ();
}

dis_client *
x64_target_client::new_backedge_check_client (intptr_t base, intptr_t hookend)
{
  return new x64_test_back_egde_client (base, hookend);
}

char *x64_target_client::template_start (intptr_t)
{
  return (char *)template_for_hook;
}

char *x64_target_client::template_end (intptr_t)
{
  return (char *)template_for_hook_end;
}

bool
x64_target_client::check_jump_dist (intptr_t target_code_point,
                                    intptr_t trampoline_code_start)
{
  intptr_t jump_dist = trampoline_code_start
                       - (target_code_point + byte_needed_to_modify_const);
  if (jump_dist < 0 && jump_dist < max_negative_jump)
    return false;
  if (jump_dist > 0 && jump_dist > max_positive_jump)
    return false;
  return true;
}

void
x64_target_client::flush_code (void *, int)
{
  // x64 does not need this.
}

void
x64_target_client::copy_original_code (void *trampoline_code_start,
                                       check_code_result_buffer *b)
{
  void *target_code_point = b->code_point;
  int len = b->code_len_to_replace;
  memcpy (trampoline_code_start, target_code_point, len);
}

void
x64_target_client::add_jump_to_original (char *code_start, int offset,
                                         code_context *code_context)
{
  offset -= 6;
  code_start[0] = 0xff;
  code_start[1] = 0x25;
  memcpy (code_start + 2, &offset, 4);
}

int
x64_target_client::jump_back_instr_len (code_context *)
{
  return 6;
}
