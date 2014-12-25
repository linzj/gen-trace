#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "x64_target_client.h"
#include "dis.h"
#include "dis_client.h"
#include "mem_modify.h"
#include "log.h"

// jmp *xxxx;
const static int max_positive_jump = 0x7fffffff;
const static int max_negative_jump = 0x80000000;
const static int nop = 0x90;
// 0000000000000000 <foo()>:
//    0:	55                   	push   %rbp
//    1:	48 89 e5             	mov    %rsp,%rbp
//    4:	e9 00 00 00 00       	jmpq   9 <foo()+0x9>
//    9:	5d                   	pop    %rbp
//    a:	c3                   	retq

x64_target_client::x64_target_client () {}
x64_target_client::~x64_target_client () {}

class x64_dis_client : public dis_client
{
public:
  x64_dis_client () : is_accept_ (true) {}
  inline bool
  is_accept ()
  {
    return is_accept_;
  }

private:
  virtual void on_instr (const char *);
  virtual void on_addr (intptr_t);
  bool is_accept_;
};

void
x64_dis_client::on_instr (const char *dis_str)
{
  // REMOVE PREFIX
  if (strncmp (dis_str, "REX.W ", 6) == 0)
    {
      dis_str += 6;
    }
  bool check_pass = false;
  // check the instr.
  struct
  {
    const char *instr_name;
    int size;
  } check_list[] = { { "mov", 3 },
                     { "add", 3 },
                     { "sub", 3 },
                     { "div", 3 },
                     { "push", 4 },
                     { "pop", 3 },
                     { "mul", 3 },
                     { "div", 3 },
                     { "xor", 3 },
                     { "pxor", 4 },
                     { "cvtsi2", 6 },
                     { "cltd", 4 },
                     { "or", 2 },
                     { "and", 3 },
                     { "cmp", 3 },
                     { "shr", 3 },
                     { "shl", 3 },
                     { "test", 4 } };
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
  virtual void on_instr (const char *);
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
x64_test_back_egde_client::on_instr (const char *)
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
x64_target_client::modify_code (code_context *context)
{
  const intptr_t target_code_point
      = reinterpret_cast<intptr_t> (context->code_point);
  int code_len = reinterpret_cast<intptr_t> (context->machine_defined);
  mem_modify_instr *instr = static_cast<mem_modify_instr *> (
      malloc (sizeof (mem_modify_instr) + code_len - 1));
  instr->where = context->code_point;
  instr->size = code_len;
  char *modify_intr_pointer = reinterpret_cast<char *> (&instr->data[0]);
  memset (modify_intr_pointer, 0x90, code_len);
  modify_intr_pointer[0] = 0xe9;
  intptr_t jump_dist
      = reinterpret_cast<intptr_t> (context->trampoline_code_start)
        - reinterpret_cast<intptr_t> (target_code_point
                                      + byte_needed_to_modify ());
  int jump_dist_int = static_cast<int> (jump_dist);
  memcpy (&modify_intr_pointer[1], &jump_dist_int, sizeof (int));
  return instr;
}

extern "C" {
extern void template_for_hook (void);
extern void template_for_hook2 (void);
extern void template_for_hook_end (void);
}

int
x64_target_client::byte_needed_to_modify ()
{
  return 5;
}

disassembler *
x64_target_client::new_disassembler ()
{
  return new disasm::Disassembler ();
}

dis_client *
x64_target_client::new_code_check_client ()
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

char *x64_target_client::template_ret_start (intptr_t)
{
  return (char *)template_for_hook2;
}

char *x64_target_client::template_end (intptr_t)
{
  return (char *)template_for_hook_end;
}

int
x64_target_client::max_tempoline_insert_space ()
{
  return 16;
}

bool
x64_target_client::check_jump_dist (intptr_t target_code_point,
                                    intptr_t trampoline_code_start)
{
  intptr_t jump_dist = trampoline_code_start
                       - (target_code_point + byte_needed_to_modify ());
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
                                       void *target_code_point, int len)
{
  memcpy (trampoline_code_start, target_code_point, code_len);
}
