#include <string.h>
#include <stdlib.h>
#include "mem_modify.h"
#include "arm_target_client.h"
#include "dis.h"
#include "dis_client.h"
#include "flush_code.h"
#include "log.h"

extern "C" {
extern void template_for_hook_thumb (void);
extern void template_for_hook_thumb_end (void);
extern void template_for_hook_thumb_ret (void);

extern void template_for_hook_arm (void);
extern void template_for_hook_arm_end (void);
extern void template_for_hook_arm_ret (void);
}
// that is what bw.w does
static intptr_t thumb_max_positive_jump = 16777214;
static intptr_t thumb_max_negative_jump = -16777216;

static intptr_t arm_max_positive_jump = 33554428;
static intptr_t arm_max_negative_jump = -33554432;

class arm_dis_client : public dis_client
{
public:
  arm_dis_client () : is_accept_ (true) {}
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
arm_dis_client::on_instr (const char *dis_str)
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
                     { "push", 4 },
                     { "pop", 3 },
                     { "ldr", 3 },
                     { "str", 3 },
                     { "add", 3 },
                     { "sub", 3 },
                     { "mul", 3 },
                     { "div", 3 },
                     { "xor", 3 },
                     { "or", 2 },
                     { "and", 3 },
                     { "not", 3 },
                     { "cmp", 3 },
                     { "lsl", 3 },
                     { "lsr", 3 },
                     { "asr", 3 },
                     { "asl", 3 },
                     { "tst", 3 } };
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
  if (strstr (dis_str, "pc"))
    {
      is_accept_ = false;
    }
}

void arm_dis_client::on_addr (intptr_t) {}

class arm_test_back_egde_client : public dis_client
{
public:
  arm_test_back_egde_client (intptr_t base, intptr_t hook_end);

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

arm_test_back_egde_client::arm_test_back_egde_client (intptr_t base,
                                                      intptr_t hook_end)
    : is_accept_ (true), base_ (base), hook_end_ (hook_end)
{
}

void
arm_test_back_egde_client::on_instr (const char *)
{
}

void
arm_test_back_egde_client::on_addr (intptr_t ref)
{
  if (ref < hook_end_ && ref >= base_)
    {
      is_accept_ = false;
    }
}

arm_target_client::arm_target_client () {}
arm_target_client::~arm_target_client () {}

int
arm_target_client::byte_needed_to_modify ()
{
  return 4;
}

disassembler *
arm_target_client::new_disassembler ()
{
  return new disasm::Disassembler ();
}

dis_client *
arm_target_client::new_code_check_client ()
{
  return new arm_dis_client ();
}

dis_client *
arm_target_client::new_backedge_check_client (intptr_t base, intptr_t hookend)
{
  return new arm_test_back_egde_client (base, hookend);
}

extern "C" {
extern void template_for_hook (void);
extern void template_for_hook_thumb_ret (void);
extern void template_for_hook_arm_ret (void);
extern void template_for_hook_end (void);
}

char *
arm_target_client::template_start (intptr_t target_code_point)
{
  if (target_code_point & 1)
    {
      intptr_t r = (intptr_t)template_for_hook_thumb;
      r &= static_cast<intptr_t> (~1);
      return (char *)r;
    }
  else
    {
      return (char *)template_for_hook_arm;
    }
}

char *
arm_target_client::template_ret_start (intptr_t target_code_point)
{
  intptr_t r;
  if (target_code_point & 1)
    {
      r = (intptr_t)template_for_hook_thumb_ret;
    }
  else
    {
      r = (intptr_t)template_for_hook_arm_ret;
    }
  r &= static_cast<intptr_t> (~1);
  return (char *)r;
}

char *
arm_target_client::template_end (intptr_t target_code_point)
{
  if (target_code_point & 1)
    {
      intptr_t r = (intptr_t)template_for_hook_thumb_end;
      r &= static_cast<intptr_t> (~1);
      return (char *)r;
    }
  else
    {
      return (char *)template_for_hook_arm_end;
    }
}

int
arm_target_client::max_tempoline_insert_space ()
{
  return 16;
}

bool
arm_target_client::check_jump_dist (intptr_t target_code_point,
                                    intptr_t trampoline_code_start)
{
  bool thumb = (target_code_point & 1) != 0;
  intptr_t jump_dist = trampoline_code_start
                       - ((target_code_point & static_cast<intptr_t> (~1))
                          + byte_needed_to_modify ());
  intptr_t max_positive_jump = target_code_point & 1 ? thumb_max_positive_jump
                                                     : arm_max_positive_jump;
  intptr_t max_negative_jump = target_code_point & 1 ? thumb_max_negative_jump
                                                     : arm_max_negative_jump;
  if (jump_dist < 0 && jump_dist < max_negative_jump)
    return false;
  if (jump_dist > 0 && jump_dist > max_positive_jump)
    return false;
  if (jump_dist & 1)
    return false;
  if (thumb)
    {
      if (jump_dist & 1)
        {
          return false;
        }
    }
  else
    {
      if (jump_dist & 3)
        {
          return false;
        }
    }
  return true;
}

void
arm_target_client::flush_code (void *code_start, int len)
{
  ::flush_code (code_start, len);
}

mem_modify_instr *
arm_target_client::modify_code (code_context *context)
{
  const intptr_t target_code_point
      = reinterpret_cast<intptr_t> (context->code_point);
  int code_len = reinterpret_cast<intptr_t> (context->machine_defined);
  mem_modify_instr *instr = static_cast<mem_modify_instr *> (
      malloc (sizeof (mem_modify_instr) + code_len - 1));
  instr->where = (void *)(target_code_point & static_cast<intptr_t> (~1));
  instr->size = code_len;
  intptr_t trampoline_code_start
      = reinterpret_cast<intptr_t> (context->trampoline_code_start);
  intptr_t jump_dist = trampoline_code_start
                       - ((target_code_point & static_cast<intptr_t> (~1))
                          + byte_needed_to_modify ());
  if (target_code_point & 1)
    {
      // thumb mode
      uint16_t *modify_intr_pointer
          = reinterpret_cast<uint16_t *> (&instr->data[0]);
      jump_dist >>= 1;
      uint16_t imm10 = static_cast<uint16_t> (
          (static_cast<uint32_t> (0x1ff800)
           & static_cast<uint32_t> (jump_dist)) >> static_cast<uint32_t> (11));
      uint16_t imm11 = static_cast<uint32_t> (0x7ff)
                       & static_cast<uint32_t> (jump_dist);
      uint16_t i2 = static_cast<uint32_t> (0x200000)
                    & static_cast<uint32_t> (jump_dist);
      uint16_t i1 = static_cast<uint32_t> (0x400000)
                    & static_cast<uint32_t> (jump_dist);
      int S = jump_dist < 0;
      uint16_t j2 = ((!i2) ^ S) & 1;
      uint16_t j1 = ((!i1) ^ S) & 1;
      S <<= 10;

      uint16_t first = static_cast<uint16_t> (30)
                       << static_cast<uint16_t> (11);
      first |= S;
      first |= imm10;
      uint16_t second = imm11;
      second |= static_cast<uint16_t> (j2) << static_cast<uint16_t> (11);
      second |= static_cast<uint16_t> (1) << static_cast<uint16_t> (12);
      second |= static_cast<uint16_t> (j1) << static_cast<uint16_t> (13);
      second |= static_cast<uint16_t> (1) << static_cast<uint16_t> (15);
      modify_intr_pointer[0] = first;
      modify_intr_pointer[1] = second;
    }
  else
    {
      uint32_t *modify_intr_pointer
          = reinterpret_cast<uint32_t *> (&instr->data[0]);
      jump_dist -= 4;
      jump_dist >>= 2;
      uint32_t whatever = 0xa;
      uint32_t code = whatever << 24;
      uint32_t cond = 0xe; // always
      code |= cond << 28;
      code |= (jump_dist & 0xffffff);
      modify_intr_pointer[0] = code;
    }
  return instr;
}

void
arm_target_client::copy_original_code (void *trampoline_code_start,
                                       void *target_code_point, int len)
{
  intptr_t target_code_point_i
      = reinterpret_cast<intptr_t> (target_code_point);
  target_code_point_i &= static_cast<intptr_t> (~1);
  memcpy (trampoline_code_start,
          reinterpret_cast<void *> (target_code_point_i), len);
}
