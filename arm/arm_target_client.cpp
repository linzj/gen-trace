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

static const int arm_byte_needed_to_modify = 12;
static const int thumb_byte_needed_to_modify = 10;

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
                     { "stm", 3 },
                     { "ldm", 3 },
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
arm_target_client::byte_needed_to_modify (intptr_t target_code_point)
{
  if (target_code_point & 1)
    {
      return thumb_byte_needed_to_modify;
    }
  else
    {
      return arm_byte_needed_to_modify;
    }
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
  const uint16_t ip = 12;
  if (target_code_point & 1)
    {
      // thumb mode
      uint16_t *modify_intr_pointer
          = reinterpret_cast<uint16_t *> (&instr->data[0]);
      uint16_t first, second, third, forth, fifth;
      uint16_t lower_imm16 = (trampoline_code_start & 0xffff);
      uint16_t higher_imm16
          = static_cast<uintptr_t> (trampoline_code_start & 0xffff0000) >> 16;
      // first second: movw
      {
        uint16_t i = (lower_imm16 & (1 << (8 + 3))) >> (8 + 3);
        uint16_t imm8 = lower_imm16 & (0xff);
        uint16_t imm3 = (lower_imm16 & 0x700) >> 8;
        uint16_t imm4 = (lower_imm16 & 0xf000) >> (8 + 3 + 1);
        first = 0x1e << 11;
        first |= i << 10;
        first |= 0x24 << 4;
        first |= imm4;
        second = imm3 << 12;
        second |= ip << 8;
        second |= imm8;
        second |= 1;
      }
      // third forth: movt
      {
        uint16_t i = (higher_imm16 & (1 << (8 + 3))) >> (8 + 3);
        uint16_t imm8 = higher_imm16 & (0xff);
        uint16_t imm3 = (higher_imm16 & 0x700) >> 8;
        uint16_t imm4 = (higher_imm16 & 0xf000) >> (8 + 3 + 1);
        third = 0x1e << 11;
        third |= i << 10;
        third |= 0x2c << 4;
        third |= imm4;
        forth = imm3 << 12;
        forth |= ip << 8;
        forth |= imm8;
      }
      {
        fifth = 0x8e << 7;
        fifth |= ip << 3;
      }

      modify_intr_pointer[0] = first;
      modify_intr_pointer[1] = second;
      modify_intr_pointer[2] = third;
      modify_intr_pointer[3] = forth;
      modify_intr_pointer[4] = fifth;
    }
  else
    {
      uint32_t *modify_intr_pointer
          = reinterpret_cast<uint32_t *> (&instr->data[0]);
      // use movw ,movt as above.
      uint32_t first, second, third;
      uint32_t cond = 0xe; // always
      uint32_t lower_imm16 = (trampoline_code_start & 0xffff);
      uint32_t higher_imm16
          = static_cast<uintptr_t> (trampoline_code_start & 0xffff0000) >> 16;
      {
        uint32_t imm4 = (lower_imm16 & 0xf000) >> 12;
        uint32_t imm12 = 0xfff & lower_imm16;
        first = cond << 28;
        first |= 0x30 << 20;
        first |= imm4 << 16;
        first |= ip << 12;
        first |= imm12;
      }
      {
        uint32_t imm4 = (higher_imm16 & 0xf000) >> 12;
        uint32_t imm12 = 0xfff & higher_imm16;
        second = cond << 28;
        second |= 0x34 << 20;
        second |= imm4 << 16;
        second |= ip << 12;
        second |= imm12;
      }

      {
        third = cond << 28;
        third |= 0x12fff1 << 4;
        third |= ip;
      }

      modify_intr_pointer[0] = first;
      modify_intr_pointer[1] = second;
      modify_intr_pointer[2] = third;
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

bool
arm_target_client::use_target_code_point_as_hint (void)
{
  return false;
}
