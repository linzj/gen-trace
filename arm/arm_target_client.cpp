#include <string.h>
#include <stdlib.h>
#include <vector>
#include <assert.h>
#include "mem_modify.h"
#include "arm_target_client.h"
#include "dis.h"
#include "dis_client.h"
#include "flush_code.h"
#include "log.h"

extern "C" {
extern void template_for_hook_thumb (void);
extern void template_for_hook_thumb_end (void);

extern void template_for_hook_arm (void);
extern void template_for_hook_arm_end (void);
}

static const int arm_byte_needed_to_modify = 12;
static const int thumb_byte_needed_to_modify = 10;

enum post_process_trampoline_type
{
  INVALID,
  BL,
};

struct post_process_trampoline_desc
{
  enum post_process_trampoline_type type;
  size_t offset;
  intptr_t addr;
  // type bl
  union
  {
    // for bl
    struct
    {
      bool is_blx;
    } bl;
  } un;
};

typedef std::vector<post_process_trampoline_desc> desc_vector;

class arm_dis_client : public check_code_dis_client
{
public:
  arm_dis_client (void *code_point);
  inline bool
  is_accept ()
  {
    return is_accept_;
  }

private:
  virtual void on_instr (const char *, char *start, size_t s);
  virtual void on_addr (intptr_t);
  virtual int lowered_original_code_len (int);
  void ensure_desc ();
  void advance (size_t);
  bool is_accept_;
  bool is_thumb_;
  size_t offset_;
  size_t lowered_original_code_len_;
  bool ip_appears_;
  intptr_t last_addr_;
  std::auto_ptr<desc_vector> desc_;
  friend class arm_target_client;
};

arm_dis_client::arm_dis_client (void *code_point)
    : is_accept_ (true),
      is_thumb_ ((reinterpret_cast<intptr_t> (code_point) & 1) != 0),
      offset_ (0), lowered_original_code_len_ (0), ip_appears_ (false),
      last_addr_ (-1)
{
}

void
arm_dis_client::ensure_desc ()
{
  if (desc_.get () == NULL)
    {
      desc_.reset (new desc_vector);
    }
}

void
arm_dis_client::advance (size_t s)
{
  offset_ += s;
  lowered_original_code_len_ += s;
}

void
arm_dis_client::on_instr (const char *dis_str, char *start, size_t s)
{
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
                     { "bl", 2 },
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
      advance (s);
      return;
    }
  char *operand;
  if ((operand = strchr (dis_str, '\t')))
    {
      operand += 1;
      if (strstr (operand, "ip"))
        {
          ip_appears_ = true;
        }
    }
  // check if pc position independent code is here.
  do
    {
      if (strstr (dis_str, "pc"))
        {
          is_accept_ = false;
        }
      // hack on bl inst
      else if (dis_str[0] == 'b')
        {
          // conditional is harder, not handle now.
          if (ip_appears_ || dis_str[2] != '\t')
            {
              is_accept_ = false;
              break;
            }
          // if this is a bl rx case.
          if (strrchr (dis_str, 'r'))
            {
              // just copy not need to handle
              break;
            }

          // movt, movw, blx ip
          int offset_add_end = 4 + 4 + (is_thumb_ ? 2 : 4);
          ensure_desc ();
          assert (last_addr_ != -1);
          post_process_trampoline_desc desc = { BL, offset_, last_addr_ };
          last_addr_ = -1;
          desc.un.bl.is_blx = false;
          desc_->push_back (desc);
          lowered_original_code_len_ += offset_add_end - s;
        }
    }
  while (false);
  advance (s);
}

void
arm_dis_client::on_addr (intptr_t addr)
{
  last_addr_ = addr;
}

int
arm_dis_client::lowered_original_code_len (int)
{
  return lowered_original_code_len_;
}

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
  virtual void on_instr (const char *, char *start, size_t s);
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
arm_test_back_egde_client::on_instr (const char *, char *start, size_t s)
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

check_code_dis_client *
arm_target_client::new_code_check_client (void *code_point)
{
  return new arm_dis_client (code_point);
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

static void
fill_thumb_movt_movw (intptr_t target, uint16_t *modify_intr_pointer, int bl)
{
  const uint16_t ip = 12;
  uint16_t first, second, third, forth, fifth;
  uint16_t lower_imm16 = (target & 0xffff);
  uint16_t higher_imm16 = static_cast<uintptr_t> (target & 0xffff0000) >> 16;
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
  fifth ^= (fifth & (1 << 7)) ^ ((bl & 1) << 7);
  modify_intr_pointer[0] = first;
  modify_intr_pointer[1] = second;
  modify_intr_pointer[2] = third;
  modify_intr_pointer[3] = forth;
  modify_intr_pointer[4] = fifth;
}

void
fill_arm_movt_movw (intptr_t target, uint32_t *modify_intr_pointer, int bl)
{
  const uint16_t ip = 12;
  // use movw ,movt as above.
  uint32_t first, second, third;
  uint32_t cond = 0xe; // always
  uint32_t lower_imm16 = (target & 0xffff);
  uint32_t higher_imm16 = static_cast<uintptr_t> (target & 0xffff0000) >> 16;
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
  third ^= (third & (1 << 5)) ^ ((bl & 1) << 5);

  modify_intr_pointer[0] = first;
  modify_intr_pointer[1] = second;
  modify_intr_pointer[2] = third;
}

mem_modify_instr *
arm_target_client::modify_code (code_context *context)
{
  const intptr_t target_code_point
      = reinterpret_cast<intptr_t> (context->code_point);
  int code_len_to_replace = context->code_len_to_replace;
  mem_modify_instr *instr = static_cast<mem_modify_instr *> (
      malloc (sizeof (mem_modify_instr) + code_len_to_replace - 1));
  instr->where = (void *)(target_code_point & static_cast<intptr_t> (~1));
  instr->size = code_len_to_replace;
  intptr_t trampoline_code_start
      = reinterpret_cast<intptr_t> (context->trampoline_code_start);
  if (target_code_point & 1)
    {
      // thumb mode
      uint16_t *modify_intr_pointer
          = reinterpret_cast<uint16_t *> (&instr->data[0]);
      fill_thumb_movt_movw (trampoline_code_start, modify_intr_pointer, 0);
    }
  else
    {
      uint32_t *modify_intr_pointer
          = reinterpret_cast<uint32_t *> (&instr->data[0]);
      fill_arm_movt_movw (trampoline_code_start, modify_intr_pointer, 0);
    }
  return instr;
}

static void
handle_bl_thumb (char *&start, char *&write, intptr_t addr, bool is_blx)
{
  start += 4;
  if (!is_blx)
    {
      addr |= 1;
    }
  fill_thumb_movt_movw (addr, reinterpret_cast<uint16_t *> (write), 1);
  write += thumb_byte_needed_to_modify;
}

static void
handle_thumb_entry (post_process_trampoline_desc &desc, char *&start,
                    char *&write)
{
  switch (desc.type)
    {
    case BL:
      handle_bl_thumb (start, write, desc.addr, desc.un.bl.is_blx);
      break;
    default:
      assert (false);
    }
}

static void
handle_bl_arm (char *&start, char *&write, intptr_t addr, bool is_blx)
{
  start += 4;
  fill_arm_movt_movw (addr, reinterpret_cast<uint32_t *> (write), 1);
  write += arm_byte_needed_to_modify;
}

static void
handle_arm_entry (post_process_trampoline_desc &desc, char *&start,
                  char *&write)
{
  switch (desc.type)
    {
    case BL:
      handle_bl_arm (start, write, desc.addr, desc.un.bl.is_blx);
      break;
    default:
      assert (false);
    }
}

void
arm_target_client::copy_original_code (void *trampoline_code_start,
                                       code_context *context)
{
  void *target_code_point = context->code_point;
  int len = context->code_len_to_replace;
  desc_vector *descs = static_cast<desc_vector *> (context->machine_defined2);
  if (!descs)
    {
      intptr_t target_code_point_i
          = reinterpret_cast<intptr_t> (target_code_point);
      target_code_point_i &= static_cast<intptr_t> (~1);
      memcpy (trampoline_code_start,
              reinterpret_cast<void *> (target_code_point_i), len);
      return;
    }
  assert (descs->empty () == false);
  char *_target_code_point = reinterpret_cast<char *> (
      reinterpret_cast<intptr_t> (target_code_point) & ~1UL);

  char *start = _target_code_point;
  char *write = static_cast<char *> (trampoline_code_start);
  bool is_thumb = (reinterpret_cast<intptr_t> (target_code_point) & 1) != 0;
  for (desc_vector::iterator i = descs->begin (); i != descs->end (); ++i)
    {
      char *end = _target_code_point + i->offset;
      memcpy (write, start, reinterpret_cast<int> (end - start));
      write += reinterpret_cast<int> (end - start);
      start = end;
      if (is_thumb)
        {
          handle_thumb_entry (*i, start, write);
        }
      else
        {
          handle_arm_entry (*i, start, write);
        }
    }
  memcpy (write, start,
          reinterpret_cast<int> (_target_code_point + len - start));
}

bool
arm_target_client::use_target_code_point_as_hint (void)
{
  return false;
}

bool
arm_target_client::build_machine_define2 (code_context *context,
                                          dis_client *code_check_client)
{
  arm_dis_client *real_client
      = static_cast<arm_dis_client *> (code_check_client);
  context->machine_defined2 = real_client->desc_.release ();
  return true;
}

void
arm_target_client::release_machine_define2 (code_context *context)
{
  if (context->machine_defined2)
    {
      delete static_cast<desc_vector *> (context->machine_defined2);
    }
}

void
arm_target_client::add_jump_to_original (char *code_start, int offset,
                                         code_context *code_context)
{
  if (reinterpret_cast<intptr_t> (code_context->code_point) & 1)
    {
      uint16_t *data = reinterpret_cast<uint16_t *> (code_start);
      data[0] = 0xf85f;
      offset -= 4;
      offset = -offset;
      // 4 byte align.
      offset &= ~(4UL - 1UL);
      data[1] = ((0xf) << 12) | offset;
    }
  else
    {
      uint32_t *data = reinterpret_cast<uint32_t *> (code_start);
      offset -= 8;
      offset = -offset;
      data[0] = 0xe51ff000 | offset;
    }
}

int
arm_target_client::jump_back_instr_len (code_context *)
{
  return 4;
}
