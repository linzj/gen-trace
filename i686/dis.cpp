#include "dis.h"
#include "dis_client.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <memory.h>
#include <stdint.h>
#include "dis_gnu.h"

namespace disasm
{
class Disassembler::DisassemblerImpl
{
public:
  DisassemblerImpl ();
  disassemble_info info_;
  dis_client *client_;
  char buf_[512];
  char *pos_;
  char *end_;

  static int _fprintf_ (void *, const char *, ...)
      __attribute__ ((__format__ (__printf__, 2, 3)))
      __attribute__ ((__nonnull__ (2)));
  static void print_address (bfd_vma addr, struct disassemble_info *dinfo);
  void flush (char *start, size_t s);
};

int
Disassembler::DisassemblerImpl::_fprintf_ (void *stream, const char *fmt, ...)
{
  DisassemblerImpl *impl = static_cast<DisassemblerImpl *> (stream);
  va_list args;
  va_start (args, fmt);
  int num_of_chars = vsnprintf (
      impl->pos_, static_cast<size_t> (impl->end_ - impl->pos_), fmt, args);
  va_end (args);
  impl->pos_ += num_of_chars;
  assert (impl->pos_ <= impl->end_);
  return num_of_chars;
}

void
Disassembler::DisassemblerImpl::flush (char *start, size_t s)
{
  client_->on_instr (buf_, start, s);
  pos_ = buf_;
  pos_[0] = '\0';
}
static int
read_memory (bfd_vma memaddr, bfd_byte *myaddr, unsigned int length,
             struct disassemble_info *dinfo)
{
  memcpy (myaddr, reinterpret_cast<void *> (memaddr), length);
  return 0;
}

static void
memory_error (int status, bfd_vma memaddr, struct disassemble_info *dinfo)
{
  __builtin_unreachable ();
}

void
Disassembler::DisassemblerImpl::print_address (bfd_vma addr,
                                               struct disassemble_info *dinfo)
{
  DisassemblerImpl *impl = static_cast<DisassemblerImpl *> (dinfo->stream);
  impl->client_->on_addr (addr);
}

Disassembler::DisassemblerImpl::DisassemblerImpl ()
    : client_ (NULL), pos_ (&buf_[0])
{
  end_ = pos_ + 512;
  info_.fprintf_func = _fprintf_;
  info_.stream = this;
  info_.address_mode = mode_32bit;
  info_.read_memory_func = read_memory;
  info_.memory_error_func = memory_error;
  info_.print_address_func = print_address;
}
}
extern "C" {
extern int print_insn_i386 (bfd_vma, disassemble_info *);
}

//------------------------------------------------------------------------------

namespace disasm
{
Disassembler::Disassembler () : impl_ (new DisassemblerImpl ()) {}

Disassembler::~Disassembler () {}

int
Disassembler::instruction_decode (char *start)
{
  int octets
      = print_insn_i386 (reinterpret_cast<bfd_vma> (start), &impl_->info_);
  if (impl_->pos_ != &impl_->buf_[0])
    {
      impl_->flush (start, octets);
    }
  return octets;
}

void
Disassembler::set_client (dis_client *client)
{
  impl_->client_ = client;
}

// The X64 assembler does not use constant pools.

} // namespace disasm
