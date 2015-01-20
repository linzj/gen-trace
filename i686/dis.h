#ifndef DIS_H
#define DIS_H
#include <memory>
#include "disassembler.h"
class dis_client;

namespace disasm
{

// A generic Disassembler interface
class Disassembler : public disassembler
{
public:
  // Caller deallocates converter.
  explicit Disassembler ();

  ~Disassembler ();

  // Returns the length of the disassembled machine instruction in bytes.
  virtual int instruction_decode (char *start);

  virtual void set_client (dis_client *client);

private:
  class DisassemblerImpl;
  std::unique_ptr<DisassemblerImpl> impl_;
};
#define DCHECK_EQ(a, b) assert ((a) == (b))
#define DCHECK_NE(a, b) assert ((a) != (b))
#define DCHECK(a) assert ((a))
#define CHECK(a) assert ((a))
#define UNREACHABLE __builtin_unreachable
#define UNIMPLEMENTED __builtin_trap

} // namespace disasm
#endif /* DIS_H */
