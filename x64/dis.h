#ifndef DIS_H
#define DIS_H
#include <memory>
class dis_client;

namespace disasm
{

typedef unsigned char byte;

// A generic Disassembler interface
class Disassembler
{
public:
  // Caller deallocates converter.
  explicit Disassembler (dis_client *client);

  ~Disassembler ();

  // Returns the length of the disassembled machine instruction in bytes.
  int InstructionDecode (char *start);

private:
  class DisassemblerImpl;
  std::auto_ptr<DisassemblerImpl> impl_;
};
#define DCHECK_EQ(a, b) assert ((a) == (b))
#define DCHECK_NE(a, b) assert ((a) != (b))
#define DCHECK(a) assert ((a))
#define CHECK(a) assert ((a))
#define UNREACHABLE __builtin_unreachable
#define UNIMPLEMENTED __builtin_trap

} // namespace disasm
#endif /* DIS_H */
