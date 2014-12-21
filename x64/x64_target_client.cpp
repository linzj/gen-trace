#include <string.h>

#include "x64_target_client.h"
#include "dis.h"
#include "dis_client.h"
#include "mem_modify.h"

// jmp *xxxx;
const static int byte_needed_to_modify = 6;
// 0000000000000000 <foo()>:
//    0:	55                   	push   %rbp
//    1:	48 89 e5             	mov    %rsp,%rbp
//    4:	ff 25 a0 aa aa 0a    	jmpq   *0xaaaaaa0(%rip)        #
//    aaaaaaa
//    a:	5d                   	pop    %rbp
//    b:	c3                   	retq

x64_target_client::x64_target_client () {}
x64_target_client::~x64_target_client () {}

class x64_dis_client : public dis_client
{
public:
  x64_dis_client () : is_accept_ (true) {}
  inline bool is_accept const() { return is_accept_; }

private:
  virtual void on_instr (const char *);
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
                     { "test", 4 } };
  for (int i = 0; i < sizeof (check_list) / sizeof (check_list[0]); ++i)
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

bool
x64_target_client::check_code (void *code_point, code_manager *m,
                               code_context **ppcontext)
{
  x64_dis_client dis_client;
  disasm::Disassembler dis (&dis_client);
  char *start = static_cast<char *> (code_point);
  int current = 0;
  while (current < byte_needed_to_modify && dis_client.is_accept ())
    {
      int len = dis.InstructionDecode (start);
      current += len;
      start += len;
    }
  if (dis_client.is_accept () == false)
    {
      return false;
    }
  code_context *context;
  context = m->new_context ();
  if (context == NULL)
    return false;
  context->code_point = code_point;
  context->machine_defined = reinterpret_cast<void *> (current);
  *ppcontext = context;
  return true;
}

bool
x64_target_client::build_trampoline (code_manager *, code_context *)
{
}

mem_modify_instr *
x64_target_client::modify_code (code_context *, void *called_callback,
                                void *return_callback)
{
}
