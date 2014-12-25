#include "arm_target_client.h"
#include "code_manager_impl.h"
#include <assert.h>
#include <stdlib.h>

unsigned int code[] = {
  0xe5d03000, 0xe3530047, 0x0a000001, 0xe3a00000, 0xe12fff1e, 0xe5d03001,
  0xe353004e, 0x1afffffa, 0xe5d03002, 0xe3530055, 0x1afffff7, 0xe5d03003,
  0xe3530043, 0x1afffff4, 0xe5d03004, 0xe3530043, 0x1afffff1, 0xe5d03005,
  0xe353002b, 0x1affffee, 0xe5d03006, 0xe353002b, 0x1affffeb, 0xe5d00007,
  0xe3500001, 0x83a00000, 0x93a00001, 0xe12fff1e,
};

unsigned short code_thumb[] = {
  0xb590, 0xb08b, 0xaf04, 0x4c69, 0x447c, 0xf04f, 0x33ff, 0x9300, 0x2300,
  0x9301, 0x2000, 0xf44f, 0x5180, 0x2207, 0x2322, 0xf7ff, 0xee18, 0x6178,
  0x697b, 0xf1b3, 0x3fff, 0xd110, 0xf7ff, 0xedf8, 0x4603, 0x681b, 0x4618,
  0xf7ff, 0xede8, 0x4602, 0x4b5c, 0x447b, 0x4618, 0x4611, 0xf000, 0xf94e,
  0x2001, 0xf7ff, 0xee6e, 0x697b, 0x613b, 0x693b, 0x4a57, 0x447a, 0x601a,
  0x693b, 0x3304, 0x4a56, 0x447a, 0x601a, 0x693b, 0x3308, 0x4a54, 0x447a,
  0x601a, 0x693b, 0x330c, 0x4a53, 0x447a, 0x601a, 0x4b52, 0x58e3, 0x60fb,
  0x4b52, 0x447b, 0x681b, 0xf003, 0x0301, 0x2b00, 0xd119, 0x4b4f, 0x447b,
  0x4618, 0xf000, 0xe960, 0x4603, 0x2b00, 0xbf14, 0x2301, 0x2300, 0xb2db,
  0x2b00, 0xd00c,
};
int
main ()
{
  code_manager_impl code_manager;
  {
    arm_target_client arm_target_client;
    target_client *target_client = &arm_target_client;
    code_context *cc;
    target_client::check_code_status c = target_client->check_code (
        code, "test", sizeof (code), &code_manager, &cc);
    assert (target_client::check_code_okay == c);
    assert (cc->code_point == &code[0]);
    assert (target_client->build_trampoline (
        &code_manager, cc, (pfn_called_callback)main, (pfn_ret_callback)main));
    assert (cc->trampoline_code_start != 0);
    mem_modify_instr *instr = target_client->modify_code (cc);
    assert (instr);
    free (instr);
  }
  {
    arm_target_client arm_target_client;
    target_client *target_client = &arm_target_client;
    code_context *cc;
    assert (target_client::check_code_okay
            == target_client->check_code (
                   reinterpret_cast<char *> (&code_thumb[0]) + 1, "test",
                   sizeof (code_thumb), &code_manager, &cc));
    assert (cc->code_point == reinterpret_cast<char *> (&code_thumb[0]) + 1);
    assert (target_client->build_trampoline (
        &code_manager, cc, (pfn_called_callback)main, (pfn_ret_callback)main));
    assert (cc->trampoline_code_start != 0);
    mem_modify_instr *instr = target_client->modify_code (cc);
    assert (instr);
    free (instr);
  }
}
