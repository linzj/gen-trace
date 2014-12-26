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
  0xb5f0, 0xb085, 0x1c1d, 0xab0a, 0x1c0e, 0xcb02, 0x1c17, 0x1c04, 0x781b,
  0x6045, 0x9303, 0x7802, 0xab0c, 0x781b, 0x07d1, 0xd500, 0xe03a, 0x2b00,
  0xd005, 0x69c0, 0x2201, 0x6803, 0x9200, 0x685f, 0xe01f,

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
    assert (target_client::build_trampoline_okay
            == target_client->build_trampoline (&code_manager, cc,
                                                (pfn_called_callback)main,
                                                (pfn_ret_callback)main));
    assert (cc->trampoline_code_start != 0);
    mem_modify_instr *instr = target_client->modify_code (cc);
    assert (instr);
    free (instr);
  }
  {
    arm_target_client arm_target_client;
    target_client *target_client = &arm_target_client;
    code_context *cc;
    target_client::check_code_status c = target_client->check_code (
        reinterpret_cast<char *> (&code_thumb[0]) + 1, "test",
        sizeof (code_thumb), &code_manager, &cc);
    assert (target_client::check_code_okay == c);
    assert (cc->code_point == reinterpret_cast<char *> (&code_thumb[0]) + 1);
    assert (target_client::build_trampoline_okay
            == target_client->build_trampoline (&code_manager, cc,
                                                (pfn_called_callback)main,
                                                (pfn_ret_callback)main));
    assert (cc->trampoline_code_start != 0);
    mem_modify_instr *instr = target_client->modify_code (cc);
    assert (instr);
    free (instr);
  }
}
