#include "i686_target_client.h"
#include "code_manager_impl.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

char data[] = "\x53"
              "\x31"
              "\xd2"
              "\x48"
              "\x89"
              "\xfb"
              "\x48"
              "\x89"
              "\xf7"
              "\x31"
              "\xf6"
              "\xe8"
              "\x80"
              "\x45"
              "\x50"
              "\x00";

int
main ()
{
  code_manager_impl code_manager;
  i686_target_client i686_target_client;
  target_client *target_client = &i686_target_client;
  std::unique_ptr<target_session> session
      = std::move (target_client->create_session ());
  check_code_result_buffer *b
      = target_client->check_code (data, "test", sizeof (data));
  assert (b && b->status == target_client::check_code_okay);
  assert (strcmp (b->name, "test") == 0);
  session->set_code_context (code_manager.new_context (b->name));
  session->set_check_code_result_buffer (b);
  code_context *cc = session->code_context ();
  cc->code_point = b->code_point;
  assert (cc->code_point == &data[0]);
  assert (target_client::build_trampoline_okay
          == target_client->build_trampoline (&code_manager, session.get (),
                                              (pfn_called_callback)main,
                                              (pfn_ret_callback)main));
  assert (cc->trampoline_code_start != 0);
  mem_modify_instr *instr = target_client->modify_code (session.get ());
  assert (instr);
  free (instr);
  free (b);
}
