#include <vector>
#include <stdlib.h>
#include "code_modify.h"
#include "code_manager_impl.h"
#include "mem_modify.h"

target_client::~target_client () {}

static target_client *g_client;
static code_manager *g_code_manager;

int
code_modify (const code_modify_desc *code_points, int count_of,
             void *called_callback, void *return_callback)
{
  typedef std::vector<mem_modify_instr *> instr_vector;
  instr_vector v;
  for (int i = 0; i < count_of; ++i)
    {
      code_context *context;
      void *code_point = code_points[i].code_point;
      const char *name = code_points[i].name;
      if (g_client->check_code (code_point, name, g_code_manager, &context))
        {
          if (g_client->build_trampoline (g_code_manager, context))
            {
              mem_modify_instr *instr = g_client->modify_code (
                  context, called_callback, return_callback);
              v.push_back (instr);
            }
        }
    }
  if (v.size () == 0)
    return 0;
  // commit the instr.
  mem_modify_instr **ppinst = new mem_modify_instr *[v.size ()];
  if (!ppinst)
    return false;
  {
    mem_modify_instr **_ppinst = ppinst;
    for (instr_vector::iterator i = v.begin (); i != v.end (); ++i, ++_ppinst)
      {
        *_ppinst = *i;
      }
  }
  int count_of_success
      = mem_modify (const_cast<const mem_modify_instr **> (ppinst), v.size ());
  delete[] ppinst;
  {
    for (instr_vector::iterator i = v.begin (); i != v.end (); ++i)
      {
        free (*i);
      }
  }
  return count_of_success;
}

bool
code_modify_init (target_client *(*func)(void))
{
  g_client = func ();
  g_code_manager = new code_manager_impl ();
  return g_client != NULL && g_code_manager != NULL;
}
