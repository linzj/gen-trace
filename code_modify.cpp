#include <vector>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "code_modify.h"
#include "code_manager_impl.h"
#include "mem_modify.h"

target_client::~target_client () {}

static target_client *g_client;
static code_manager *g_code_manager;
static const char *g_log_for_fail;

int
code_modify (const code_modify_desc *code_points, int count_of,
             pfn_called_callback called_callback,
             pfn_ret_callback return_callback)
{
  assert (g_client);
  assert (g_code_manager);
  typedef std::vector<mem_modify_instr *> instr_vector;
  instr_vector v;
  FILE *fp_for_fail = NULL;

  if (g_log_for_fail)
    {
      fp_for_fail = fopen (g_log_for_fail, "w");
    }
  for (int i = 0; i < count_of; ++i)
    {
      code_context *context;
      void *code_point = code_points[i].code_point;
      const char *name = code_points[i].name;
      int size = code_points[i].size;
      target_client::check_code_status check_code_status;
      if (target_client::check_code_okay
          == (check_code_status = g_client->check_code (
                  code_point, name, size, g_code_manager, &context)))
        {
          if (g_client->build_trampoline (g_code_manager, context,
                                          called_callback, return_callback))
            {
              mem_modify_instr *instr = g_client->modify_code (context);
              v.push_back (instr);
              if (fp_for_fail)
                fprintf (fp_for_fail, "build okay: %p, %s\n", code_point,
                         name);
            }
          else if (fp_for_fail)
            {
              fprintf (fp_for_fail, "build trampoline: %p, %s\n", code_point,
                       name);
            }
        }
      else
        {
          if (fp_for_fail)
            fprintf (fp_for_fail, "check code: %p, %s, %d\n", code_point, name,
                     check_code_status);
        }
    }
  if (fp_for_fail)
    {
      fclose (fp_for_fail);
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
code_modify_init (target_client *client)
{
  g_client = client;
  g_code_manager = new code_manager_impl ();
  return g_client != NULL && g_code_manager != NULL;
}

void
code_modify_set_log_for_fail (const char *log_for_fail_name)
{
  if (log_for_fail_name && log_for_fail_name[0] == '\0')
    return;
  g_log_for_fail = log_for_fail_name;
}
