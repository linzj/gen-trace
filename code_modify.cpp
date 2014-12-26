#include <vector>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "code_modify.h"
#include "code_manager_impl.h"
#include "mem_modify.h"
#include "log.h"
#include <time.h>

target_client::~target_client () {}

class perf_target_client;
static target_client *g_client;
static code_manager *g_code_manager;
static const char *g_log_for_fail;
static perf_target_client *g_perf_target_client;

class perf_target_client : public target_client
{
public:
  perf_target_client ();
  inline void
  set_client (target_client *client)
  {
    real_ = client;
  }

private:
  virtual check_code_status check_code (void *, const char *, int code_size,
                                        code_manager *, code_context **);
  virtual build_trampoline_status
  build_trampoline (code_manager *, code_context *,
                    pfn_called_callback called_callback,
                    pfn_ret_callback return_callback);
  virtual mem_modify_instr *modify_code (code_context *);
  void check_env ();

  uint64_t env_;
  uint64_t check_code_;
  uint64_t build_trampoline_;
  uint64_t modify_code_;
  target_client *real_;
};

perf_target_client::perf_target_client ()
    : env_ (0), check_code_ (0), build_trampoline_ (0), modify_code_ (0),
      real_ (NULL)
{
}

target_client::check_code_status
perf_target_client::check_code (void *p1, const char *p2, int p3,
                                code_manager *p4, code_context **p5)
{
  timespec t1, t2;
  clock_gettime (CLOCK_MONOTONIC, &t1);
  check_code_status status = real_->check_code (p1, p2, p3, p4, p5);
  clock_gettime (CLOCK_MONOTONIC, &t2);
  uint64_t elapse = (t2.tv_sec - t1.tv_sec) * 1e9 + (t2.tv_nsec - t2.tv_nsec);
  elapse /= 1000;
  env_ += elapse;
  check_code_ += elapse;
  check_env ();
  return status;
}

target_client::build_trampoline_status
perf_target_client::build_trampoline (code_manager *p1, code_context *p2,
                                      pfn_called_callback p3,
                                      pfn_ret_callback p4)
{
  timespec t1, t2;
  clock_gettime (CLOCK_MONOTONIC, &t1);
  build_trampoline_status status = real_->build_trampoline (p1, p2, p3, p4);
  clock_gettime (CLOCK_MONOTONIC, &t2);
  uint64_t elapse = (t2.tv_sec - t1.tv_sec) * 1e9 + (t2.tv_nsec - t2.tv_nsec);
  elapse /= 1000;
  env_ += elapse;
  build_trampoline_ += elapse;
  check_env ();
  return status;
}

mem_modify_instr *
perf_target_client::modify_code (code_context *p1)
{
  timespec t1, t2;
  clock_gettime (CLOCK_MONOTONIC, &t1);
  mem_modify_instr *ret = real_->modify_code (p1);
  clock_gettime (CLOCK_MONOTONIC, &t2);
  uint64_t elapse = (t2.tv_sec - t1.tv_sec) * 1e9 + (t2.tv_nsec - t2.tv_nsec);
  elapse /= 1000;
  env_ += elapse;
  modify_code_ += elapse;
  check_env ();
  return ret;
}

void
perf_target_client::check_env ()
{
  if (env_ > 1e6)
    {
      LOGI ("env_ = %ld, check_code_ = %ld, build_trampoline_ = %ld, "
            "modify_code = %ld\n",
            env_, check_code_, build_trampoline_, modify_code_);
      env_ = 0;
      check_code_ = 0;
      build_trampoline_ = 0;
      modify_code_ = 0;
    }
}

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
          target_client::build_trampoline_status build_trampoline_status;
          if (target_client::build_trampoline_okay
              == (build_trampoline_status = g_client->build_trampoline (
                      g_code_manager, context, called_callback,
                      return_callback)))
            {
              mem_modify_instr *instr = g_client->modify_code (context);
              v.push_back (instr);
              if (fp_for_fail)
                fprintf (fp_for_fail, "build okay: %p, %s\n", code_point,
                         name);
            }
          else if (fp_for_fail)
            {
              fprintf (fp_for_fail, "build trampoline: %p, %s, %d\n",
                       code_point, name, build_trampoline_status);
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
  if (g_client == NULL)
    g_client = client;
  if (g_code_manager == NULL)
    g_code_manager = new code_manager_impl ();
  if (g_perf_target_client == NULL)
    g_perf_target_client = new perf_target_client ();
  return g_client != NULL && g_code_manager != NULL;
}

void
code_modify_set_log_for_fail (const char *log_for_fail_name)
{
  if (log_for_fail_name && log_for_fail_name[0] == '\0')
    return;
  g_log_for_fail = log_for_fail_name;
}
