#define __STDC_FORMAT_MACROS
#include <vector>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "code_modify.h"
#include "code_manager_impl.h"
#include "mem_modify.h"
#include "log.h"
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#define USE_PERF 1

typedef std::vector<mem_modify_instr *> instr_vector;
typedef std::vector<check_code_result_buffer *> check_result_vector;

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
  virtual std::unique_ptr<target_session> create_session ();
  virtual check_code_result_buffer *check_code (void *, const char *,
                                                int code_size);
  virtual build_trampoline_status
  build_trampoline (code_manager *, target_session *,
                    pfn_called_callback called_callback,
                    pfn_ret_callback return_callback);
  virtual mem_modify_instr *modify_code (target_session *);
  void check_env ();

  uint64_t env_;
  uint64_t check_code_;
  uint64_t build_trampoline_;
  uint64_t modify_code_;
  target_client *real_;
};

perf_target_client::perf_target_client ()
    : env_ (0), check_code_ (0), build_trampoline_ (0), modify_code_ (0),
      real_ (nullptr)
{
}

std::unique_ptr<target_session>
perf_target_client::create_session ()
{
  return real_->create_session ();
}

check_code_result_buffer *
perf_target_client::check_code (void *p1, const char *p2, int p3)
{
  timespec t1, t2;
  clock_gettime (CLOCK_MONOTONIC, &t1);
  auto r = real_->check_code (p1, p2, p3);
  clock_gettime (CLOCK_MONOTONIC, &t2);
  uint64_t elapse = (t2.tv_sec - t1.tv_sec) * 1e9 + (t2.tv_nsec - t2.tv_nsec);
  elapse /= 1000;
  env_ += elapse;
  check_code_ += elapse;
  check_env ();
  return r;
}

target_client::build_trampoline_status
perf_target_client::build_trampoline (code_manager *p1, target_session *p2,
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
perf_target_client::modify_code (target_session *p1)
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
      LOGI ("env_ = %" PRIu64 ", check_code_ = %" PRIu64
            ", build_trampoline_ = %" PRIu64 ", "
            "modify_code = %" PRIu64 "\n",
            env_, check_code_, build_trampoline_, modify_code_);
      env_ = 0;
      check_code_ = 0;
      build_trampoline_ = 0;
      modify_code_ = 0;
    }
}

static void
free_check_results (check_result_vector &check_results)
{
  for (auto r : check_results)
    {
      free (r);
    }
  check_results.resize (0);
}

int
code_modify (const code_modify_desc *code_points, int count_of,
             pfn_called_callback called_callback,
             pfn_ret_callback return_callback)
{
  assert (g_client);
  assert (g_code_manager);
  instr_vector v;
  check_result_vector check_results;
  FILE *fp_for_fail = nullptr;

  if (g_log_for_fail)
    {
      static bool first_come = true;
      const char *open_mode;
      if (first_come)
        {
          open_mode = "w";
          first_come = false;
        }
      else
        {
          open_mode = "a";
        }
      fp_for_fail = fopen (g_log_for_fail, open_mode);
    }
  for (int i = 0; i < count_of; ++i)
    {
      void *code_point = code_points[i].code_point;
      const char *name = code_points[i].name;
      int size = code_points[i].size;
      // That means this code point should be ignored.
      if (code_points[i].ignore)
        continue;
      check_code_result_buffer *b
          = g_client->check_code (code_point, name, size);
      if (b)
        {
          check_results.push_back (b);
        }
    }
  std::unique_ptr<target_session> session
      = std::move (g_client->create_session ());

  for (auto result : check_results)
    {
      void *code_point = result->code_point;
      const char *name = result->name;
      target_client::check_code_status check_code_status = result->status;
      if (check_code_status == target_client::check_code_okay)
        {
          session->set_check_code_result_buffer (result);
          session->set_code_context (
              g_code_manager->new_context (result->name));
          assert (session->code_context () != nullptr);
          session->code_context ()->code_point = result->code_point;
          target_client::build_trampoline_status build_trampoline_status;
          if (target_client::build_trampoline_okay
              == (build_trampoline_status = g_client->build_trampoline (
                      g_code_manager, session.get (), called_callback,
                      return_callback)))
            {
              mem_modify_instr *instr = g_client->modify_code (session.get ());
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
            {
              if (check_code_status != target_client::check_code_not_accept)
                {
                  fprintf (fp_for_fail, "check code: %p, %s, %d\n", code_point,
                           name, check_code_status);
                }
              else
                {
                  fprintf (fp_for_fail, "check code not accept: %p, %s, %p\n",
                           code_point, name,
                           *reinterpret_cast<char **> (result + 1));
                }
            }
        }
    }
  if (fp_for_fail)
    {
      fclose (fp_for_fail);
    }
  free_check_results (check_results);
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
  if (g_client == nullptr)
    g_client = client;
  if (g_code_manager == nullptr)
    g_code_manager = new code_manager_impl ();
  if (g_perf_target_client == nullptr)
    g_perf_target_client = new perf_target_client ();
#ifdef USE_PERF
  if (g_client != g_perf_target_client)
    {
      g_perf_target_client->set_client (g_client);
      g_client = g_perf_target_client;
    }
#endif
  return g_client != nullptr && g_code_manager != nullptr;
}

void
code_modify_set_log_for_fail (const char *log_for_fail_name)
{
  if (log_for_fail_name && log_for_fail_name[0] == '\0')
    return;
  g_log_for_fail = log_for_fail_name;
}

target_session::target_session () : context_ (nullptr), buffer_ (nullptr) {}

target_session::~target_session () {}
