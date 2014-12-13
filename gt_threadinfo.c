#include "valgrind.h"
#include "pub_tool_basics.h"
#include "pub_tool_libcproc.h"
#include "include/pub_tool_mallocfree.h"
#include "pub_tool_tooliface.h"
#include <stdint.h>
#include <time.h>

#include "gt_threadinfo.h"
#include "gt_time.h"
#include "gt_config.h"

static ThreadId s_tid;

struct ThreadInfo s_thread_info[MAX_THREAD_INFO];

struct ThreadInfo *
gt_get_thread_info (void)
{
  int index;
  struct ThreadInfo *ret;
  if (s_tid > MAX_THREAD_INFO)
    return NULL;
  index = s_tid - 1;
  ret = &s_thread_info[index];
  if (ret->tid_ == 0)
    {
      // initialize it if possible
      ret->tid_ = s_tid;
      ret->pid_ = VG_ (getpid)();
      ret->last_jumpkind_ = Ijk_INVALID;
      ret->stack_ = VG_ (malloc)("gentrace.stack",
                                 sizeof (struct CTraceStruct) * s_max_stack);
      ret->bc_jumpkind_ = Ijk_INVALID;
      if (s_use_estimated_time)
        {
          ret->estimated_thread_ns_
              = gt_get_times_from_clock_ (CLOCK_MONOTONIC) * 1000;
        }
    }
  return ret;
}

static void
gt_start_client_code_callback (ThreadId tid, ULong blocks_done)
{
  s_tid = tid;
}

void
gt_thread_info_init (void)
{
  VG_ (track_start_client_code)(&gt_start_client_code_callback);
}
