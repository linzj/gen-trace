#include "valgrind.h"
#include "pub_tool_basics.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_tooliface.h"
#include <stdint.h>
#include <time.h>

#include "gt_threadinfo.h"
#include "gt_time.h"
#include "gt_config.h"

static ThreadId s_tid;

#define MAX_THREAD_INFO (1000)
static struct ThreadInfo s_thread_info[MAX_THREAD_INFO];

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

struct CTraceStruct *
gt_thread_info_pop (struct ThreadInfo *info, HWord last_addr)
{
  struct CTraceStruct *target;
  if (info->stack_end_ == 0)
    return NULL;
  if (info->stack_end_-- >= s_max_stack)
    return NULL;

  target = &info->stack_[info->stack_end_];

  target->end_time_ = gt_get_times_from_clock (info);
  return target;
}

void
gt_thread_info_push (struct ThreadInfo *info, HWord addr)
{
  struct CTraceStruct *target;
  int index;
  if (++info->stack_end_ > s_max_stack)
    return;
  index = info->stack_end_ - 1;
  target = &info->stack_[index];
  target->last_ = addr;
  target->start_time_ = gt_get_times_from_clock (info);
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

void
gt_flush_thread_info (void (*worker)(struct CTraceStruct *c,
                                     struct ThreadInfo *tinfo))
{
  int i;

  for (i = 0; i < MAX_THREAD_INFO; ++i)
    {
      struct ThreadInfo *info = &s_thread_info[i];
      if (info->tid_ == 0)
        break;
      if (info->stack_end_ > 0)
        {
          int64_t end_time;

          end_time = gt_get_times_from_clock (info);
          if (info->stack_end_ > s_max_stack)
            info->stack_end_ = s_max_stack;
          while (info->stack_end_ > 0)
            {
              struct CTraceStruct *c = &info->stack_[--info->stack_end_];
              c->end_time_ = end_time;
              end_time += 10;
              worker (c, info);
            }
        }
    }
}
