#include <sys/syscall.h>

#include "gt_threadinfo.h"
#include "gt_time.h"

// Timing facility.
static int64_t
gt_get_times_from_clock_ (int clockid)
{
  struct timespec ts_thread;
  int64_t ret;
  static const int64_t kMillisecondsPerSecond = 1000;
  static const int64_t kMicrosecondsPerMillisecond = 1000;
  static const int64_t kMicrosecondsPerSecond = kMicrosecondsPerMillisecond
                                                * kMillisecondsPerSecond;
  static const int64_t kNanosecondsPerMicrosecond = 1000;

  extern SysRes VG_ (do_syscall)(UWord sysno, UWord, UWord, UWord, UWord,
                                 UWord, UWord);
  VG_ (do_syscall)(__NR_clock_gettime, clockid, (UWord)&ts_thread, 0, 0, 0, 0);
  ret = ((int64_t)(ts_thread.tv_sec) * kMicrosecondsPerSecond)
        + ((int64_t)(ts_thread.tv_nsec) / kNanosecondsPerMicrosecond);
  if (s_last_time >= ret)
    return (s_last_time += 1);
  s_last_time = ret;
  return ret;
}

static int64_t
gt_get_times_from_clock (struct ThreadInfo *tinfo)
{
  if (s_use_estimated_time)
    {
      int64_t ret = tinfo->estimated_thread_ns_ / 1000;
      tinfo->estimated_thread_ns_ += 1000;
      return ret;
    }
  else
    {
      return gt_get_times_from_clock_ (CLOCK_MONOTONIC);
    }
}
