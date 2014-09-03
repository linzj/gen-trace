#ifndef CTRACE_H
#define CTRACE_H
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <syscall.h>
#include <stdio.h>

class CTrace
{
public:
  CTrace (const char *cat, const char *name);
  ~CTrace ();

  void CommonInit ();

  const char *cat_;
  const char *name_;
  int pid_;
  int tid_;
  uint64_t clock_;
  uint64_t clock_real_;
  static const int64_t kMillisecondsPerSecond = 1000;
  static const int64_t kMicrosecondsPerMillisecond = 1000;
  static const int64_t kMicrosecondsPerSecond = kMicrosecondsPerMillisecond
                                                * kMillisecondsPerSecond;
  static const int64_t kMicrosecondsPerMinute = kMicrosecondsPerSecond * 60;
  static const int64_t kMicrosecondsPerHour = kMicrosecondsPerMinute * 60;
  static const int64_t kMicrosecondsPerDay = kMicrosecondsPerHour * 24;
  static const int64_t kMicrosecondsPerWeek = kMicrosecondsPerDay * 7;
  static const int64_t kNanosecondsPerMicrosecond = 1000;
  static const int64_t kNanosecondsPerSecond = kNanosecondsPerMicrosecond
                                               * kMicrosecondsPerSecond;

private:
  static void Submit (const CTrace *);
  static uint64_t &GetCurrentTime ();
};

#define C_TRACE_0(cat, name) CTrace __trace__ (cat, name)

inline CTrace::CTrace (const char *cat, const char *name)
{
  cat_ = cat;
  name_ = name;
  CommonInit ();
}

inline CTrace::~CTrace () { Submit (this); }

inline void
CTrace::CommonInit ()
{
  pid_ = getpid ();
  tid_ = syscall (__NR_gettid, 0);

  struct timespec ts;
  if (clock_gettime (CLOCK_MONOTONIC, &ts) != 0)
    {
      clock_ = 0;
    }
  else
    {
      clock_ = (static_cast<uint64_t> (ts.tv_sec)
                * CTrace::kMicrosecondsPerSecond)
               + (static_cast<uint64_t> (ts.tv_nsec)
                  / CTrace::kNanosecondsPerMicrosecond);
      clock_real_ = clock_;
    }
  uint64_t &current = GetCurrentTime ();

  if (this->clock_ <= current)
    this->clock_ = current + 1;
  current = this->clock_;
}

inline uint64_t &
CTrace::GetCurrentTime ()
{
  static uint64_t current = 0;
  return current;
}

inline void
CTrace::Submit (const CTrace *This)
{
  static FILE *f;
  static bool isInit = false;
  struct FileSink
  {
    FileSink () : f_ (NULL) {}
    ~FileSink ()
    {
      if (f_)
        {
          fprintf (f_, "]}");
          fclose (f_);
        }
    }
    FILE *f_;
  };
  static FileSink fsink;
  static bool needComma = false;
  uint64_t dur, now;
  uint64_t &current = GetCurrentTime ();

  if (!isInit)
    {
      f = fopen ("trace.json", "w");
      if (!f)
        return;
      fprintf (f, "{\"traceEvents\": [");
      fsink.f_ = f;
      isInit = true;
    }
  timespec ts;
  if (clock_gettime (CLOCK_MONOTONIC, &ts) != 0)
    {
      now = 0;
    }
  else
    {
      now = (static_cast<uint64_t> (ts.tv_sec)
             * CTrace::kMicrosecondsPerSecond)
            + (static_cast<uint64_t> (ts.tv_nsec)
               / CTrace::kNanosecondsPerMicrosecond);
    }

  if (now <= This->clock_real_)
    dur = 1;
  else
    dur = now - This->clock_real_;

  if (dur + This->clock_ < current)
    {
      dur = current - This->clock_;
    }

  if (!needComma)
    {
      needComma = true;
    }
  else
    {
      fprintf (f, ", ");
    }
  fprintf (f, "{\"cat\":\"%s\", \"pid\":%d, \"tid\":%d, \"ts\":%lu, "
              "\"ph\":\"X\", \"name\":\"%s\", \"dur\": %lu}",
           This->cat_, This->pid_, This->tid_, This->clock_, This->name_, dur);
  current = This->clock_ + dur;
}

#endif /* CTRACE_H */
