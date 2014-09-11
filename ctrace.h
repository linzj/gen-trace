#ifndef CTRACE_H
#define CTRACE_H
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>

#ifndef CTRACE_FILE_NAME
#define CTRACE_FILE_NAME "trace.json"
#endif // CTRACE_FILE_NAME
#ifdef CTRACE_THREAD_SUPPORTED
#include <pthread.h>
#define CURRENT_TIME_LOCK_VAR CTrace::Lock __my_lock__ (GetCurrentTimeLock ())
#define SUBMIT_LOCK_VAR CTrace::Lock __my_submit_lock__ (GetSubmitLock ())
#else
#define CURRENT_TIME_LOCK_VAR
#define SUBMIT_LOCK_VAR
#endif // CTRACE_THREAD_SUPPORTED

#ifndef CTRACE_OMIT_JITTER
#define CTRACE_OMIT_JITTER 0UL
#endif // CTRACE_OMIT_JITTER

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
#ifdef CTRACE_THREAD_SUPPORTED
  uint64_t clock_thread_;
  uint64_t clock_thread_real_;
#endif
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
#ifdef CTRACE_THREAD_SUPPORTED
  static uint64_t GetCurrentThreadTime ();
  static void SetCurrentThreadTime (uint64_t);
  static pthread_key_t GetThreadTimeKey ();
  struct Lock
  {
    Lock (pthread_mutex_t *mutex) : mutex_ (mutex)
    {
      pthread_mutex_lock (mutex_);
    }
    ~Lock () { pthread_mutex_unlock (mutex_); }
    pthread_mutex_t *mutex_;
  };
  static pthread_mutex_t *GetCurrentTimeLock ();
  static pthread_mutex_t *GetSubmitLock ();
#endif // CTRACE_THREAD_SUPPORTED
};

#define C_TRACE_0(cat, name) CTrace __trace__ (cat, name)

#ifdef CTRACE_THREAD_SUPPORTED

inline uint64_t
CTrace::GetCurrentThreadTime ()
{
  pthread_key_t key = GetThreadTimeKey ();
#ifdef __LP64__
  return reinterpret_cast<uint64_t> (pthread_getspecific (key));
#else
  uint64_t *pdata = static_cast<uint64_t *> (pthread_getspecific (key));
  if (pdata)
    {
      return *pdata;
    }
  else
    {
      return 0;
    }
#endif
}

inline void
CTrace::SetCurrentThreadTime (uint64_t time)
{
  pthread_key_t key = GetThreadTimeKey ();
#ifdef __LP64__
  pthread_setspecific (key, reinterpret_cast<const void *> (time));
#else
  uint64_t *pdata = static_cast<uint64_t *> (pthread_getspecific (key));
  if (pdata)
    {
      *pdata = time;
    }
  else
    {
      pdata = static_cast<uint64_t *> (malloc (sizeof (uint64_t)));
      if (pdata)
        {
          *pdata = time;
          pthread_setspecific (key, pdata);
        }
    }
#endif
}

inline pthread_key_t
CTrace::GetThreadTimeKey ()
{
  static pthread_key_t key;
  static bool inited = false;

  if (!inited)
    {
#ifdef __LP64__
      pthread_key_create (&key, NULL);
#else
      pthread_key_create (&key, free);
#endif
      inited = true;
    }
  return key;
}

inline pthread_mutex_t *
CTrace::GetCurrentTimeLock ()
{
  static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  return &mutex;
}

inline pthread_mutex_t *
CTrace::GetSubmitLock ()
{
  static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  return &mutex;
}
#endif // CTRACE_THREAD_SUPPORTED

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
#ifdef CTRACE_THREAD_SUPPORTED
  struct timespec ts_thread;
  if (clock_gettime (CLOCK_THREAD_CPUTIME_ID, &ts_thread) != 0)
    {
      clock_thread_ = 0;
    }
  else
    {
      clock_thread_ = (static_cast<uint64_t> (ts_thread.tv_sec)
                       * CTrace::kMicrosecondsPerSecond)
                      + (static_cast<uint64_t> (ts_thread.tv_nsec)
                         / CTrace::kNanosecondsPerMicrosecond);
      clock_thread_real_ = clock_thread_;
    }
  {
    uint64_t current_thread = GetCurrentThreadTime ();
    if (this->clock_thread_ <= current_thread)
      this->clock_thread_ = current_thread + 1;
    SetCurrentThreadTime (this->clock_thread_);
  }
#endif // CTRACE_THREAD_SUPPORTED
  {
    CURRENT_TIME_LOCK_VAR;
    uint64_t &current = GetCurrentTime ();

    if (this->clock_ <= current)
      this->clock_ = current + 1;
    current = this->clock_;
  }
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
  uint64_t dur, now;

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

  if (dur < CTRACE_OMIT_JITTER)
    return;

  {
    CURRENT_TIME_LOCK_VAR;
    uint64_t &current = GetCurrentTime ();
    if (dur + This->clock_ < current)
      {
        dur = current - This->clock_;
      }
    current = This->clock_ + dur;
  }

#ifdef CTRACE_THREAD_SUPPORTED
  timespec ts_thread;
  uint64_t now_thread, dur_thread;
  if (clock_gettime (CLOCK_THREAD_CPUTIME_ID, &ts_thread) != 0)
    {
      now_thread = 0;
    }
  else
    {
      now_thread = (static_cast<uint64_t> (ts_thread.tv_sec)
                    * CTrace::kMicrosecondsPerSecond)
                   + (static_cast<uint64_t> (ts_thread.tv_nsec)
                      / CTrace::kNanosecondsPerMicrosecond);
    }
  if (now_thread <= This->clock_thread_real_)
    dur_thread = 1;
  else
    dur_thread = now_thread - This->clock_thread_real_;
  {
    uint64_t current = GetCurrentThreadTime ();
    if (dur_thread + This->clock_thread_ < current)
      {
        dur_thread = current - This->clock_thread_;
      }
    SetCurrentThreadTime (This->clock_thread_ + dur_thread);
  }

#endif // CTRACE_THREAD_SUPPORTED
  {
    SUBMIT_LOCK_VAR;
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

    if (!isInit)
      {
        f = fopen (CTRACE_FILE_NAME, "w");
        if (!f)
          return;
        fprintf (f, "{\"traceEvents\": [");
        fsink.f_ = f;
        isInit = true;
      }

    if (!needComma)
      {
        needComma = true;
      }
    else
      {
        fprintf (f, ", ");
      }
#ifdef CTRACE_THREAD_SUPPORTED
    fprintf (f, "{\"cat\":\"%s\", \"pid\":%d, \"tid\":%d, \"ts\":%" PRIu64
                ", \"ph\":\"X\", \"name\":\"%s\", \"dur\":%" PRIu64
                ", \"tts\":%" PRIu64 ", \"tdur\":%" PRIu64 "}",
             This->cat_, This->pid_, This->tid_, This->clock_, This->name_,
             dur, This->clock_thread_, dur_thread);

#else
    fprintf (f, "{\"cat\":\"%s\", \"pid\":%d, \"tid\":%d, \"ts\":%" PRIu64 ", "
                "\"ph\":\"X\", \"name\":\"%s\", \"dur\": %" PRIu64 "}",
             This->cat_, This->pid_, This->tid_, This->clock_, This->name_,
             dur);
#endif // CTRACE_THREAD_SUPPORTED
    static int flushCount = 0;
    if (flushCount++ == 5)
      {
        fflush (f);
        flushCount = 0;
      }
  }
}

#endif /* CTRACE_H */
