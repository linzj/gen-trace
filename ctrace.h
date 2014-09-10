#ifndef CTRACE_H
#define CTRACE_H
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <syscall.h>
#include <stdio.h>

#ifndef CTRACE_FILE_NAME
#define CTRACE_FILE_NAME "trace.json"
#endif // CTRACE_FILE_NAME
#ifdef CTRACE_THREAD_SUPPORTED
#include <pthread.h>
#define SUBMIT_LOCK_VAR CTrace::Lock __my_submit_lock__ (GetSubmitLock ())
#else
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
  struct timespec clock_;
  struct timespec clock_thread_;

private:
  static void Submit (const CTrace *);
#ifdef CTRACE_THREAD_SUPPORTED
  struct Lock
  {
    Lock (pthread_mutex_t *mutex) : mutex_ (mutex)
    {
      pthread_mutex_lock (mutex_);
    }
    ~Lock () { pthread_mutex_unlock (mutex_); }
    pthread_mutex_t *mutex_;
  };
  static pthread_mutex_t *GetSubmitLock ();
#endif // CTRACE_THREAD_SUPPORTED
  static uint64_t timespec2uint64_t (const struct timespec *);
};

#define C_TRACE_0(cat, name) CTrace __trace__ (cat, name)

#ifdef CTRACE_THREAD_SUPPORTED

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

  clock_gettime (CLOCK_MONOTONIC, &clock_);
  clock_gettime (CLOCK_THREAD_CPUTIME_ID, &clock_thread_);
}

inline uint64_t
CTrace::timespec2uint64_t (const struct timespec *spec)
{
  return spec->tv_sec * 1000000000LL + spec->tv_nsec;
}

inline void
CTrace::Submit (const CTrace *This)
{
  uint64_t dur, tdur;

  timespec now;
  clock_gettime (CLOCK_MONOTONIC, &now);
  dur = (now.tv_sec - This->clock_.tv_sec) * 1000000000LL
        + (now.tv_nsec - This->clock_.tv_nsec);
  if (dur < CTRACE_OMIT_JITTER)
    return;

  timespec now_thread;
  clock_gettime (CLOCK_THREAD_CPUTIME_ID, &now_thread);
  tdur = (now_thread.tv_sec - This->clock_thread_.tv_sec) * 1000000000LL
         + (now_thread.tv_nsec - This->clock_thread_.tv_nsec);

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
    fprintf (f, "{\"cat\":\"%s\", \"pid\":%d, \"tid\":%d, \"ts\":%lu, "
                "\"ph\":\"X\", \"name\":\"%s\", \"dur\":%lu, \"tts\":%lu, "
                "\"tdur\":%lu}",
             This->cat_, This->pid_, This->tid_,
             timespec2uint64_t (&This->clock_), This->name_, dur,
             timespec2uint64_t (&This->clock_thread_), tdur);
  }
}

#endif /* CTRACE_H */
