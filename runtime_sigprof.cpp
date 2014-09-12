#define __STDC_FORMAT_MACROS
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <signal.h>
#include <sys/time.h>
#include <sys/syscall.h>

#include <new>

#ifndef CTRACE_FILE_NAME
#define CTRACE_FILE_NAME "/sdcard/trace.json"
#endif // CTRACE_FILE_NAME
#define CRASH()                                                               \
  do                                                                          \
    {                                                                         \
      (*(int *)0xeadbaddc = 0);                                               \
    }                                                                         \
  while (0)

namespace
{
pthread_key_t thread_info_key;
FILE *file_to_write;
static const uint64_t invalid_time = static_cast<uint64_t> (-1);
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
static const int frequency = 50;
static const int ticks = 1000;

struct ucontext
{
  unsigned long uc_flags;
  struct ucontext *uc_link;
  stack_t uc_stack;
  struct sigcontext uc_mcontext;
  sigset_t uc_sigmask; /* mask last for extensibility */
};

struct CTraceStruct
{
  uint64_t start_time_;
  uint64_t min_end_time_;
  const char *name_;
  CTraceStruct (const char *);
};

struct ThreadInfo
{
  static const int MAX_STACK = ticks;
  int pid_;
  int tid_;
  CTraceStruct *stack_[MAX_STACK];
  int stack_end_;
  uint64_t current_time_;
  ThreadInfo ();
  static ThreadInfo *New ();
  static ThreadInfo *Find ();
  static ThreadInfo *Find (const int);
};
static const int MAX_THREADS = 100;
char info_store_char[MAX_THREADS * sizeof (ThreadInfo)];

ThreadInfo *
ThreadInfo::Find (const int tid)
{
  ThreadInfo *info_store = reinterpret_cast<ThreadInfo *> (info_store_char);
  int hash_index = tid % MAX_THREADS;
  for (int i = 0; i < MAX_THREADS; ++i)
    {
      if (info_store[hash_index].tid_ == tid)
        {
          return &info_store[hash_index];
        }
      hash_index++;
      if (hash_index >= MAX_THREADS)
        hash_index = 0;
    }
  return NULL;
}

ThreadInfo *
ThreadInfo::Find ()
{
  const int tid = syscall (__NR_gettid, 0);
  return ThreadInfo::Find (tid);
}

ThreadInfo *
ThreadInfo::New ()
{
  ThreadInfo *free_thread_info = NULL;
  ThreadInfo *info_store = reinterpret_cast<ThreadInfo *> (info_store_char);
  int hash_index = syscall (__NR_gettid, 0) % MAX_THREADS;
  for (int i = 0; i < MAX_THREADS; ++i)
    {
      if (info_store[hash_index].tid_ == 0)
        {
          if (!__sync_bool_compare_and_swap (&info_store[hash_index].pid_, 0,
                                             -1))
            {
              goto __continue;
            }
          free_thread_info = &info_store[hash_index];
          break;
        }
    __continue:
      hash_index++;
      if (hash_index >= MAX_THREADS)
        hash_index = 0;
    }
  if (free_thread_info == NULL)
    CRASH ();
  pthread_setspecific (thread_info_key, free_thread_info);
  return new (free_thread_info) ThreadInfo ();
}

ThreadInfo::ThreadInfo ()
{
  static const int64_t kMillisecondsPerSecond = 1000;
  static const int64_t kMicrosecondsPerMillisecond = 1000;
  static const int64_t kMicrosecondsPerSecond = kMicrosecondsPerMillisecond
                                                * kMillisecondsPerSecond;
  static const int64_t kNanosecondsPerMicrosecond = 1000;

  pid_ = getpid ();
  tid_ = syscall (__NR_gettid, 0);
  stack_end_ = 0;
  struct timespec ts_thread;
  clock_gettime (CLOCK_MONOTONIC, &ts_thread);
  current_time_
      = (static_cast<uint64_t> (ts_thread.tv_sec) * kMicrosecondsPerSecond)
        + (static_cast<uint64_t> (ts_thread.tv_nsec)
           / kNanosecondsPerMicrosecond);
  sigset_t unblock_set;
  sigemptyset (&unblock_set);
  sigaddset (&unblock_set, SIGPROF);
  sigprocmask (SIG_UNBLOCK, &unblock_set, 0);
}

CTraceStruct::CTraceStruct (const char *name)
{
  start_time_ = invalid_time;
  min_end_time_ = invalid_time;
  name_ = name;
}

ThreadInfo *
get_thread_info ()
{
  ThreadInfo *tinfo = ThreadInfo::Find ();
  if (tinfo)
    return tinfo;
  tinfo = ThreadInfo::New ();
  return tinfo;
}

void
delete_thread_info (void *tinfo)
{
  static_cast<ThreadInfo *> (tinfo)->tid_ = 0;
}

void
myhandler (int, siginfo_t *, void *context)
{
  int tid = syscall (__NR_gettid, 0);
  // we don't use get_thread_info, because
  // it make no sense to deal
  // with the thread without this structure
  // created in __start_ctrace__.
  ThreadInfo *tinfo = ThreadInfo::Find (tid);
  if (!tinfo)
    {
      // block this signal if it does not belong to
      // the profiling threads.
      sigaddset (&static_cast<ucontext *> (context)->uc_sigmask, SIGPROF);
      return;
    }
  uint64_t old_time = tinfo->current_time_;
  uint64_t &current_time_thread = tinfo->current_time_;
  current_time_thread += ticks * frequency;

  if (tinfo->stack_end_ >= ThreadInfo::MAX_STACK)
    {
      CRASH ();
    }
  for (int i = 0; i < tinfo->stack_end_; ++i)
    {
      CTraceStruct *cur = tinfo->stack_[i];
      if (cur->start_time_ != invalid_time)
        continue;
      cur->start_time_ = old_time;
      old_time += frequency;
    }
  if (tinfo->stack_end_ != 0)
    {
      tinfo->stack_[tinfo->stack_end_ - 1]->min_end_time_ = current_time_thread
                                                            + frequency;
    }
}

struct Lock
{
  Lock (pthread_mutex_t *mutex) : mutex_ (mutex)
  {
    pthread_mutex_lock (mutex_);
  }
  ~Lock () { pthread_mutex_unlock (mutex_); }
  pthread_mutex_t *mutex_;
};

struct Initializer
{
  Initializer ()
  {
    pthread_key_create (&thread_info_key, delete_thread_info);
    struct sigaction myaction = { 0 };
    struct itimerval timer;
    myaction.sa_sigaction = myhandler;
    myaction.sa_flags = SA_SIGINFO;
    sigaction (SIGPROF, &myaction, NULL);

    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = frequency;
    timer.it_interval = timer.it_value;
    setitimer (ITIMER_PROF, &timer, NULL);
    file_to_write = fopen (CTRACE_FILE_NAME, "w");
    fprintf (file_to_write, "{\"traceEvents\": [");
  }
  ~Initializer () { fclose (file_to_write); }
};

Initializer __init__;

void
record_this (CTraceStruct *c, ThreadInfo *tinfo)
{
  Lock __lock__ (&file_mutex);
  static bool needComma = false;
  if (!needComma)
    {
      needComma = true;
    }
  else
    {
      fprintf (file_to_write, ", ");
    }

  fprintf (file_to_write,
           "{\"cat\":\"%s\", \"pid\":%d, \"tid\":%d, \"ts\":%" PRIu64 ", "
           "\"ph\":\"X\", \"name\":\"%s\", \"dur\": %" PRIu64 "}",
           "profile", tinfo->pid_, tinfo->tid_, c->start_time_, c->name_,
           c->min_end_time_ - c->start_time_);
  static int flushCount = 0;
  if (flushCount++ == 5)
    {
      fflush (file_to_write);
      flushCount = 0;
    }
}
}

extern "C" {
extern void __start_ctrace__ (void *c, const char *name);
extern void __end_ctrace__ (CTraceStruct *c, const char *name);
}

void
__start_ctrace__ (void *c, const char *name)
{
  if (file_to_write == 0)
    return;
  CTraceStruct *cs = new (c) CTraceStruct (name);
  ThreadInfo *tinfo = get_thread_info ();
  if (tinfo->stack_end_ < ThreadInfo::MAX_STACK)
    {
      tinfo->stack_[tinfo->stack_end_] = cs;
    }
  tinfo->stack_end_++;
}

void
__end_ctrace__ (CTraceStruct *c, const char *name)
{
  if (file_to_write == 0)
    return;
  ThreadInfo *tinfo = get_thread_info ();
  tinfo->stack_end_--;
  if (tinfo->stack_end_ < ThreadInfo::MAX_STACK)
    {
      if (c->start_time_ != invalid_time)
        {
          // we should record this
          record_this (c, tinfo);
          if (tinfo->stack_end_ != 0)
            {
              // propagate the back's mini end time
              tinfo->stack_[tinfo->stack_end_ - 1]->min_end_time_
                  = c->min_end_time_ + frequency;
            }
        }
    }
}
