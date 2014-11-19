#define __STDC_FORMAT_MACROS
// C Headers
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
// POSIX Headers
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/syscall.h>
// C++ Headers
#include <new>

#ifndef CTRACE_FILE_NAME
#define CTRACE_FILE_NAME "/sdcard/trace_%d.json"
#endif // CTRACE_FILE_NAME
#define CRASH()                                                               \
  do                                                                          \
    {                                                                         \
      (*(int *)0xeadbaddc = 0);                                               \
    }                                                                         \
  while (0)

#ifdef CTRACE_ENABLE_STAT
int stat_find_miss = 0;
#endif // CTRACE_ENABLE_STAT
namespace
{
pthread_key_t thread_info_key;
FILE *file_to_write;
static const int64_t invalid_time = static_cast<int64_t> (-1);
// frequency in microsec.
static const int frequency = 100;
static const int ticks = 1;
// time facilities, in microsec.
static const int64_t min_interval = 1 * frequency;
static volatile int64_t s_time = 0;

// for WriterThread
pthread_mutex_t writer_waitup_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile bool writer_waitup = false;
pthread_cond_t writer_waitup_cond = PTHREAD_COND_INITIALIZER;
struct Record;
struct Record *pending_records_head;

struct CTraceStruct
{
  int64_t start_time_;
  int64_t end_time_;
  const char *name_;
  CTraceStruct (const char *, int64_t start_time);
};

struct ThreadInfo
{
  static const int max_stack = 1000;
  int pid_;
  int tid_;
  int64_t virtual_time_;
  CTraceStruct *stack_[max_stack];
  int stack_end_;
  ThreadInfo ();
  int64_t UpdateVirtualTime (bool fromStart);
  static ThreadInfo *New ();
  static ThreadInfo *Find ();
};

static const int MAX_THREADS = 100;
char info_store_char[MAX_THREADS * sizeof (ThreadInfo)];

struct FreeListNode
{
  const struct FreeListNode *next_;
};

FreeListNode *free_head;

ThreadInfo *
ThreadInfo::Find ()
{
  return static_cast<ThreadInfo *> (pthread_getspecific (thread_info_key));
}

ThreadInfo *
ThreadInfo::New ()
{
  ThreadInfo *free_thread_info;
  while (true)
    {
      FreeListNode *current_free = free_head;
      if (current_free == NULL)
        CRASH ();
      if (!__sync_bool_compare_and_swap (&free_head, current_free,
                                         current_free->next_))
        continue;
      free_thread_info = reinterpret_cast<ThreadInfo *> (current_free);
      break;
    }
  if (free_thread_info == NULL)
    CRASH ();
  pthread_setspecific (thread_info_key, free_thread_info);
  return new (free_thread_info) ThreadInfo ();
}

ThreadInfo::ThreadInfo ()
{
  pid_ = getpid ();
  tid_ = syscall (__NR_gettid, 0);
  stack_end_ = 0;
  virtual_time_ = 0;
}

int64_t
ThreadInfo::UpdateVirtualTime (bool fromStart)
{
  int64_t tmp = s_time;
  if (virtual_time_ >= tmp)
    {
      if (fromStart)
        {
          if (virtual_time_ >= tmp + frequency)
            return invalid_time;
          // return the original value.
          return virtual_time_++;
        }
    }
  else
    {
      virtual_time_ = tmp;
    }
  return virtual_time_;
}

CTraceStruct::CTraceStruct (const char *name, int64_t start_time)
{
  name_ = name;
  start_time_ = start_time;
}

ThreadInfo *
_GetThreadInfo ()
{
  ThreadInfo *tinfo = ThreadInfo::Find ();
  if (tinfo)
    return tinfo;
  tinfo = ThreadInfo::New ();
  return tinfo;
}

ThreadInfo *
GetThreadInfo ()
{
  ThreadInfo *tinfo = _GetThreadInfo ();
  return tinfo;
}

void
DeleteThreadInfo (void *tinfo)
{
  FreeListNode *free_node = static_cast<FreeListNode *> (tinfo);
  while (true)
    {
      FreeListNode *current_free = free_head;
      free_node->next_ = current_free;
      if (__sync_bool_compare_and_swap (&free_head, current_free, free_node))
        break;
    }
}

void *WriterThread (void *);

static void timer_func (union sigval) { s_time += frequency; }

struct Initializer
{
  void
  InitFreeList ()
  {
    ThreadInfo *info_store = reinterpret_cast<ThreadInfo *> (info_store_char);
    free_head
        = reinterpret_cast<FreeListNode *> (&info_store[MAX_THREADS - 1]);
    free_head->next_ = NULL;
    for (int i = MAX_THREADS - 2; i >= 0; --i)
      {
        FreeListNode *current
            = reinterpret_cast<FreeListNode *> (&info_store[i]);
        current->next_ = free_head;
        free_head = current;
      }
  }

  Initializer ()
  {
    pthread_key_create (&thread_info_key, DeleteThreadInfo);
    InitFreeList ();

    char buffer[256];
    sprintf (buffer, CTRACE_FILE_NAME, getpid ());
    file_to_write = fopen (buffer, "w");
    fprintf (file_to_write, "{\"traceEvents\": [");
    pthread_t my_writer_thread;
    pthread_create (&my_writer_thread, NULL, WriterThread, NULL);
    // time initialize, the thread_timer is used to update s_time in a pthread.
    timer_t thread_timer;

    struct sigevent sev = { 0 };
    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_notify_function = timer_func;
    if (0 != timer_create (CLOCK_MONOTONIC, &sev, &thread_timer))
      {
        CRASH ();
      }
    struct itimerspec timerspec;
    timerspec.it_value.tv_sec = 0;
    timerspec.it_value.tv_nsec = frequency * 1000;
    timerspec.it_interval = timerspec.it_value;

    if (0 != timer_settime (thread_timer, 0, &timerspec, NULL))
      {
        CRASH ();
      }
  }

  ~Initializer () { fclose (file_to_write); }
};

Initializer __init__;

struct Record
{
  int pid_;
  int tid_;
  int64_t start_time_;
  int64_t dur_;
  const char *name_;
  struct Record *next_;
};

struct Lock
{
  Lock (pthread_mutex_t *mutex) : mutex_ (mutex)
  {
    pthread_mutex_lock (mutex_);
  }
  ~Lock () { pthread_mutex_unlock (mutex_); }
  pthread_mutex_t *mutex_;
};

void
RecordThis (CTraceStruct *c, ThreadInfo *tinfo)
{
  Record *r = static_cast<Record *> (malloc (sizeof (Record)));
  if (!r)
    CRASH ();
  r->pid_ = tinfo->pid_;
  r->tid_ = tinfo->tid_;
  r->start_time_ = c->start_time_;
  r->name_ = c->name_;
  r->dur_ = c->end_time_ - c->start_time_;
  while (true)
    {
      Record *current_head = pending_records_head;
      r->next_ = current_head;
      if (__sync_bool_compare_and_swap (&pending_records_head, current_head,
                                        r))
        break;
    }
  {
    Lock lock (&writer_waitup_mutex);
    writer_waitup = true;
    pthread_cond_signal (&writer_waitup_cond);
  }
}

void
DoWriteRecursive (struct Record *current)
{
  if (current->next_)
    DoWriteRecursive (current->next_);

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
           "profile", current->pid_, current->tid_, current->start_time_,
           current->name_, current->dur_);
  static int flushCount = 0;
  if (flushCount++ == 5)
    {
      fflush (file_to_write);
      flushCount = 0;
    }
  free (current);
}

void *
WriterThread (void *)
{
  pthread_setname_np (pthread_self (), "WriterThread");

  while (true)
    {
      Record *record_to_write;

      {
        Lock lock (&writer_waitup_mutex);
        if (writer_waitup == false)
          pthread_cond_wait (&writer_waitup_cond, &writer_waitup_mutex);
        assert (writer_waitup == true);
        writer_waitup = false;
      }
      while (pending_records_head)
        {
          while (true)
            {
              record_to_write = pending_records_head;
              if (record_to_write == NULL)
                break;
              if (__sync_bool_compare_and_swap (&pending_records_head,
                                                record_to_write, NULL))
                break;
            }
          if (record_to_write == NULL)
            break;
          DoWriteRecursive (record_to_write);
        }
    }
  return NULL;
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
  ThreadInfo *tinfo = GetThreadInfo ();
  int64_t currentTime = tinfo->UpdateVirtualTime (true);

  if (tinfo->stack_end_ < ThreadInfo::max_stack)
    {
      CTraceStruct *cs = new (c) CTraceStruct (name, currentTime);
      tinfo->stack_[tinfo->stack_end_] = cs;
    }
  tinfo->stack_end_++;
}

void
__end_ctrace__ (CTraceStruct *c, const char *name)
{
  if (file_to_write == 0)
    return;
  ThreadInfo *tinfo = GetThreadInfo ();
  tinfo->stack_end_--;
  int64_t currentTime = tinfo->UpdateVirtualTime (false);
  if (tinfo->stack_end_ < ThreadInfo::max_stack)
    {
      if (c->start_time_ != invalid_time)
        {
          // we should record this
          c->end_time_ = currentTime;
          if (c->end_time_ - c->start_time_ >= min_interval)
            RecordThis (c, tinfo);
        }
    }
}
