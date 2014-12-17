#define __STDC_FORMAT_MACROS
// C Headers
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
// POSIX Headers
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/syscall.h>
// C++ Headers
#include <new>

#ifndef CTRACE_FILE_NAME
#define CTRACE_FILE_NAME "trace_%d.json"
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
  uint64_t name_;
  CTraceStruct (void *, int64_t current_time);
  CTraceStruct () {}
};

struct ThreadInfo
{
  static const int max_stack = 1000;
  int pid_;
  int tid_;
  int64_t virtual_time_;
  CTraceStruct stack_[max_stack];
  int stack_end_;
  ThreadInfo ();
  int64_t UpdateVirtualTime (bool fromStart);
  static ThreadInfo *New ();
  static ThreadInfo *Find ();
  void NewBack (void *, int64_t current_time);
  CTraceStruct *PoppedBack ();
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
          return ++virtual_time_;
        }
    }
  else
    {
      virtual_time_ = tmp;
    }
  return virtual_time_;
}

void
ThreadInfo::NewBack (void *name, int64_t current_time)
{
  assert (stack_end_ < max_stack);
  CTraceStruct *cs = &stack_[stack_end_];
  new (cs) CTraceStruct (name, current_time);
}

CTraceStruct *
ThreadInfo::PoppedBack ()
{
  return &stack_[stack_end_];
}

CTraceStruct::CTraceStruct (void *name, int64_t current_time)
{
  start_time_ = current_time;
  end_time_ = invalid_time;
  name_ = reinterpret_cast<uint64_t> (name);
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

  class MapLineData
  {
  public:
    MapLineData (char *str);

    intptr_t getBase ();
    intptr_t getEnd ();

  private:
    intptr_t m_base;
    intptr_t m_end;
  };

  static void StartFile (FILE *f);

  Initializer ()
  {
    pthread_key_create (&thread_info_key, DeleteThreadInfo);
    InitFreeList ();

    char buffer[256];
    sprintf (buffer, CTRACE_FILE_NAME, getpid ());
    file_to_write = fopen (buffer, "wb");
    StartFile (file_to_write);
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

Initializer::MapLineData::MapLineData (char *str) : m_base (-1), m_end (-1)
{
  int len = strlen (str);
  // strip the '\n'
  str[len - 1] = '\0';

  char *address_sep = strchr (str, '-');
  if (!address_sep)
    {
      return;
    }
  address_sep[0] = '\0';
  errno = 0;
  m_base = strtoll (str, NULL, 16);
  if (errno)
    {
      m_base = -1;
      return;
    }
  str = address_sep + 1;
  char *space = strchr (str, ' ');
  if (!space)
    {
      return;
    }
  space[0] = '\0';
  errno = 0;
  m_end = strtoll (str, NULL, 16);
  if (errno)
    {
      m_end = -1;
      return;
    }
}

intptr_t
Initializer::MapLineData::getBase ()
{
  return m_base;
}

intptr_t
Initializer::MapLineData::getEnd ()
{
  return m_end;
}

struct Record
{
  int pid_;
  int tid_;
  int64_t start_time_;
  int64_t dur_;
  uint64_t name_;
  struct Record *next_;
};

void
Initializer::StartFile (FILE *f)
{
  char sz[1024] = "/proc/self/maps";
  FILE *fp = fopen (sz, "r");
  if (!fp)
    {
      return;
    }
  intptr_t return_address
      = reinterpret_cast<intptr_t> (__builtin_return_address (0));
  while (fgets (sz, 1024, fp))
    {
      MapLineData data (sz);
      if (data.getBase () == -1)
        break;
      if (data.getBase () <= return_address && data.getEnd () > return_address)
        {
          Record r = { 0, 0, 0, 0, static_cast<uint64_t> (data.getBase ()) };
          fwrite (&r, sizeof (r) - sizeof (void *), 1, f);
          fflush (f);
          fclose (fp);
          return;
        }
    }
  __builtin_unreachable ();
}

Initializer __init__;

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

  fwrite (current, sizeof (*current) - sizeof (void *), 1, file_to_write);
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
void __cyg_profile_func_enter (void *this_fn, void *call_site);
void __cyg_profile_func_exit (void *this_fn, void *call_site);
}

void
__cyg_profile_func_enter (void *this_fn, void *call_site)
{
  if (file_to_write == 0)
    return;
  ThreadInfo *tinfo = GetThreadInfo ();
  int64_t current_time = tinfo->UpdateVirtualTime (true);

  if (tinfo->stack_end_ < ThreadInfo::max_stack)
    {
      tinfo->NewBack (this_fn, current_time);
    }
  tinfo->stack_end_++;
}

void
__cyg_profile_func_exit (void *this_fn, void *call_site)
{
  if (file_to_write == 0)
    return;
  ThreadInfo *tinfo = GetThreadInfo ();
  tinfo->stack_end_--;
  int64_t current_time = tinfo->UpdateVirtualTime (false);
  if (tinfo->stack_end_ < ThreadInfo::max_stack)
    {
      CTraceStruct *c = tinfo->PoppedBack ();
      if (c->start_time_ != invalid_time)
        {
          // we should record this
          c->end_time_ = current_time;
          if (c->end_time_ - c->start_time_ >= min_interval)
            RecordThis (c, tinfo);
        }
    }
}
