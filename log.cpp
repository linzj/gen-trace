#include "log.h"
#include <stdarg.h>
#include <stdio.h>
#include <sys/syscall.h>
#ifdef __ANDROID__
#include <android/log.h>
#endif

#ifndef LOG_TO_FILE

void
logi (const char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  int bytes = vsnprintf (NULL, 0, fmt, va);
  va_end (va);
  char buf[bytes + 1];
  va_start (va, fmt);
  vsnprintf (buf, bytes + 1, fmt, va);
  va_end (va);
#ifndef __ANDROID__
  fputs (buf, stdout);
#else
  __android_log_write (ANDROID_LOG_INFO, "LINZJ", buf);
#endif
}

void
loge (const char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  int bytes = vsnprintf (NULL, 0, fmt, va);
  va_end (va);
  char buf[bytes + 1];
  va_start (va, fmt);
  vsnprintf (buf, bytes + 1, fmt, va);
  va_end (va);
#ifndef __ANDROID__
  fputs (buf, stdout);
#else
  __android_log_write (ANDROID_LOG_ERROR, "LINZJ", buf);
#endif
}
#else
static volatile int spin_lock;
static void
lock ()
{
  while (true)
    {
      if (__sync_bool_compare_and_swap (&spin_lock, 0, 1))
        {
          break;
        }
    }
}
static void
unlock ()
{
  spin_lock = 0;
}

static FILE *g_file = fopen ("/sdcard/log.txt", "w");
void
logi (const char *fmt, ...)
{
  if (!g_file)
    {
      return;
    }
  lock ();
  {
    fprintf (g_file, "%d: ", syscall (__NR_gettid));
  }
  va_list va;
  va_start (va, fmt);
  int bytes = vsnprintf (NULL, 0, fmt, va);
  va_end (va);
  char buf[bytes + 1];
  va_start (va, fmt);
  vsnprintf (buf, bytes + 1, fmt, va);
  va_end (va);
  fputs (buf, g_file);
  if (buf[bytes - 1] != '\n')
    {
      fputs ("\n", g_file);
    }
  fflush (g_file);
  unlock ();
}

void
loge (const char *fmt, ...)
{
  if (!g_file)
    {
      return;
    }
  lock ();
  {
    fprintf (g_file, "%d: ", syscall (__NR_gettid));
  }
  va_list va;
  va_start (va, fmt);
  int bytes = vsnprintf (NULL, 0, fmt, va);
  va_end (va);
  char buf[bytes + 1];
  va_start (va, fmt);
  vsnprintf (buf, bytes + 1, fmt, va);
  va_end (va);
  fputs (buf, g_file);
  if (buf[bytes - 1] != '\n')
    {
      fputs ("\n", g_file);
    }
  fflush (g_file);
  unlock ();
}
#endif // LOG_TO_FILE
