#include "log.h"
#include <stdarg.h>
#include <stdio.h>
#ifdef __ANDROID__
#include <android/log.h>
#endif

void
logi (const char *fmt, ...)
{
  char buf[512];
  va_list va;
  va_start (va, fmt);
  int bytes = vsnprintf (buf, 511, fmt, va);
  va_end (va);
  buf[bytes] = '\0';
#ifndef __ANDROID__
  fputs (buf, stdout);
#else
  __android_log_write (ANDROID_LOG_INFO, "LINZJ", buf);
#endif
}

void
loge (const char *fmt, ...)
{
  char buf[512];
  va_list va;
  va_start (va, fmt);
  int bytes = vsnprintf (buf, 511, fmt, va);
  va_end (va);
  buf[bytes] = '\0';
#ifndef __ANDROID__
  fputs (buf, stdout);
#else
  __android_log_write (ANDROID_LOG_ERROR, "LINZJ", buf);
#endif
}
