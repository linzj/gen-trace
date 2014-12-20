#include "log.h"
#include <stdarg.h>
#include <stdio.h>

void
logi (const char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  vfprintf (stdout, fmt, va);
  va_end (va);
}

void
loge (const char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  vfprintf (stdout, fmt, va);
  va_end (va);
}
