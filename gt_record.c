#include <stdint.h>
#include <inttypes.h>
#include "valgrind.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_xarray.h"
#include "pub_tool_libcfile.h"
#include "gt_record.h"
#include "gt_threadinfo.h"
#include "gt_config.h"
#include "gt_misc.h"
#include "gt_string.h"

static struct Record *s_head;

void
gt_ctrace_struct_submit (struct CTraceStruct *c, struct ThreadInfo *tinfo)
{
  HChar buf[256];
  struct Record *r;
  if (c->end_time_ - c->start_time_ <= s_min_interval)
    return;

  buf[0] = 0;
  VG_ (get_fnname)(c->last_, buf, 256);
  if (buf[0] == 0)
    gt_overwrite_empty_fnname (buf, c->last_);
  r = VG_ (malloc)("gentrace.record", sizeof (struct Record));
  r->pid_ = tinfo->pid_;
  r->tid_ = tinfo->tid_;
  r->start_time_ = c->start_time_;
  r->name_ = gt_find_string (buf);
  if (c->end_time_ > c->start_time_)
    r->dur_ = c->end_time_ - c->start_time_;
  else
    r->dur_ = 1;
  r->next_ = s_head;
  s_head = r;
}

static void
DoWriteRecursive (int file_to_write, struct Record *current)
{
  char buf[256];
  XArray *array;
  const char comma[] = ", ";
  int i;
  Bool needComma = False;

  // init the array
  array = VG_ (newXA)(VG_ (malloc), "gentrace.DoWriteRecursive.1", VG_ (free),
                      sizeof (struct Record *));

  while (current)
    {
      VG_ (addToXA)(array, &current);
      current = current->next_;
    }
  i = VG_ (sizeXA)(array) - 1;

  for (; i >= 0; --i)
    {
      const char *name;
      char name_buf[64];
      if (!needComma)
        {
          needComma = True;
        }
      else
        {
          VG_ (write)(file_to_write, comma, sizeof (comma) - 1);
        }
      current = *(struct Record **)VG_ (indexXA)(array, i);
      int size;
      if (VG_ (strlen (current->name_)) >= 64)
        {
          VG_ (memcpy)(name_buf, current->name_, 63);
          name_buf[63] = 0;
          name = name_buf;
        }
      else
        {
          name = current->name_;
        }
      size = VG_ (snprintf)(
          buf, 256,
          "{\"cat\":\"%s\", \"pid\":%d, \"tid\":%d, \"ts\":%" PRId64 ", "
          "\"ph\":\"X\", \"name\":\"%s\", \"dur\": %" PRId64 "}",
          "profile", current->pid_, current->tid_, current->start_time_, name,
          current->dur_);
      VG_ (write)(file_to_write, buf, size);
      VG_ (free)(current);
    }
  VG_ (deleteXA)(array);
}

void
gt_final_write (void)
{
  SysRes res;
  char buf[256];
  VG_ (snprintf)(buf, 256, "trace_%d.json", VG_ (getpid)());
  res = VG_ (open)(buf, VKI_O_CREAT | VKI_O_WRONLY, VKI_S_IRUSR | VKI_S_IWUSR);
  if (!sr_isError (res))
    {
      int output;
      output = sr_Res (res);
      const char start[] = "{\"traceEvents\": [";
      const char end[] = "]}";
      VG_ (write)(output, start, sizeof (start) - 1);
      DoWriteRecursive (output, s_head);
      VG_ (write)(output, end, sizeof (end) - 1);
      VG_ (close)(output);
    }
}
