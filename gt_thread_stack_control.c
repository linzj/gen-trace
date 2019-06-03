#include "valgrind.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_debuginfo.h"
#include "gt_thread_stack_control.h"
#include "gt_threadinfo.h"
#include "gt_config.h"

static Bool s_always = True;
static HChar **s_match_patterns;
static int s_num_of_match_patterns;
static Bool s_match_enable = False;

void
gt_thread_stack_control_push (struct ThreadInfo *info, HWord addr)
{
  if (s_always || s_match_enable)
    {
      gt_thread_info_push (info, addr);
    }
  else
    {
      const HChar *fnname;

      if (VG_ (get_fnname) (addr, &fnname))
        {
          int i;
          for (i = 0; i < s_num_of_match_patterns; ++i)
            {
              HChar *str = s_match_patterns[i];
              if (VG_ (strstr) (fnname, str))
                {
                  // match
                  s_match_enable = True;
                  gt_thread_info_push (info, addr);
                }
            }
        }
    }
}

struct CTraceStruct *
gt_thread_stack_control_pop (struct ThreadInfo *info, HWord last_addr)
{
  if (s_always)
    {
      return gt_thread_info_pop (info, last_addr);
    }
  else if (s_match_enable)
    {
      struct CTraceStruct *ret;

      ret = gt_thread_info_pop (info, last_addr);
      if (info->stack_end_ == 0)
        s_match_enable = False;
      return ret;
    }
  return NULL;
}

void
gt_thread_stack_control_init (void)
{
  const HChar *str;
  const HChar *end;
  int count;
  int index;
  if (!s_only_begin_with)
    {
      return;
    }
  // Parse s_only_begin_with.
  // Pre parse.
  end = s_only_begin_with - 1;
  count = 0;
  do
    {
      str = end + 1;
      if (*str == '\0')
        break;
      end = VG_ (strstr)(str, "|");
      if (str != end)
        count++;
    }
  while (end != NULL);
  s_num_of_match_patterns = count;

  if (count != 0)
    s_always = False;
  s_match_patterns = VG_ (malloc)("thread_stack_control.patterns",
                                  sizeof (HChar *) * count);
  // fill in s_match_patterns.

  end = s_only_begin_with - 1;
  index = 0;
  do
    {
      str = end + 1;
      if (*str == '\0')
        break;
      end = VG_ (strstr)(str, "|");
      if (str != end)
        {
          int len;
          if (end == NULL)
            {
              len = VG_ (strlen)(str);
            }
          else
            {
              len = end - str;
            }

          HChar *new_string
              = (HChar *)VG_ (malloc)("thread_stack_control.strings", len + 1);
          VG_ (memcpy)(new_string, str, len);
          new_string[len] = 0;
          s_match_patterns[index++] = new_string;
        }
    }
  while (end != NULL);
}
