#include "valgrind.h"
#include "pub_tool_tooliface.h"
#include "gt_thread_stack_control.h"
#include "gt_threadinfo.h"

void
gt_thread_stack_control_push (struct ThreadInfo *info, HWord addr)
{
  gt_thread_info_push (info, addr);
}

struct CTraceStruct *
gt_thread_stack_control_pop (struct ThreadInfo *info, HWord last_addr)
{
  return gt_thread_info_pop (info, last_addr);
}

void
gt_thread_stack_control_init (void)
{
}
