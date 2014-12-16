#ifndef GT_THREADINFO_H
#define GT_THREADINFO_H
#pragma once
#include <stdint.h>

struct CTraceStruct
{
  int64_t start_time_;
  int64_t end_time_;
  HWord last_;
};

struct ThreadInfo
{
  int pid_;
  int tid_;
  struct CTraceStruct *stack_;
  int stack_end_;
  HWord last_jumpkind_;
  HWord last_addr_;
  Word bc_jumpkind_;
  int64_t estimated_thread_ns_;
};

struct ThreadInfo *gt_get_thread_info (void);

void gt_thread_info_init (void);

struct CTraceStruct *gt_thread_info_pop (struct ThreadInfo *info,
                                         HWord last_addr);

void gt_thread_info_push (struct ThreadInfo *info, HWord addr);

void gt_flush_thread_info (void (*worker)(struct CTraceStruct *c,
                                          struct ThreadInfo *tinfo));
#endif /* GT_THREADINFO_H */
