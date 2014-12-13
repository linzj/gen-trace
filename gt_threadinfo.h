#ifndef GT_THREADINFO_H
#define GT_THREADINFO_H
#pragma once

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

#endif /* GT_THREADINFO_H */
