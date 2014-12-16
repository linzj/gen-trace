#ifndef GT_RECORD_H
#define GT_RECORD_H
#pragma once
#include <stdint.h>
struct ThreadInfo;
struct CTraceStruct;

struct Record
{
  int pid_;
  int tid_;
  int64_t start_time_;
  int64_t dur_;
  const HChar *name_;
  struct Record *next_;
};

void gt_ctrace_struct_submit (struct CTraceStruct *c,
                              struct ThreadInfo *tinfo);
void gt_final_write (void);
#endif /* GT_RECORD_H */
