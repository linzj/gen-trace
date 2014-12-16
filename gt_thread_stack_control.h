#ifndef GT_THREAD_STACK_CONTROL_H
#define GT_THREAD_STACK_CONTROL_H
#pragma once
struct CTraceStruct;
struct ThreadInfo;

void gt_thread_stack_control_push (struct ThreadInfo *info, HWord addr);
struct CTraceStruct *gt_thread_stack_control_pop (struct ThreadInfo *info,
                                                  HWord last_addr);
void gt_thread_stack_control_init (void);

#endif /* GT_THREAD_STACK_CONTROL_H */
