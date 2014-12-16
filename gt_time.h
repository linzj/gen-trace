#ifndef GT_TIME_H
#define GT_TIME_H
#pragma once
struct ThreadInfo;
int64_t gt_get_times_from_clock_ (int clockid);
int64_t gt_get_times_from_clock (struct ThreadInfo *tinfo);

#endif /* GT_TIME_H */
