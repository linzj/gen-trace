#include "valgrind.h"
#include "pub_tool_basics.h"
#include "gt_config.h"
// Estimated time facility.
Bool s_use_estimated_time = False;
int s_max_stack = 15;
int s_min_interval = 10;
const char *s_only_begin_with = NULL;
