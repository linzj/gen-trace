#include "valgrind.h"
#include "pub_tool_aspacemgr.h"
#include "pub_tool_libcprint.h"
#include "gt_misc.h"

void
gt_overwrite_empty_fnname (HChar buf[256], HWord addr)
{
  const NSegment *segment;
  segment = VG_ (am_find_nsegment)(addr);
  if (!segment)
    {
      VG_ (snprintf)(buf, 256, "Unknown: %08lx", addr);
      return;
    }
  VG_ (snprintf)(buf, 256, "%s: %08lx", VG_ (am_get_filename)(segment),
                 addr - segment->start);
}
