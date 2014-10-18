
/*--------------------------------------------------------------------*/
/*--- Nulgrind: The minimal Valgrind tool.               nl_main.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Nulgrind, the minimal Valgrind tool,
   which does no instrumentation or analysis.

   Copyright (C) 2002-2013 Nicholas Nethercote
      njn@valgrind.org

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#include "valgrind.h"
#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_machine.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_xarray.h"

#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <alloca.h>

#include <sys/syscall.h>

static ThreadId s_tid;
#define HASH_CONSTANT 256

struct MyNode
{
  VgHashNode super;
  HChar str[1];
};

struct MyLookupNode
{
  VgHashNode super;
  const HChar *str;
};

static UWord
str_hash (const HChar *s)
{
  UWord hash_value = 0;
  for (; *s; s++)
    hash_value = (HASH_CONSTANT * hash_value + *s);
  return hash_value;
}

static Word
lookup_func (const void *node1, const void *node2)
{
  const struct MyLookupNode *lookup = node1;
  const struct MyNode *node = node2;
  return VG_ (strcmp)(lookup->str, (char *)node->str);
}

static VgHashTable s_string_hash_table;

static HChar *
new_string (const HChar *str, Word key)
{
  int len;
  struct MyNode *new_node;

  len = VG_ (strlen)(str);
  new_node = VG_ (malloc)("gentrace.fnname", sizeof (struct MyNode) + len + 1);
  new_node->super.key = key;
  new_node->super.next = 0;
  VG_ (strcpy)(new_node->str, str);
  VG_ (HT_add_node)(s_string_hash_table, new_node);
  return new_node->str;
}

static HChar *
find_string (const HChar *str)
{
  struct MyLookupNode lookup_node;
  struct MyNode *found;
  lookup_node.super.key = str_hash (str);
  lookup_node.str = str;

  found = VG_ (HT_gen_lookup)(s_string_hash_table, &lookup_node, lookup_func);
  if (found)
    {
      return found->str;
    }
  return new_string (str, lookup_node.super.key);
}

static int64_t
GetTimesFromClock (int clockid)
{
  struct timespec ts_thread;
  int64_t ret;
  static const int64_t kMillisecondsPerSecond = 1000;
  static const int64_t kMicrosecondsPerMillisecond = 1000;
  static const int64_t kMicrosecondsPerSecond = kMicrosecondsPerMillisecond
                                                * kMillisecondsPerSecond;
  static const int64_t kNanosecondsPerMicrosecond = 1000;

  extern SysRes VG_ (do_syscall)(UWord sysno, UWord, UWord, UWord, UWord,
                                 UWord, UWord, UWord, UWord, UWord, UWord,
                                 UWord, UWord);
  VG_ (do_syscall)(__NR_clock_gettime, clockid, (UWord)&ts_thread, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0);
  ret = ((int64_t)(ts_thread.tv_sec) * kMicrosecondsPerSecond)
        + ((int64_t)(ts_thread.tv_nsec) / kNanosecondsPerMicrosecond);
  return ret;
}

struct CTraceStruct
{
  int64_t start_time_;
  int64_t end_time_;
  HChar *name_;
};

#define MAX_STACK (100)
struct ThreadInfo
{
  int pid_;
  int tid_;
  struct CTraceStruct stack_[MAX_STACK];
  int stack_end_;
};

#define MAX_THREAD_INFO (1000)
struct ThreadInfo s_thread_info[MAX_THREAD_INFO];

static struct CTraceStruct *
thread_info_pop (struct ThreadInfo *info, const HChar *fnname)
{
  struct CTraceStruct *target;
  if (info->stack_end_ == 0)
    return NULL;
  if (info->stack_end_-- > MAX_STACK)
    return NULL;

  target = &info->stack_[info->stack_end_];
  // work around c++ throw
  if (VG_ (strcmp)(target->name_, fnname))
    return thread_info_pop (info, fnname);

  target->end_time_ = GetTimesFromClock (CLOCK_MONOTONIC);
  return target;
}

static void
thread_info_push (struct ThreadInfo *info, const HChar *fnname)
{
  struct CTraceStruct *target;
  int index;
  if (info->stack_end_++ > MAX_STACK)
    return;
  index = info->stack_end_ - 1;
  target = &info->stack_[index];
  target->name_ = find_string (fnname);
  tl_assert (target->name_ != NULL);
  target->start_time_ = GetTimesFromClock (CLOCK_MONOTONIC);
}

struct Record
{
  int pid_;
  int tid_;
  int64_t start_time_;
  int64_t dur_;
  const HChar *name_;
  struct Record *next_;
};

static struct Record *s_head;

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
      size = VG_ (snprintf)(
          buf, 256,
          "{\"cat\":\"%s\", \"pid\":%d, \"tid\":%d, \"ts\":%" PRId64 ", "
          "\"ph\":\"X\", \"name\":\"%s\", \"dur\": %" PRId64 "}",
          "profile", current->pid_, current->tid_, current->start_time_,
          current->name_, current->dur_);
      VG_ (write)(file_to_write, buf, size);
      VG_ (free)(current);
    }
  VG_ (deleteXA)(array);
}

static void
ctrace_struct_submit (struct CTraceStruct *c, struct ThreadInfo *tinfo)
{
  struct Record *r = VG_ (malloc)("gentrace.record", sizeof (struct Record));
  r->pid_ = tinfo->pid_;
  r->tid_ = tinfo->tid_;
  r->start_time_ = c->start_time_;
  r->name_ = c->name_;
  if (c->end_time_ > c->start_time_)
    r->dur_ = c->end_time_ - c->start_time_;
  else
    r->dur_ = 1;
  r->next_ = s_head;
  s_head = r;
}

static struct ThreadInfo *
get_thread_info (void)
{
  int index;
  struct ThreadInfo *ret;
  if (s_tid > MAX_THREAD_INFO)
    return NULL;
  index = s_tid - 1;
  ret = &s_thread_info[index];
  if (ret->tid_ == 0)
    {
      ret->tid_ = s_tid;
      ret->pid_ = VG_ (getpid)();
    }
  return ret;
}

static VG_REGPARM (1) void guest_call_entry (Addr64 addr)
{
  HChar buf[256];
  struct ThreadInfo *tinfo;
  Bool ret = VG_ (get_fnname_if_entry)(addr, buf, 256);

  if (ret != True)
    {
      return;
    }
  // VG_ (printf)("at function entry:%08llx:%s:%d\n", addr, buf, s_tid);
  tinfo = get_thread_info ();
  if (!tinfo)
    return;
  thread_info_push (tinfo, buf);
}

static VG_REGPARM (1) void guest_ret_entry (Addr64 addr)
{
  HChar buf[256];
  struct ThreadInfo *tinfo;
  struct CTraceStruct *c;
  Bool ret = VG_ (get_fnname)(addr, buf, 256);

  // VG_ (printf)("at function return:%08llx:%s:%d\n", addr, buf, s_tid);
  if (ret != True)
    {
      return;
    }
  tinfo = get_thread_info ();
  if (!tinfo)
    return;
  c = thread_info_pop (tinfo, buf);
  if (!c)
    return;
  ctrace_struct_submit (c, tinfo);
}

static void
gt_start_client_code_callback (ThreadId tid, ULong blocks_done)
{
  s_tid = tid;
}

static void
gt_post_clo_init (void)
{
  s_string_hash_table = VG_ (HT_construct)("fnname table");
}

static IRSB *
gt_instrument (VgCallbackClosure *closure, IRSB *sbIn, VexGuestLayout *layout,
               VexGuestExtents *vge, VexArchInfo *archinfo_host,
               IRType gWordTy, IRType hWordTy)
{
  Bool bIMarkMet = False;
  IRSB *sbOut;
  int i = 0;
  Addr64 cia = 0;
  // Int isize;
  // VG_ (printf)("sb begins\n");
  sbOut = deepCopyIRSBExceptStmts (sbIn);
  for (/*use current i*/; i < sbIn->stmts_used; i++)
    {
      IRStmt *st;
      Bool bNeedToAdd = True;
      st = sbIn->stmts[i];

      switch (st->tag)
        {
        case Ist_IMark:
          {
            HChar buf[256];

            cia = st->Ist.IMark.addr;
            // isize = st->Ist.IMark.len;
            // delta = st->Ist.IMark.delta;
            if (VG_ (get_fnname_if_entry)(cia, buf, 256))
              {
                // VG_ (printf)("found fnname %s at %08x\n", buf, cia);
                // handle code injection here
                IRExpr *addr;
                IRDirty *di;
                IRExpr **argv;

                addr = mkIRExpr_HWord (cia);
                argv = mkIRExprVec_1 (addr);
                di = unsafeIRDirty_0_N (
                    1, "guest_call_entry",
                    VG_ (fnptr_to_fnentry)(guest_call_entry), argv);
                addStmtToIRSB (sbOut, IRStmt_Dirty (di));
              }
            if (!bIMarkMet)
              {
                if (sbIn->jumpkind == Ijk_Ret)
                  {
                    IRExpr *addr;
                    IRDirty *di;
                    IRExpr **argv;

                    addr = mkIRExpr_HWord (cia);
                    argv = mkIRExprVec_1 (addr);
                    di = unsafeIRDirty_0_N (
                        1, "guest_ret_entry",
                        VG_ (fnptr_to_fnentry)(guest_ret_entry), argv);
                    addStmtToIRSB (sbOut, IRStmt_Dirty (di));
                  }
                bIMarkMet = True;
              }
          }
          break;
        default:
          break;
        }
      if (False)
        {
          HChar buf[256];
          VG_ (get_fnname)(cia, buf, 256);
          if (VG_ (strcmp)(buf, "strcmp") == 0)
            {
              VG_ (printf)("   pass  %s  ", buf);
              ppIRStmt (st);
              VG_ (printf)("\n");
            }
        }
      if (bNeedToAdd)
        addStmtToIRSB (sbOut, st);
    }
  // VG_ (printf)("sb ends\n");
  return sbOut;
}

static void
gt_fini (Int exitcode)
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
  VG_ (HT_destruct)(s_string_hash_table, VG_ (free));
}

static void
gt_pre_clo_init (void)
{
  VG_ (details_name)("gentrace");
  VG_ (details_version)(NULL);
  VG_ (details_description)("the gentrace Valgrind tool");
  VG_ (details_copyright_author)(
      "Copyright (C) 2002-2013, and GNU GPL'd, by Nicholas Nethercote.");
  VG_ (details_bug_reports_to)(VG_BUGS_TO);

  VG_ (details_avg_translation_sizeB)(275);

  VG_ (basic_tool_funcs)(gt_post_clo_init, gt_instrument, gt_fini);

  VG_ (track_start_client_code)(&gt_start_client_code_callback);

  /* No needs, no core events to track */
}

VG_DETERMINE_INTERFACE_VERSION (gt_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
