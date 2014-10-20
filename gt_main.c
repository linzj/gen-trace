
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
#include "pub_tool_threadstate.h"
#include "pub_tool_options.h"

#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <alloca.h>

#include <sys/syscall.h>

static ThreadId s_tid;
static int s_max_stack = 15;
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

  static int64_t last_time;
  extern SysRes VG_ (do_syscall)(UWord sysno, UWord, UWord, UWord, UWord,
                                 UWord, UWord);
  VG_ (do_syscall)(__NR_clock_gettime, clockid, (UWord)&ts_thread, 0, 0, 0, 0);
  ret = ((int64_t)(ts_thread.tv_sec) * kMicrosecondsPerSecond)
        + ((int64_t)(ts_thread.tv_nsec) / kNanosecondsPerMicrosecond);
  if (last_time == ret)
    return last_time + 1;
  last_time = ret;
  return ret;
}

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
};

#define MAX_THREAD_INFO (1000)
struct ThreadInfo s_thread_info[MAX_THREAD_INFO];

static struct CTraceStruct *
thread_info_pop (struct ThreadInfo *info)
{
  struct CTraceStruct *target;
  if (info->stack_end_ == 0)
    return NULL;
  if (info->stack_end_-- > s_max_stack)
    return NULL;

  target = &info->stack_[info->stack_end_];

  target->end_time_ = GetTimesFromClock (CLOCK_MONOTONIC);
  // VG_ (printf)("thread_info_pop: pop addr %lx\n", target->last_);
  return target;
}

static void
thread_info_push (struct ThreadInfo *info, HWord addr)
{
  struct CTraceStruct *target;
  int index;
  if (++info->stack_end_ > s_max_stack)
    return;
  index = info->stack_end_ - 1;
  target = &info->stack_[index];
  target->last_ = addr;
  target->start_time_ = GetTimesFromClock (CLOCK_MONOTONIC);
  // VG_ (printf)("thread_info_push: push addr %lx\n", addr);
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
      const char *name;
      char name_buf[64];
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
      if (VG_ (strlen (current->name_)) >= 64)
        {
          VG_ (memcpy)(name_buf, current->name_, 63);
          name_buf[63] = 0;
          name = name_buf;
        }
      else
        {
          name = current->name_;
        }
      size = VG_ (snprintf)(
          buf, 256,
          "{\"cat\":\"%s\", \"pid\":%d, \"tid\":%d, \"ts\":%" PRId64 ", "
          "\"ph\":\"X\", \"name\":\"%s\", \"dur\": %" PRId64 "}",
          "profile", current->pid_, current->tid_, current->start_time_, name,
          current->dur_);
      VG_ (write)(file_to_write, buf, size);
      VG_ (free)(current);
    }
  VG_ (deleteXA)(array);
}

static void
ctrace_struct_submit (struct CTraceStruct *c, struct ThreadInfo *tinfo)
{
  HChar buf[256];
  struct Record *r;
  if (c->end_time_ - c->start_time_ <= 10)
    return;

  buf[0] = 0;
  VG_ (get_fnname)(c->last_, buf, 256);
  r = VG_ (malloc)("gentrace.record", sizeof (struct Record));
  r->pid_ = tinfo->pid_;
  r->tid_ = tinfo->tid_;
  r->start_time_ = c->start_time_;
  r->name_ = find_string (buf);
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
      // initialize it if possible
      ret->tid_ = s_tid;
      ret->pid_ = VG_ (getpid)();
      ret->last_jumpkind_ = Ijk_INVALID;
      ret->stack_ = VG_ (malloc)("gentrace.stack",
                                 sizeof (struct CTraceStruct) * s_max_stack);
    }
  return ret;
}

static Bool
is_function_named (const HChar *name, HWord addr)
{
  HChar buf[256];
  buf[0] = 0;
  if (VG_ (get_fnname)(addr, buf, 256))
    {
      if (VG_ (strstr)(buf, name) == buf)
        return True;
    }
  return False;
}

static void
handle_call_entry (HWord addr)
{
  struct ThreadInfo *tinfo;
  tinfo = get_thread_info ();
  if (!tinfo)
    return;
  // VG_ (printf)("handle_call_entry : addr = %lx\n", addr);

  thread_info_push (tinfo, addr);
}

static void
handle_ret_entry (HWord addr)
{
  struct ThreadInfo *tinfo;
  struct CTraceStruct *c;
  tinfo = get_thread_info ();
  if (!tinfo)
    return;
  // VG_ (printf)("handle_ret_entry : addr = %lx\n", addr);
  c = thread_info_pop (tinfo);
  if (!c)
    return;
  ctrace_struct_submit (c, tinfo);
}

static VG_REGPARM (2) void guest_sb_entry (HWord addr, HWord jumpkind)
{
  struct ThreadInfo *tinfo;
  tinfo = get_thread_info ();
  if (!tinfo)
    return;
  HWord last_jumpkind = tinfo->last_jumpkind_;
  tinfo->last_jumpkind_ = jumpkind;
  tinfo->last_addr_ = addr;

  switch (last_jumpkind)
    {
    case Ijk_Ret:
      handle_ret_entry (addr);
      return;
    case Ijk_Call:
      handle_call_entry (addr);
      break;
    default:
      break;
    }
}

static void
gt_start_client_code_callback (ThreadId tid, ULong blocks_done)
{
  s_tid = tid;
}

static void
gt_post_clo_init (void)
{
  if (VG_ (clo_vex_control).iropt_unroll_thresh != 0)
    {
      VG_ (message)(Vg_UserMsg,
                    "gentrace only works with --vex-iropt-unroll-thresh=0\n"
                    "=> resetting it back to 0\n");
      VG_ (clo_vex_control).iropt_unroll_thresh = 0; // cannot be overriden.
    }
  if (VG_ (clo_vex_control).guest_chase_thresh != 0)
    {
      VG_ (message)(Vg_UserMsg,
                    "gentrace only works with --vex-guest-chase-thresh=0\n"
                    "=> resetting it back to 0\n");
      VG_ (clo_vex_control).guest_chase_thresh = 0; // cannot be overriden.
    }
  VG_ (message)(Vg_UserMsg, "max stack = %d\n", s_max_stack);
  s_string_hash_table = VG_ (HT_construct)("fnname table");
}

static void
add_host_function_helper_2 (IRSB *sbOut, const char *str, void *func,
                            HWord cia, HWord jumpkind)
{
  IRExpr *addr;
  IRExpr *jumpkind_expr;
  IRDirty *di;
  IRExpr **argv;

  addr = mkIRExpr_HWord (cia);
  jumpkind_expr = mkIRExpr_HWord (jumpkind);
  argv = mkIRExprVec_2 (addr, jumpkind_expr);

  di = unsafeIRDirty_0_N (2, str, func, argv);
  addStmtToIRSB (sbOut, IRStmt_Dirty (di));
}

static IRSB *
gt_instrument (VgCallbackClosure *closure, IRSB *sbIn, VexGuestLayout *layout,
               VexGuestExtents *vge, VexArchInfo *archinfo_host,
               IRType gWordTy, IRType hWordTy)
{
  IRSB *sbOut;
  int i = 0;
  Bool has_inject_sb_entry = False;
  HWord cia = 0;
  // Int isize;
  // filter out the strcmp shit

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
            cia = st->Ist.IMark.addr;
            if (!has_inject_sb_entry)
              {
                // VG_ (printf)("instrument: adding guest_sb_entry before instr
                // "
                //              "%lx, %0x\n",
                //              cia, sbIn->jumpkind);
                add_host_function_helper_2 (
                    sbOut, "guest_sb_entry",
                    VG_ (fnptr_to_fnentry)(guest_sb_entry), cia,
                    sbIn->jumpkind);
                has_inject_sb_entry = True;
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
          // if (VG_ (strstr)(buf, "memory_move_cost") == buf)
          {
            VG_ (printf)("   pass  %s ", buf);
            ppIRStmt (st);
            VG_ (printf)(" sbIn->jumpkind = %x, %p\n", sbIn->jumpkind, sbIn);
          }
        }
      if (bNeedToAdd)
        addStmtToIRSB (sbOut, st);
    }
  return sbOut;
}

static void
flush_thread_info (void)
{
  int i;

  for (i = 0; i < MAX_THREAD_INFO; ++i)
    {
      struct ThreadInfo *info = &s_thread_info[i];
      if (info->tid_ == 0)
        break;
      if (info->stack_end_ > 0)
        {
          int64_t end_time;

          end_time = GetTimesFromClock (CLOCK_MONOTONIC);
          if (info->stack_end_ > s_max_stack)
            info->stack_end_ = s_max_stack;
          while (info->stack_end_ > 0)
            {
              struct CTraceStruct *c = &info->stack_[--info->stack_end_];
              c->end_time_ = end_time;
              end_time += 10;
              ctrace_struct_submit (c, info);
            }
        }
    }
}

static void
gt_fini (Int exitcode)
{
  SysRes res;
  char buf[256];
  // flush all thread info
  flush_thread_info ();

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

static Bool
gt_process_cmd_line_option (const HChar *arg)
{
  if (VG_INT_CLO (arg, "--max-stack", s_max_stack))
    {
    }
  return True;
}

static void
gt_print_debug_usage (void)
{
}

static void
gt_print_usage (void)
{
  VG_ (printf)("\t--max-stack: Used to specify a max stack size. This option\n"
               "\t             effects the size of trace output.\n");
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

  VG_ (needs_command_line_options)(gt_process_cmd_line_option, gt_print_usage,
                                   gt_print_debug_usage);
}

VG_DETERMINE_INTERFACE_VERSION (gt_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
