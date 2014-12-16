
/*--------------------------------------------------------------------*/
/*--- gentrace: The trace file generator                gt_main.c ---*/
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
#include "pub_tool_mallocfree.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_xarray.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_options.h"
#include "pub_tool_aspacemgr.h"

#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <alloca.h>

#include "gt_string.h"
#include "gt_threadinfo.h"
#include "gt_time.h"
#include "gt_config.h"
#include "gt_misc.h"

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
  if (c->end_time_ - c->start_time_ <= s_min_interval)
    return;

  buf[0] = 0;
  VG_ (get_fnname)(c->last_, buf, 256);
  if (buf[0] == 0)
    gt_overwrite_empty_fnname (buf, c->last_);
  r = VG_ (malloc)("gentrace.record", sizeof (struct Record));
  r->pid_ = tinfo->pid_;
  r->tid_ = tinfo->tid_;
  r->start_time_ = c->start_time_;
  r->name_ = gt_find_string (buf);
  if (c->end_time_ > c->start_time_)
    r->dur_ = c->end_time_ - c->start_time_;
  else
    r->dur_ = 1;
  r->next_ = s_head;
  s_head = r;
}

static void
handle_call_entry (HWord addr)
{
  struct ThreadInfo *tinfo;
  tinfo = gt_get_thread_info ();
  if (!tinfo)
    return;
  // VG_ (printf)("handle_call_entry : addr = %lx\n", addr);

  gt_thread_info_push (tinfo, addr);
}

static void
handle_ret_entry (HWord addr)
{
  struct ThreadInfo *tinfo;
  struct CTraceStruct *c;
  tinfo = gt_get_thread_info ();
  if (!tinfo)
    return;
  // VG_ (printf)("handle_ret_entry : addr = %lx\n", addr);
  c = gt_thread_info_pop (tinfo, addr);
  if (!c)
    return;
  ctrace_struct_submit (c, tinfo);
}

static void
guest_sb_entry_worker (struct ThreadInfo *tinfo, HWord addr, HWord jumpkind)
{
  HWord last_jumpkind = tinfo->last_jumpkind_;
  HWord last_addr = tinfo->last_addr_;
  Word bc_jumpkind = tinfo->bc_jumpkind_;
  tinfo->last_jumpkind_ = jumpkind;
  tinfo->last_addr_ = addr;

  if (bc_jumpkind != Ijk_INVALID)
    {
      last_jumpkind = bc_jumpkind;

      tinfo->bc_jumpkind_ = Ijk_INVALID;
    }

  switch (last_jumpkind)
    {
    case Ijk_Ret:
      handle_ret_entry (last_addr);
      return;
    case Ijk_Call:
      handle_call_entry (addr);
      break;
    case Ijk_Sys_syscall:
    case Ijk_Sys_int32:
    case Ijk_Sys_int128:
    case Ijk_Sys_int129:
    case Ijk_Sys_int130:
    case Ijk_Sys_sysenter:
      // Update the thread time after a syscall.
      if (s_use_estimated_time)
        {
          int64_t nowms = gt_get_times_from_clock_ (CLOCK_MONOTONIC);
          int64_t nowns = nowms * 1000;
          if (nowns > tinfo->estimated_thread_ns_)
            tinfo->estimated_thread_ns_ = nowns;
        }
    default:
      break;
    }
}

static VG_REGPARM (2) void guest_sb_entry (HWord addr, HWord jumpkind)
{
  struct ThreadInfo *tinfo;
  tinfo = gt_get_thread_info ();
  if (!tinfo)
    return;
  guest_sb_entry_worker (tinfo, addr, jumpkind);
}

static VG_REGPARM (3) void guest_sb_entry_estimated (HWord addr,
                                                     HWord jumpkind,
                                                     HWord size)
{
  struct ThreadInfo *tinfo;
  tinfo = gt_get_thread_info ();
  if (!tinfo)
    return;
  tinfo->estimated_thread_ns_ += size << 1;
  guest_sb_entry_worker (tinfo, addr, jumpkind);
}

static VG_REGPARM (1) void guest_bc_entry (HWord jumpkind)
{
  struct ThreadInfo *tinfo;
  tinfo = gt_get_thread_info ();
  if (!tinfo)
    return;
  tinfo->bc_jumpkind_ = jumpkind;
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
  gt_init_string ();
}

static void
add_host_function_helper_2 (IRSB *sbOut, const char *str, void *func,
                            IRExpr *r1, IRExpr *r2)
{
  IRDirty *di;
  IRExpr **argv;

  argv = mkIRExprVec_2 (r1, r2);

  di = unsafeIRDirty_0_N (2, str, func, argv);
  addStmtToIRSB (sbOut, IRStmt_Dirty (di));
}

static void
add_host_function_helper_3 (IRSB *sbOut, const char *str, void *func,
                            IRExpr *r1, IRExpr *r2, IRExpr *r3)
{
  IRDirty *di;
  IRExpr **argv;

  argv = mkIRExprVec_3 (r1, r2, r3);

  di = unsafeIRDirty_0_N (3, str, func, argv);
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
                if (s_use_estimated_time)
                  {
                    add_host_function_helper_3 (
                        sbOut, "guest_sb_entry_estimated",
                        VG_ (fnptr_to_fnentry)(guest_sb_entry_estimated),
                        mkIRExpr_HWord (cia + st->Ist.IMark.delta),
                        mkIRExpr_HWord (sbIn->jumpkind),
                        mkIRExpr_HWord (sbIn->stmts_used));
                  }
                else
                  {
                    add_host_function_helper_2 (
                        sbOut, "guest_sb_entry",
                        VG_ (fnptr_to_fnentry)(guest_sb_entry),
                        mkIRExpr_HWord (cia + st->Ist.IMark.delta),
                        mkIRExpr_HWord (sbIn->jumpkind));
                  }
                has_inject_sb_entry = True;
              }
          }
          break;
        case Ist_Exit:
          {
            Bool guest_exit;
            IRDirty *di;
            IRExpr **args;
            guest_exit = (st->Ist.Exit.jk == Ijk_Boring)
                         || (st->Ist.Exit.jk == Ijk_Call)
                         || (st->Ist.Exit.jk == Ijk_Ret);
            if (!guest_exit)
              break;

            args = mkIRExprVec_1 (mkIRExpr_HWord (st->Ist.Exit.jk));

            di = emptyIRDirty ();
            di->cee = mkIRCallee (1, "guest_bc_entry",
                                  VG_ (fnptr_to_fnentry)(guest_bc_entry));
            di->guard = st->Ist.Exit.guard;
            di->args = args;
            addStmtToIRSB (sbOut, IRStmt_Dirty (di));
          }
        default:
          break;
        }
      if (False)
        {
          HChar buf[256];
          buf[0] = 0;
          VG_ (get_fnname)(cia, buf, 256);
          if (buf[0] == 0)
            gt_overwrite_empty_fnname (buf, cia);
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
gt_fini (Int exitcode)
{
  SysRes res;
  char buf[256];
  // flush all thread info
  gt_flush_thread_info (ctrace_struct_submit);

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
  gt_destroy_string ();
}

static Bool
gt_process_cmd_line_option (const HChar *arg)
{
  if (VG_INT_CLO (arg, "--max-stack", s_max_stack))
    {
    }
  if (VG_INT_CLO (arg, "--min-interval", s_min_interval))
    {
    }
  if (VG_BOOL_CLO (arg, "--use-estimated-time", s_use_estimated_time))
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
  VG_ (printf)(
      "\t--max-stack: Used to specify a max stack size. This option\n"
      "\t             effects the size of trace output.\n"
      "\t--use-estimated-time: Use estimated time instead of real time.\n"
      "\t--min-interval: Used to specify a the minium interval. No\n"
      "\t             interval should less than what you specify.\n");
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

  gt_thread_info_init ();

  VG_ (needs_command_line_options)(gt_process_cmd_line_option, gt_print_usage,
                                   gt_print_debug_usage);
}

VG_DETERMINE_INTERFACE_VERSION (gt_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
