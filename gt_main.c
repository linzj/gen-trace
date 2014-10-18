
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

static ThreadId s_tid;

static VG_REGPARM (1) void guest_call_entry (Addr64 addr)
{
  HChar buf[256];
  Bool ret = VG_ (get_fnname_if_entry)(addr, buf, 256);

  tl_assert (ret == True);
  VG_ (printf)("at function entry:%08llx:%s:%d\n", addr, buf, s_tid);
}

static VG_REGPARM (1) void guest_ret_entry (Addr64 addr)
{
  HChar filebuf[256];
  HChar dirbuf[256];
  Bool dirAvailable;
  Bool ret;
  UInt linenum;

  ret = VG_ (get_filename_linenum)(addr, filebuf, 256, dirbuf, 256,
                                   &dirAvailable, &linenum);
  if (!ret)
    {
      VG_ (printf)("function return at :%08llx:%d\n", addr, s_tid);
      return;
    }
  if (!dirAvailable)
    dirbuf[0] = 0;
  VG_ (printf)("function return at :%08llx:%s:%s:%u:%d\n", addr, dirbuf,
               filebuf, linenum, s_tid);
}

static void
gt_start_client_code_callback (ThreadId tid, ULong blocks_done)
{
  s_tid = tid;
}

static void
gt_post_clo_init (void)
{
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
            if (!bIMarkMet)
              {
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
                else if (sbIn->jumpkind == Ijk_Ret)
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
          if (True)
            {
              VG_ (printf)("   pass  ");
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
