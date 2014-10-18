
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

static void
gt_post_clo_init (void)
{
}

static IRSB *
gt_instrument (VgCallbackClosure *closure, IRSB *sbIn, VexGuestLayout *layout,
               VexGuestExtents *vge, VexArchInfo *archinfo_host,
               IRType gWordTy, IRType hWordTy)
{
  int i = 0;
  // VG_ (printf)("sb begins\n");

  for (/*use current i*/; i < sbIn->stmts_used; i++)
    {
      IRStmt *st;
      st = sbIn->stmts[i];
      switch (st->tag)
        {
        case Ist_IMark:
          {
            Addr64 cia = st->Ist.IMark.addr;
            Int isize = st->Ist.IMark.len;
            HChar buf[256];
            if (VG_ (get_fnname_if_entry)(cia, buf, 256))
              {
                VG_ (printf)("found fnname %s at %08x\n", buf, cia);
              }
          }
        }
      // VG_ (printf)("   pass  ");
      // ppIRStmt (st);
      // VG_ (printf)("\n");
    }
  // VG_ (printf)("sb ends\n");
  return sbIn;
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

  /* No needs, no core events to track */
}

VG_DETERMINE_INTERFACE_VERSION (gt_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
