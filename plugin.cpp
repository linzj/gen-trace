#include "gcc-plugin.h"
#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tm.h"
#include "tree.h"
#include "tree-pass.h"
#include "tree-cfg.h"
#include "function.h"
#include "gimple-expr.h"

#include "langhooks.h"
#include "timevar.h"
#include "dumpfile.h"
#include "target.h"
#include "df.h"
#include "tree-ssa-alias.h"
#include "pointer-set.h"
#include "internal-fn.h"
#include "is-a.h"
#include "gimple.h"
#include "gimple-ssa.h"

static struct pass_data mypass = {
  GIMPLE_PASS,              /* type */
  "gen_trace",              /* name */
  OPTGROUP_NONE,            /* optinfo_flags */
  false,                    /* has_gate */
  true,                     /* has_execute */
  TV_NONE,                  /* tv_id */
  PROP_gimple_any,          /* properties_required */
  0,                        /* properties_provided */
  0,                        /* properties_destroyed */
  TODO_mark_first_instance, /* todo_flags_start */
  0,                        /* todo_flags_finish */
};
extern gcc::context *g;
int plugin_is_GPL_compatible;

static unsigned int
execute_trace ()
{
  gimple_seq body, cleanup;
  gimple_statement_try *gtry;

  body = gimple_body (current_function_decl);
  cleanup = NULL;
  gtry = gimple_build_try (body, cleanup, GIMPLE_TRY_FINALLY);
  gimple_set_body (current_function_decl, gtry);
  dump_function_to_file (current_function_decl, stderr,
                         TDF_TREE | TDF_BLOCKS | TDF_VERBOSE);
  exit (0);
}

class trace_pass : public gimple_opt_pass
{
public:
  trace_pass (pass_data &mydata, gcc::context *context)
      : gimple_opt_pass (mydata, context)
  {
  }
  unsigned int
  execute ()
  {
    return execute_trace ();
  }
};

int
plugin_init (struct plugin_name_args *plugin_info,
             struct plugin_gcc_version *version)
{
  struct register_pass_info pass_info
      = { new trace_pass (mypass, g), "omplower", 1, PASS_POS_INSERT_BEFORE };

  /* Code to fill in the pass_info object with new pass information.  */

  /* Register the new pass.  */
  register_callback (plugin_info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL,
                     &pass_info);
  return 0;
}
