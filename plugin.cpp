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
#include "stringpool.h"
#include "gimplify.h"
#include "gimple-iterator.h"

#include "tree-pretty-print.h"

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

static tree
build_type ()
{
  tree ret_type, i_type, a_type, field_decl;
  ret_type = make_node (RECORD_TYPE);

  i_type = build_index_type (size_int (15));
  a_type = build_array_type (char_type_node, i_type);
  field_decl = build_decl (UNKNOWN_LOCATION, FIELD_DECL, NULL_TREE, a_type);
  TYPE_FIELDS (ret_type) = field_decl;
  TYPE_SIZE_UNIT (ret_type) = build_int_cst (integer_type_node, 16);
  TYPE_NAME (ret_type) = get_identifier ("__CtraceStruct__");
  fprintf (stderr, "begin print built type:\n");
  print_generic_decl (stderr, ret_type, 0);
  fprintf (stderr, "end print built type:\n");
  return ret_type;
}

static tree
build_function_decl (const char *name, tree param_type)
{
  tree func_decl, function_type_list;

  function_type_list = build_function_type_list (
      void_type_node, build_pointer_type (param_type),
      build_pointer_type (char_type_node), NULL_TREE);
  func_decl = build_decl (UNKNOWN_LOCATION, FUNCTION_DECL,
                          get_identifier (name), function_type_list);
  fprintf (stderr, "begin print built function type %s:\n", name);
  print_generic_decl (stderr, func_decl, 0);
  fprintf (stderr, "end print built function type %s:\n", name);
  TREE_USED (func_decl) = 1;

  return func_decl;
}

static tree
make_fname_decl ()
{
  const char *name = lang_hooks.decl_printable_name (current_function_decl, 2);
  tree decl, type, init;
  size_t length = strlen (name);

  type = build_array_type (build_type_variant (char_type_node, true, false),
                           build_index_type (size_int (length)));

  decl = build_decl (UNKNOWN_LOCATION, VAR_DECL,
                     get_identifier ("__function_name__"), type);

  TREE_STATIC (decl) = 1;
  TREE_READONLY (decl) = 1;
  DECL_ARTIFICIAL (decl) = 1;

  init = build_string (length + 1, name);
  TREE_TYPE (init) = type;
  TREE_READONLY (init) = 1;
  DECL_INITIAL (decl) = init;

  TREE_USED (decl) = 1;

  return decl;
}

static unsigned int
execute_trace ()
{
  gimple_seq body, body_bind_body, cleanup;
  gimple_statement_try *gtry;
  tree record_type, func_start_decl, func_end_decl, var_decl,
      function_name_decl;
  gimple call_func_start;
  gimple_stmt_iterator gsi;

  // build record type
  record_type = build_type ();
  // build start & end function decl
  func_start_decl = build_function_decl ("__start_ctrace__", record_type);
  func_end_decl = build_function_decl ("__end_ctrace__", record_type);
  // init variables of current body
  body = gimple_body (current_function_decl);

  var_decl = build_decl (UNKNOWN_LOCATION, VAR_DECL,
                         get_identifier ("__ctrace_var__"), record_type);
  declare_vars (var_decl, body, false);
  TREE_USED (var_decl) = 1;
  // mimic __FUNCTION__ builtin.
  function_name_decl = make_fname_decl ();
  declare_vars (function_name_decl, body, false);
  // add calls to body
  body_bind_body = gimple_bind_body (body);
  call_func_start = gimple_build_call (
      func_start_decl, 2,
      build1 (ADDR_EXPR, build_pointer_type (record_type), var_decl),
      build1 (ADDR_EXPR, build_pointer_type (TREE_TYPE (function_name_decl)),
              function_name_decl));
  gsi = gsi_start (body_bind_body);
  gsi_insert_before (&gsi, call_func_start, GSI_NEW_STMT);
  // make clean up
  cleanup = gimple_build_call (
      func_end_decl, 2,
      build1 (ADDR_EXPR, build_pointer_type (record_type), var_decl),
      build1 (ADDR_EXPR, build_pointer_type (TREE_TYPE (function_name_decl)),
              function_name_decl));
  gtry = gimple_build_try (body_bind_body, cleanup, GIMPLE_TRY_FINALLY);
  gimple_bind_set_body (body, gtry);
  // TODO:
  // make to:
  // try {
  // ...
  // }
  // finally {
  //  __ctrace_var__ = {clobber};
  // }
  dump_function_to_file (current_function_decl, stderr,
                         TDF_TREE | TDF_BLOCKS | TDF_VERBOSE);
  // exit (0);
  return 0;
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
