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
#include "internal-fn.h"
#include "is-a.h"
#include "gimple.h"
#include "gimple-ssa.h"
#include "stringpool.h"
#include "gimplify.h"
#include "gimple-iterator.h"
#define CTRACE_THREAD_SUPPORTED
#include "ctrace.h"

extern void print_generic_decl (FILE *file, tree decl, int flags);
extern void print_node (FILE *file, const char *prefix, tree node, int indent);
extern void print_generic_stmt (FILE *file, tree t, int flags);

static struct pass_data mypass = {
  GIMPLE_PASS,              /* type */
  "gen_trace",              /* name */
  OPTGROUP_NONE,            /* optinfo_flags */
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

  i_type = build_index_type (size_int (sizeof (CTrace) - 1));
  a_type = build_array_type (char_type_node, i_type);
  field_decl = build_decl (UNKNOWN_LOCATION, FIELD_DECL, NULL_TREE, a_type);
  TYPE_FIELDS (ret_type) = field_decl;
  TYPE_SIZE_UNIT (ret_type)
      = build_int_cst (integer_type_node, sizeof (CTrace));
  TYPE_NAME (ret_type) = get_identifier ("__CtraceStruct__");
  if (dump_file)
    {
      fprintf (dump_file, "begin print built type:\n");
      print_generic_stmt (dump_file, ret_type, TDF_VERBOSE);
      fprintf (dump_file, "end print built type:\n");
    }
  return ret_type;
}

static tree
build_function_decl (const char *name, tree param_type)
{
  tree func_decl, function_type_list;

  function_type_list = build_function_type_list (
      void_type_node, build_pointer_type (param_type),
      build_pointer_type (build_type_variant (char_type_node, true, false)),
      NULL_TREE);
  func_decl = build_decl (UNKNOWN_LOCATION, FUNCTION_DECL,
                          get_identifier (name), function_type_list);
  if (dump_file)
    {
      fprintf (dump_file, "begin print built function type %s:\n", name);
      print_generic_decl (dump_file, func_decl, TDF_VERBOSE);
      fprintf (dump_file, "end print built function type %s:\n", name);
    }
  TREE_USED (func_decl) = 1;

  return func_decl;
}

static tree
make_fname_decl ()
{
  const char *name = lang_hooks.decl_printable_name (current_function_decl, 0);
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
  DECL_READ_P (decl) = 1;
  DECL_INITIAL (decl) = init;

  TREE_USED (decl) = 1;
  TREE_ADDRESSABLE (decl) = 1;
  DECL_CONTEXT (decl) = current_function_decl;

  return decl;
}

static unsigned int
execute_trace ()
{
  gimple_seq body, body_bind_body, inner_cleanup, outer_cleanup;
  gimple inner_try, outer_try;
  tree record_type, func_start_decl, func_end_decl, var_decl,
      function_name_decl, constructor_clobber;
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
  DECL_CONTEXT (var_decl) = current_function_decl;
  TREE_ADDRESSABLE (var_decl) = 1;
  declare_vars (var_decl, body, false);
  TREE_USED (var_decl) = 1;
  // mimic __FUNCTION__ builtin.
  function_name_decl = make_fname_decl ();
  declare_vars (function_name_decl, body, false);
  // construct inner try
  // init calls
  call_func_start = gimple_build_call (
      func_start_decl, 2,
      build1 (ADDR_EXPR, build_pointer_type (record_type), var_decl),
      build1 (ADDR_EXPR, build_pointer_type (TREE_TYPE (function_name_decl)),
              function_name_decl));
  // make inner clean up
  inner_cleanup = gimple_build_call (
      func_end_decl, 2,
      build1 (ADDR_EXPR, build_pointer_type (record_type), var_decl),
      build1 (ADDR_EXPR, build_pointer_type (TREE_TYPE (function_name_decl)),
              function_name_decl));
  // update inner try
  body_bind_body = gimple_bind_body (body);
  inner_try
      = gimple_build_try (body_bind_body, inner_cleanup, GIMPLE_TRY_FINALLY);
  gsi = gsi_start (inner_try);
  gsi_insert_before (&gsi, call_func_start, GSI_NEW_STMT);
  // construct outer try
  constructor_clobber = make_node (CONSTRUCTOR);
  TREE_THIS_VOLATILE (constructor_clobber) = 1;
  TREE_TYPE (constructor_clobber) = TREE_TYPE (var_decl);
  outer_cleanup = gimple_build_assign (var_decl, constructor_clobber);
  // update outer try
  outer_try
      = gimple_build_try (call_func_start, outer_cleanup, GIMPLE_TRY_FINALLY);
  // update body bind body
  gimple_bind_set_body (body, outer_try);
  if (dump_file)
    {
      dump_function_to_file (current_function_decl, dump_file,
                             TDF_TREE | TDF_BLOCKS | TDF_VERBOSE);
    }
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

  virtual bool
  gate (function *)
  {
    return true;
  }
  unsigned int
  execute (function *)
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
