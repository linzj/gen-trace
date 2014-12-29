#include "config_reader.h"
#include <assert.h>
#include <stdlib.h>

static const char *test_lines[] = {
  "here\n", "0\n", "module start\n", "cc1\n", "0000000000eed1e0\n", "78\n",
  "gen_lroundxfhi2(rtx_def*, rtx_def*)\n", "0000000000ac0ee0\n", "94\n",
  "debug_av_set(_list_node*)\n", "00000000009da940\n", "337\n",
  "lto_input_tree_ref(lto_input_block*, data_in*, function*, LTO_tags)\n",
  "00000000010c2850\n", "48\n", "double_int::neg_with_overflow(bool*) const\n",
  "00000000011d4280\n", "79\n", "fcache::fcache()\n", "0000000001253d80\n",
  "26\n", "std::money_get<wchar_t, std::istreambuf_iterator<wchar_t, "
          "std::char_traits<wchar_t> > >::money_get(unsigned long)\n",
  "00000000007584c0\n", "718\n", "convert_to_fixed(tree_node*, tree_node*)\n",
  "0000000000d620c0\n", "665\n", "expr_align(tree_node const*)\n",
  "0000000000d59410\n", "63\n",
  "bool wi::lts_p<generic_wide_int<fixed_wide_int_storage<384> >, "
  "generic_wide_int<fixed_wide_int_storage<384> > "
  ">(generic_wide_int<fixed_wide_int_storage<384> > const&, "
  "generic_wide_int<fixed_wide_int_storage<384> > const&)\n",
  "00000000010ca400\n", "124\n",
  "single_def_use_dom_walker::after_dom_children(basic_block_def*)\n",
  "0000000001250170\n", "255\n",
  "long std::__copy_streambufs_eof<wchar_t, std::char_traits<wchar_t> "
  ">(std::basic_streambuf<wchar_t, std::char_traits<wchar_t> >*, "
  "std::basic_streambuf<wchar_t, std::char_traits<wchar_t> >*, bool&)\n",
  "0000000000748460\n", "113\n",
  "compute_call_stmt_bb_frequency(tree_node*, basic_block_def*)\n",
  "0000000001160aa0\n", "623\n", "remove_from_deps(deps_desc*, rtx_insn*)\n",
  "0000000000cbeba0\n", "204\n", "fuck_2", "module end\n", "module start\n",
  "cc2\n", "0000000000eed1e0\n", "78\n",
  "gen_lroundxfhi2(rtx_def*, rtx_def*)\n", "0000000000ac0ee0\n", "94\n",
  "debug_av_set(_list_node*)\n", "00000000009da940\n", "337\n",
  "lto_input_tree_ref(lto_input_block*, data_in*, function*, LTO_tags)\n",
  "00000000010c2850\n", "48\n", "double_int::neg_with_overflow(bool*) const\n",
  "00000000011d4280\n", "79\n", "fcache::fcache()\n", "0000000001253d80\n",
  "26\n", "std::money_get<wchar_t, std::istreambuf_iterator<wchar_t, "
          "std::char_traits<wchar_t> > >::money_get(unsigned long)\n",
  "00000000007584c0\n", "718\n", "convert_to_fixed(tree_node*, tree_node*)\n",
  "0000000000d620c0\n", "665\n", "expr_align(tree_node const*)\n",
  "0000000000d59410\n", "63\n",
  "bool wi::lts_p<generic_wide_int<fixed_wide_int_storage<384> >, "
  "generic_wide_int<fixed_wide_int_storage<384> > "
  ">(generic_wide_int<fixed_wide_int_storage<384> > const&, "
  "generic_wide_int<fixed_wide_int_storage<384> > const&)\n",
  "00000000010ca400\n", "124\n",
  "single_def_use_dom_walker::after_dom_children(basic_block_def*)\n",
  "0000000001250170\n", "255\n",
  "long std::__copy_streambufs_eof<wchar_t, std::char_traits<wchar_t> "
  ">(std::basic_streambuf<wchar_t, std::char_traits<wchar_t> >*, "
  "std::basic_streambuf<wchar_t, std::char_traits<wchar_t> >*, bool&)\n",
  "0000000000748460\n", "113\n",
  "compute_call_stmt_bb_frequency(tree_node*, basic_block_def*)\n",
  "0000000001160aa0\n", "623\n", "remove_from_deps(deps_desc*, rtx_insn*)\n",
  "0000000000cbeba0\n", "204\n", "fuck_2", "module end\n"
};

int
main ()
{
  config_reader r;
  for (size_t i = 0; i < sizeof (test_lines) / sizeof (test_lines[0]); ++i)
    {
      r.handle_line (test_lines[i]);
    }
  config_desc *desc = r.accumulate ();
  assert (desc);
  assert (desc->num_of_modules == 2);
  free (desc);
}
