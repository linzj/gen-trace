#include "config_reader.h"
#include <assert.h>

const char *test_lines[] = {
  "cc1\n", "\n", "00000000005d5030\n", "00000000000000b2\n",
  "find_attribute_namespace(char const*)\n", "00000000005644f0\n",
  "0000000000000015\n",
  "lookup_attribute(char const*, tree_node*) [clone .part.0]\n",
  "00000000005d50f0\n", "0000000000000250\n",
  "lookup_scoped_attribute_spec(tree_node const*, tree_node const*)\n",
  "00000000005d5440\n", "000000000000026a\n",
  "register_scoped_attribute(attribute_spec const*, scoped_attributes*)\n",
  "00000000005d5be0\n", "000000000000032f\n",
  "init_attributes() [clone .part.17]\n", "00000000005d74c0\n",
  "000000000000007e\n", "c_write_global_declarations_2(tree_node*)\n",
  "00000000005d7540\n", "00000000000000ca\n", "locate_old_decl(tree_node*)\n",
  "00000000005d7610\n", "00000000000000f8\n",
  "warn_about_goto(unsigned int, tree_node*, tree_node*)\n",
  "00000000005d7710\n", "0000000000000046\n",
  "layout_array_type(tree_node*)\n", "00000000005d7760\n",
  "0000000000000107\n",
  "make_label(unsigned int, tree_node*, bool, c_label_vars**)\n",
  "00000000005d7870\n", "00000000000000f4\n",
  "warn_defaults_to(unsigned int, int, char const*, ...)\n",
  "00000000005d7970\n", "00000000000000f3\n",
  "collect_all_refs(char const*)\n",
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
}
