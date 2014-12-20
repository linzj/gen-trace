#include "mem_modify.h"
#include <assert.h>
#include <stdlib.h>
#include <vector>
#include <memory.h>
#include "log.h"

typedef std::vector<struct mem_modify_instr *> instr_vector;
static void
clearV (instr_vector &v)
{
  for (instr_vector::iterator i = v.begin (); i != v.end (); ++i)
    {
      free (*i);
    }
  v.clear ();
}

static void
test (int n)
{
  char target[16];
  const char *t = "123456789";

  instr_vector v;
  {
    mem_modify_instr *to_fill = static_cast<mem_modify_instr *> (
        malloc (sizeof (mem_modify_instr) + n));
    to_fill->where = &target[0];
    to_fill->size = n;
    memcpy (to_fill->data, t, n);
    v.push_back (to_fill);
    int count = mem_modify (
        const_cast<const struct mem_modify_instr **> (v.data ()), v.size ());
    clearV (v);
    assert (count == 1);
    LOGI ("n = %d\n", n);
    LOGI ("target = ");
    for (int i = 0; i < n; ++i)
      {
        LOGI ("%c, ", target[i]);
      }
    LOGI ("\n");
    assert (memcmp (target, t, n) == 0);
  }
}

int
main ()
{
  for (int i = 0; i < 9; ++i)
    {
      test (i + 1);
    }
}
