#include "ctrace.h"

static void
test1 ()
{
  C_TRACE_0 ("test", "test1");
  sleep (1);
}

static void
test2 ()
{
  C_TRACE_0 ("test", "test2");
  sleep (2);
}

void
run_test ()
{
  C_TRACE_0 ("test", "run_test");
  test1 ();
  sleep (3);
  test2 ();
}
