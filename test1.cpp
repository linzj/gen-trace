#include "ctrace.h"

void
run_test ()
{
  C_TRACE_0 ("test", "run_test");
  sleep (1);
}
