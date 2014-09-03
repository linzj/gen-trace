#include "ctrace.h"

int
main ()
{
  C_TRACE_0 ("test", "main");
  extern void run_test ();
  run_test ();
}
