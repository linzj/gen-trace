#include "ctrace.h"

int
main ()
{
  C_TRACE_0 ("test", "main");
  extern void run_test ();
  sleep(1);
  run_test ();
}
