#include <new>
#include "ctrace.h"

extern "C" {
extern void __start_ctrace__ (void *c, const char *name);
extern void __end_ctrace__ (CTrace *c, const char *name);
}

void
__start_ctrace__ (void *c, const char *name)
{
  new (c) CTrace ("profile", name);
}

void
__end_ctrace__ (CTrace *c, const char *name)
{
  c->~CTrace ();
}
