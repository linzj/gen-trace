#define CTRACE_THREAD_SUPPORTED
#include "ctrace.h"

static void *
thread_start (void *)
{
  C_TRACE_0 ("test", __FUNCTION__);
  sleep (1);
}

int
main ()
{
  C_TRACE_0 ("test", __FUNCTION__);
  pthread_t t1, t2, t3;

  sleep (1);
  pthread_create (&t1, NULL, thread_start, NULL);
  sleep (1);
  pthread_create (&t2, NULL, thread_start, NULL);
  pthread_create (&t3, NULL, thread_start, NULL);
  pthread_join (t1, NULL);
  pthread_detach (t1);
  pthread_join (t2, NULL);
  pthread_detach (t2);
  pthread_join (t3, NULL);
  pthread_detach (t3);
  return 0;
}
