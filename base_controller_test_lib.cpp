#include "log.h"
#include <assert.h>
extern "C" {
const char *original_function (int a, int b, int c, int d, int e, int f, int g)
    __attribute__ ((visibility ("default")));
}

const char *
original_function (int a, int b, int c, int d, int e, int f, int g)
{
  LOGI ("original_function\n");
  LOGI ("original_function %d, %d, %d, %d, %d, %d, %d, %d\n", a, b, c, d, e, f,
        g);
  assert (a == 0);
  assert (b == 1);
  assert (c == 2);
  assert (d == 3);
  assert (e == 4);
  assert (f == 5);
  assert (g == 6);
  return "nimabi";
}
