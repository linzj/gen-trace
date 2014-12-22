#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "code_modify.h"
#include "base_controller.h"
#include "log.h"

static const char *test_lines[] = {
  "libbase_controller_test_lib.so\n", "\n", "00000000000007e0\n",
  "000000000000015d\n", "original_function\n",
};

class test_fp_line_client : public fp_line_client
{
public:
  test_fp_line_client () : now_ (0) {}

private:
  virtual const char *
  next_line ()
  {
    if (now_ == sizeof (test_lines) / sizeof (test_lines[0]))
      return NULL;
    return test_lines[now_++];
  }
  int now_;
};

class test_base_controller : public base_controller
{
public:
  test_base_controller (pfn_called_callback called_callback,
                        pfn_ret_callback return_callback)
      : base_controller (called_callback, return_callback)
  {
  }

private:
  virtual fp_line_client *
  open_line_client ()
  {
    return new test_fp_line_client ();
  }
  virtual void
  destroy_line_client (fp_line_client *c)
  {
    delete c;
  }
};

static void *g_original_ret;

static void
hook (void *original_ret, const char *name)
{
  g_original_ret = original_ret;

  LOGI ("hook called, %s\n", name);
}

static void *
ret_hook (void)
{
  assert (g_original_ret != NULL);
  LOGI ("ret_hook called\n");
  return g_original_ret;
}

extern "C" {
const char *original_function (int a, int b, int c, int d, int e, int f,
                               int g);
}

int
main ()
{
  test_base_controller controller (hook, ret_hook);
  controller.do_it ();
  const char *ret = original_function (0, 1, 2, 3, 4, 5, 6);
  assert (strcmp (ret, "nimabi") == 0);
  return 0;
}
