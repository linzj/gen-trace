#include <stddef.h>
#include "base_controller.h"

static const char *test_lines[] = {
  "base_controller_test\n", "\n", "000000000000fbac\n", "000000000000008b\n",
  "main\n",
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
  test_base_controller (void *called_callback, void *return_callback)
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

int
main ()
{
  test_base_controller controller ((void *)main, (void *)main);
  controller.do_it ();
  return 0;
}
