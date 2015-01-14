#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include "code_modify.h"
#include "base_controller.h"
#include "log.h"

#if defined(__x86_64__)
static const char *test_lines[] = {
  "here\n", "0\n", "module start\n", "libbase_controller_test_lib.so\n",
  "0000000000000830\n", "349\n", "original_function\n", "module end\n",
};
#elif defined(__arm__)
static const char *test_lines[] = {
  "here\n", "0\n", "module start\n", "libbase_controller_test_lib.so\n",
  "c85\n", "348\n", "original_function\n", "module end\n",
};
static const char *test_lines2[] = {
  "herearm\n", "0\n", "module start\n", "libbase_controller_test_lib_arm.so\n",
  "c84\n", "564\n", "original_function\n", "module end\n",
};

class test_fp_line_client_arm : public fp_line_client
{
public:
  test_fp_line_client_arm () : now_ (0) {}

private:
  virtual const char *
  next_line ()
  {
    if (now_ == sizeof (test_lines2) / sizeof (test_lines2[0]))
      return NULL;
    return test_lines2[now_++];
  }
  int now_;
};
#endif

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

template <class line_client>
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
    return new line_client ();
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
ret_hook (const char *)
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
  void *handle = dlopen ("./libbase_controller_test_lib.so", RTLD_NOW);
  if (handle == NULL)
    {
      LOGE ("fails to open libbase_controller_test_lib %s\n", dlerror ());
      return 1;
    }
  typedef char *(*pfn_original_function)(int a, int b, int c, int d, int e,
                                         int f, int g);
  pfn_original_function original_function
      = (pfn_original_function)dlsym (handle, "original_function");
  test_base_controller<test_fp_line_client> controller (hook, ret_hook);
  controller.do_it ();
  const char *ret = original_function (0, 1, 2, 3, 4, 5, 6);
  assert (strcmp (ret, "nimabi") == 0);
  char *data = (char *)original_function;
  data -= 1;
  LOGI ("%x %x %x %x\n", data[0], data[1], data[2], data[3]);

#ifdef __arm__
  {
    void *handle = dlopen ("./libbase_controller_test_lib_arm.so", RTLD_NOW);
    if (handle == NULL)
      {
        LOGE ("fails to open libbase_controller_test_lib %s\n", dlerror ());
        return 1;
      }
    typedef char *(*pfn_original_function)(int a, int b, int c, int d, int e,
                                           int f, int g);
    pfn_original_function original_function
        = (pfn_original_function)dlsym (handle, "original_function");
    LOGI ("checkout function %p\n", original_function);
    test_base_controller<test_fp_line_client_arm> controller (hook, ret_hook);
    errno = 0;
    controller.do_it ();
    const char *ret = original_function (0, 1, 2, 3, 4, 5, 6);
    assert (strcmp (ret, "nimabi") == 0);
    char *data = (char *)original_function;
    LOGI ("%x %x %x %x\n", data[0], data[1], data[2], data[3]);
  }
#endif
  return 0;
}
