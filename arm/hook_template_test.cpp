#include <stdio.h>
#include <assert.h>
#include <sys/mman.h>
#ifndef __ANDROID__
#include <sys/user.h>
#else
#include <asm/user.h>
#endif // __ANDROID__
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "log.h"
#include "flush_code.h"

extern "C" {
extern void template_for_hook (void);
#ifdef __thumb__
extern void template_for_hook_thumb_ret (void);
#else
extern void template_for_hook_arm_ret (void);

#endif
extern void template_for_hook_end (void);
}

static void *g_original_ret;

static void
hook (void *original_ret, const char *name)
{
  g_original_ret = original_ret;
  LOGI ("hook called %s\n", name);
}

static void *
ret_hook (void)
{
  assert (g_original_ret != NULL);
  LOGI ("ret_hook called\n");
  return g_original_ret;
}

static const char *
original_function (int a, int b, int c, int d, int e, int f, int g)
{
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

int
main ()
{
  void *code_page = mmap (NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (code_page == MAP_FAILED)
    {
      LOGI ("mmap failed %s\n", strerror (errno));
      exit (1);
    }
  void **modify_pointer
      = reinterpret_cast<void **> (static_cast<char *> (code_page));
  modify_pointer[0]
      = reinterpret_cast<void *> (const_cast<char *> ("wocaonimabi"));
  modify_pointer[1] = reinterpret_cast<void *> (hook);
  modify_pointer[2] = reinterpret_cast<void *> (original_function);
  modify_pointer[3] = reinterpret_cast<void *> (ret_hook);
#ifdef __thumb__
  char *template_for_hook2 = (char *)template_for_hook_thumb_ret;
#else
  char *template_for_hook2 = (char *)template_for_hook_arm_ret;
#endif
  static const int template_size2 = (char *)template_for_hook_end
                                    - (char *)template_for_hook2;
  static const int template_size1 = (char *)template_for_hook2
                                    - (char *)template_for_hook;
  intptr_t template_for_hook_addr = ((intptr_t)template_for_hook) & -2;
  memcpy (&modify_pointer[4], (char *)template_for_hook_addr, template_size1 + template_size2);
  // memcpy ((char *)&modify_pointer[4] + template_size1,
  //         (char *)template_for_hook2, template_size2);
  typedef const char *(*pfn)(int a, int b, int c, int d, int e, int f, int g);
  intptr_t myfunc1 = reinterpret_cast<intptr_t> (&modify_pointer[4]);
  myfunc1 += 1;
  pfn myfunc = (pfn)myfunc1;
  flush_code (code_page, template_size2 + template_size1);
  printf ("linzj::template_for_hook is %p, template_for_hook2 is %p\n",
          template_for_hook, template_for_hook2);
  assert (0 == strcmp ((*myfunc)(0, 1, 2, 3, 4, 5, 6), "nimabi"));
  return 0;
}
