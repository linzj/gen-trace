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
#ifdef __thumb__
extern void template_for_hook_thumb (void);
extern void template_for_hook_thumb_end (void);
#else
extern void template_for_hook_arm (void);
extern void template_for_hook_arm_end (void);
#endif
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

static void
add_jump_to_original (char *code_start, int offset, bool is_thumb)
{
  if (is_thumb)
    {
      uint16_t *data = reinterpret_cast<uint16_t *> (code_start);
      data[0] = 0xf85f;
      offset -= 4;
      offset = -offset;
      LOGI ("offset = %d\n", offset);
      data[1] = ((0xf) << 12) | offset;
    }
  else
    {
      uint32_t *data = reinterpret_cast<uint32_t *> (code_start);
      offset -= 8;
      offset = -offset;
      LOGI ("offset = %d\n", offset);
      data[0] = 0xe51ff000 | offset;
    }
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
  char *template_for_hook_end = (char *)template_for_hook_thumb_end;
  char *template_for_hook = (char *)template_for_hook_thumb;
  bool is_thumb = true;
#else
  char *template_for_hook_end = (char *)template_for_hook_arm_end;
  char *template_for_hook = (char *)template_for_hook_arm;
  bool is_thumb = false;
#endif
  static const int template_size = (char *)template_for_hook_end
                                   - (char *)template_for_hook;
  intptr_t template_for_hook_addr = ((intptr_t)template_for_hook) & ~1UL;
  memcpy (&modify_pointer[4], (char *)template_for_hook_addr, template_size);
  add_jump_to_original (static_cast<char *> (code_page) + template_size
                            + sizeof (intptr_t) * 4,
                        -(template_size + sizeof (intptr_t) * 2), is_thumb);
  typedef const char *(*pfn)(int a, int b, int c, int d, int e, int f, int g);
  intptr_t myfunc1 = reinterpret_cast<intptr_t> (&modify_pointer[4]);
  if (is_thumb)
    myfunc1 += 1;
  pfn myfunc = (pfn)myfunc1;
  flush_code (code_page, template_size);
  printf ("linzj::template_for_hook is %p\n", template_for_hook);
  assert (0 == strcmp ((*myfunc)(0, 1, 2, 3, 4, 5, 6), "nimabi"));
  return 0;
}
