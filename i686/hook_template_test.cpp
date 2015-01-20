#include <stdio.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "log.h"

extern "C" {
extern void template_for_hook (void);
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

static void
add_jump_to_original (char *code_start, int offset)
{
  offset -= 5;
  //   3:	e8 00 00 00 00       	call   8 <foo()+0x8>
  //   8:	50                   	push   %eax
  //   9:	b8 12 ef cd ab       	mov    $0xabcdef12,%eax
  //   e:	01 44 24 04          	add    %eax,0x4(%esp)
  //  12:	8b 44 24 04          	mov    0x4(%esp),%eax
  //  16:	8b 00                	mov    (%eax),%eax
  //  18:	89 44 24 04          	mov    %eax,0x4(%esp)
  //  1c:	58                   	pop    %eax
  //  1d:	83 c4 04             	add    $0x4,%esp
  //  20:	ff 64 24 fc          	jmp    *-0x4(%esp)
  //  24:	5d                   	pop    %eb
  const char *instr = "\xe8\x00\x00\x00\x00\x50\xb8\x00\x00\x00\x00\x01\x44"
                      "\x24\x04\x8b\x44\x24\x04\x8b\x00\x89\x44\x24\x04\x58"
                      "\x83\xc4\x04\xff\x64\x24\xfc";
  memcpy (code_start, instr, 0x24 - 0x3);
  memcpy (code_start + 9 + 1 - 3, &offset, 4);
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
  static const int template_size = (char *)template_for_hook_end
                                   - (char *)template_for_hook;
  memcpy (&modify_pointer[4], (char *)template_for_hook, template_size);
  add_jump_to_original (static_cast<char *> (code_page) + template_size
                            + sizeof (intptr_t) * 4,
                        -(template_size + sizeof (intptr_t) * 2));
  typedef const char *(*pfn)(int a, int b, int c, int d, int e, int f, int g);
  pfn myfunc = (pfn)(&modify_pointer[4]);
  assert (0 == strcmp ((*myfunc)(0, 1, 2, 3, 4, 5, 6), "nimabi"));
  return 0;
}
