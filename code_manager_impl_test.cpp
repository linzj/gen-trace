#include "code_manager_impl.h"
#include <assert.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <stdint.h>

int
main ()
{
  code_manager_impl *impl = new code_manager_impl ();
  assert (impl->new_context ("test") != 0);
  void *code = impl->new_code_mem (7);

  assert (code != NULL);
  intptr_t code_i = reinterpret_cast<intptr_t> (code);
  int count_to_new_page = (PAGE_SIZE - 7) / 7;
  const static intptr_t my_page_mask = ~(PAGE_SIZE - 1L);
  for (int i = 0; i < count_to_new_page; ++i)
    {
      void *code2 = impl->new_code_mem (7);
      intptr_t code2_i = reinterpret_cast<intptr_t> (code2);
      assert ((code2_i & my_page_mask) == code_i);
    }
  void *code2 = impl->new_code_mem (7);
  intptr_t code2_i = reinterpret_cast<intptr_t> (code2);
  assert ((code2_i & my_page_mask) != code_i);
}
