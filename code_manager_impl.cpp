#include <stdlib.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <string.h>
#include <errno.h>

#include "log.h"
#include "code_manager_impl.h"

code_manager::~code_manager () {}

code_manager_impl::code_manager_impl () : left_ (0), current_page_ (NULL) {}
code_manager_impl::~code_manager_impl () {}

code_context *
code_manager_impl::new_context ()
{
  code_context *new_context
      = static_cast<code_context *> (calloc (1, sizeof (code_context)));
  if (!new_context)
    return new_context;
  contexts_.push_back (new_context);
  return new_context;
}

void *
code_manager_impl::new_code_mem (size_t s)
{
  if (current_page_ && left_ >= s)
    {
      void *ret = current_page_;
      current_page_ += s;
      left_ -= s;
      return ret;
    }
  else
    {
      void *new_page
          = mmap (NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (new_page == MAP_FAILED)
        {
          LOGE ("mmap fails %s\n", strerror (errno));
          return NULL;
        }
      current_page_ = static_cast<char *> (new_page);
      left_ = PAGE_SIZE;
      codes_.push_back (new_page);
      return new_code_mem (s);
    }
  return NULL;
}
