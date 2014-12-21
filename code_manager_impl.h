#ifndef CODE_MANAGER_IMPL_H
#define CODE_MANAGER_IMPL_H
#pragma once
#include <vector>
#include "code_modify.h"
class code_manager_impl : public code_manager
{
public:
  code_manager_impl ();
  ~code_manager_impl ();

  virtual code_context *new_context ();
  virtual void *new_code_mem (size_t s);

private:
  typedef std::vector<code_context *> context_vector;
  context_vector contexts_;
  typedef std::vector<void *> code_vector;
  code_vector codes_;
  // bytes left in the current page.
  size_t left_;
  // current page.
  char *current_page_;
};
#endif /* CODE_MANAGER_IMPL_H */
