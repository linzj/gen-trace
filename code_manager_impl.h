#ifndef CODE_MANAGER_IMPL_H
#define CODE_MANAGER_IMPL_H
#pragma once
#include <vector>
#include <set>
#include "code_modify.h"
class code_manager_impl : public code_manager
{
public:
  code_manager_impl ();
  ~code_manager_impl ();

  virtual code_context *new_context (const char *function_name);
  virtual void *new_code_mem (void *hint, size_t s);

private:
  void *new_code_mem_no_hint (size_t s);
  enum query_status
  {
    query_okay,
    query_occupied,
    query_mincore_fail
  };
  query_status query (void *);
  typedef std::vector<code_context *> context_vector;
  context_vector contexts_;
  typedef std::vector<void *> code_vector;
  code_vector codes_;
  // bytes left in the current page.
  size_t left_;
  // current page.
  char *current_page_;
  std::set<void *> queried_;
};
#endif /* CODE_MANAGER_IMPL_H */
