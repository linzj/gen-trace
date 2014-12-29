#ifndef BASE_CONTROLLER_H
#define BASE_CONTROLLER_H
#include <stdint.h>
class config_desc;
class config_module;

class fp_line_client
{
public:
  virtual ~fp_line_client ();
  virtual const char *next_line () = 0;
};

class base_controller
{
public:
  base_controller (pfn_called_callback called_callback,
                   pfn_ret_callback return_callback);
  virtual ~base_controller ();

  virtual fp_line_client *open_line_client () = 0;
  virtual void destroy_line_client (fp_line_client *) = 0;
  void do_it ();
  void retain ();
  void detain ();

private:
  void do_rest_with_config (config_desc *desc);
  config_desc *fill_config (fp_line_client *);
  intptr_t find_base (config_module *);
  bool should_add_base_to_sym_base (intptr_t module_base);
  void do_modify (config_desc *);
  bool is_base_elf (intptr_t base);
  static void *thread_worker (void *);

  pfn_called_callback called_callback_;
  pfn_ret_callback return_callback_;
  config_desc *config_desc_;
  int ref_count_;
};
#endif /* BASE_CONTROLLER_H */
