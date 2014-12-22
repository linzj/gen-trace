#ifndef BASE_CONTROLLER_H
#define BASE_CONTROLLER_H
#include <stdint.h>
class config_desc;

class fp_line_client
{
public:
  virtual ~fp_line_client ();
  virtual const char *next_line () = 0;
};

class base_controller
{
public:
  base_controller (void *called_callback, void *return_callback);
  virtual ~base_controller ();

  virtual fp_line_client *open_line_client () = 0;
  virtual void destroy_line_client (fp_line_client *) = 0;
  void do_it ();

private:
  void do_rest_with_config (config_desc *desc);
  config_desc *fill_config (fp_line_client *);
  intptr_t find_base (config_desc *);
  bool should_add_base_to_sym_base (intptr_t module_base);
  void do_modify (config_desc *);
  bool is_base_elf (intptr_t base);

  void *called_callback_;
  void *return_callback_;
};
#endif /* BASE_CONTROLLER_H */
