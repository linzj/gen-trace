#ifndef DIS_CLIENT_H
#define DIS_CLIENT_H
#include <stddef.h>
#include <stdint.h>
class dis_client
{
public:
  virtual ~dis_client ();
  virtual void on_instr (const char *, char *start, size_t s) = 0;
  virtual void on_addr (intptr_t) = 0;
  virtual bool is_accept () = 0;
};

class check_code_dis_client : public dis_client
{
public:
  virtual int lowered_original_code_len (int code_len_to_replace) = 0;
  virtual size_t extend_buffer_size () = 0;
  virtual void fill_buffer (void *) = 0;
};
#endif /* DIS_CLIENT_H */
