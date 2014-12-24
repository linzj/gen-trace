#ifndef DIS_CLIENT_H
#define DIS_CLIENT_H
#include <stdint.h>
class dis_client
{
public:
  virtual ~dis_client ();
  virtual void on_instr (const char *) = 0;
  virtual void on_addr (intptr_t) = 0;
  virtual bool is_accept () = 0;
};
#endif /* DIS_CLIENT_H */
