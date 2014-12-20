#ifndef DIS_CLIENT_H
#define DIS_CLIENT_H
class dis_client
{
public:
  virtual ~dis_client ();
  virtual void on_instr (const char *) = 0;
};
#endif /* DIS_CLIENT_H */
