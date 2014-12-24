#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H
class dis_client;
class disassembler
{
public:
  virtual ~disassembler ();
  virtual void set_client (dis_client *client) = 0;
  virtual int instruction_decode (char *start) = 0;
};
#endif /* DISASSEMBLER_H */
