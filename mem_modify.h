#ifndef MEM_MODIFY_H
#define MEM_MODIFY_H
#pragma once
struct mem_modify_instr
{
  void *where;
  int size;
  char data[1];
};

// returns number of instr executed
int mem_modify (const struct mem_modify_instr **instr, int count_of_instr);

#endif /* MEM_MODIFY_H */
