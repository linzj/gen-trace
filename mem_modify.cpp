#include "mem_modify.h"
#include "log.h"

#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>

#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

static int
modify (const struct mem_modify_instr **instr, int count_of_instr)
{
  int ptraceret;
  int status;
  int count = 0;

  pid_t target_pid = getppid ();
  ptraceret = ptrace (PTRACE_ATTACH, target_pid, 0, 0);
  if (ptraceret == -1)
    {
      LOGE ("ptrace attach fails %s\n", strerror (errno));
      return 0;
    }

  waitpid (target_pid, &status, __WALL);
  for (int i = 0; i < count_of_instr; ++i)
    {
      int count_for_long = instr[i]->size / sizeof (long);
      int left = instr[i]->size % sizeof (long);
      const char *data = &instr[i]->data[0];
      const char *where = static_cast<const char *> (instr[i]->where);
      int j;
      for (j = 0; j < count_for_long;
           ++j, data += sizeof (long), where += sizeof (long))
        {
          long ptr_size_data;
          memcpy (&ptr_size_data, data, sizeof (long));
          if (-1 == ptrace (PTRACE_POKEDATA, target_pid, where, ptr_size_data))
            {
              LOGE ("ptrace poke data fails %s\n", strerror (errno));
              break;
            }
        }
      if (j != count_for_long)
        continue;
      long left_data = ptrace (PTRACE_PEEKDATA, target_pid, where, 0);
      if (left_data == -1 && errno)
        {
          LOGE ("ptrace peek data fails %s\n", strerror (errno));
          continue;
        }

      for (j = 0; j < left; ++j)
        {
          long _data = data[j] & 0xff;
          long mask = 0xff;
          _data <<= j * 8;
          mask <<= j * 8;
          mask = ~mask;
          left_data = (left_data & mask) | _data;
        }
      if (-1 == ptrace (PTRACE_POKEDATA, target_pid, where, left_data))
        {
          LOGE ("ptrace peek data (left) fails %s\n", strerror (errno));
          continue;
        }
      count++;
    }
  ptrace (PTRACE_DETACH, target_pid, 0, 0);
  return count;
}

int
mem_modify (const struct mem_modify_instr **instr, int count_of_instr)
{
  pid_t forkret;
  int sv[2];

  if (-1 == socketpair (AF_UNIX, SOCK_STREAM, 0, sv))
    {
      LOGE ("pipe fails %s\n", strerror (errno));
      return 0;
    }
  forkret = fork ();

  if (forkret > 0)
    {
      int status;
      int num = 0;
#ifdef PR_SET_PTRACER
      int ptrctlret = prctl (PR_SET_PTRACER, forkret, 0, 0, 0);
      int writeret;
      int readret;
      do
        {
          writeret = write (sv[0], &ptrctlret, sizeof (ptrctlret));
        }
      while (writeret == -1 && errno == EINTR);
      if (ptrctlret == -1)
        {
          LOGE ("ptrctl fails %s\n", strerror (errno));
          close (sv[1]);
          goto fails;
        }
#endif
      close (sv[1]);

      do
        {
          readret = read (sv[0], &num, sizeof (num));
        }
      while (readret == -1 && errno == EINTR);
    fails:
      close (sv[0]);
      waitpid (forkret, &status, 0);
      return num;
    }
  else if (forkret == 0)
    {
#ifdef PR_SET_PTRACER
      int val;
      int readret;
      int writeret;
      do
        {
          readret = read (sv[1], &val, sizeof (val));
        }
      while (readret == -1 && errno == EINTR);
      if (val == -1)
        {
          _exit (0);
        }
#endif
      close (sv[0]);
      int num = modify (instr, count_of_instr);
      do
        {
          writeret = write (sv[1], &num, sizeof (num));
        }
      while (writeret == -1 && errno == EINTR);
      close (sv[1]);
      _exit (0);
    }
  else
    {
      LOGE ("fork fails %s\n", strerror (errno));
      return 0;
    }
  return 0;
}
