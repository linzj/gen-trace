#include "mem_modify.h"
#include "log.h"

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/prctl.h>

#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>

#ifndef __ANDROID__
#include <sys/syscall.h>
#define getdents(...) syscall (SYS_getdents, __VA_ARGS__)
#define dirent linux_dirent
struct linux_dirent
{
  long d_ino;
  off_t d_off;
  unsigned short d_reclen;
  char d_name[];
};

#endif

static bool
stop_conti_the_world (int pid, bool stop)
{
  char buf[256];
  snprintf (buf, 256, "/proc/%d/task", pid);
  int fd = open (buf, O_RDONLY | O_DIRECTORY);
  if (fd == -1)
    {
      return false;
    }
  struct dirent _DIR_buff[15];
  bool error = false;
  while (true)
    {
      int ret = getdents (fd, _DIR_buff, sizeof (_DIR_buff));
      if (ret <= 0)
        {
          break;
        }
      struct dirent *iterator = _DIR_buff;
      while (ret)
        {
          ret -= iterator->d_reclen;
          struct dirent *cur = iterator;
          iterator = reinterpret_cast<struct dirent *> (
              reinterpret_cast<char *> (iterator) + cur->d_reclen);
          if (cur->d_name[0] == '.' || cur->d_name[0] == '\0')
            {
              continue;
            }
          int cur_pid = static_cast<int> (strtoul (cur->d_name, NULL, 10));
          int ptraceret;
          if (stop)
            {
              int status;
              ptraceret = ptrace (PTRACE_ATTACH, cur_pid, 0, 0);

              if (ptraceret != -1)
                {
                  waitpid (cur_pid, &status, __WALL);
                }
              else if (cur_pid == pid)
                {
                  error = true;
                  LOGE ("ptrace attach fails for %d, %s\n", cur_pid,
                        strerror (errno));
                  snprintf (buf, 256, "/proc/%d/status", cur_pid);
                  FILE *f = fopen (buf, "r");
                  const char *str;
                  while ((str = fgets (buf, 256, f)) != NULL)
                    {
                      LOGE (str);
                    }
                  fclose (f);
                  break;
                }
            }
          else
            {
              ptrace (PTRACE_DETACH, cur_pid, 0, 0);
            }
        }
      if (error)
        break;
    }
  close (fd);
  return error != true;
}

static int
modify (const struct mem_modify_instr **instr, int count_of_instr)
{
  int count = 0;

  pid_t target_pid = getppid ();
  if (!stop_conti_the_world (target_pid, true))
    {
      return 0;
    }
  for (int i = 0; i < count_of_instr; ++i)
    {
      int count_for_long = instr[i]->size / sizeof (long);
      int left = instr[i]->size % sizeof (long);
      const char *data = &instr[i]->data[0];
      char *where = static_cast<char *> (instr[i]->where);
      int j;
      for (j = 0; j < count_for_long;
           ++j, data += sizeof (long), where += sizeof (long))
        {
          long ptr_size_data;
          memcpy (&ptr_size_data, data, sizeof (long));
          if (-1 == ptrace (PTRACE_POKEDATA, target_pid, where,
                            reinterpret_cast<void *> (ptr_size_data)))
            {
              LOGE ("ptrace poke data fails %s, %d\n", strerror (errno),
                    target_pid);
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
      if (-1 == ptrace (PTRACE_POKEDATA, target_pid, where,
                        reinterpret_cast<void *> (left_data)))
        {
          LOGE ("ptrace peek data (left) fails %s\n", strerror (errno));
          continue;
        }
      count++;
    }
  stop_conti_the_world (target_pid, false);
  return count;
}

static int
mem_modify_1 (const struct mem_modify_instr **instr, int count_of_instr)
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
      int readret;
#ifdef PR_SET_PTRACER
      int ptrctlret = prctl (PR_SET_PTRACER, forkret, 0, 0, 0);
      int errno_ptrctl = errno;
      int writeret;
      do
        {
          writeret = write (sv[0], &ptrctlret, sizeof (ptrctlret));
        }
      while (writeret == -1 && errno == EINTR);
      if (ptrctlret == -1)
        {
          LOGE ("ptrctl fails %s\n", strerror (errno_ptrctl));
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
#ifdef PR_SET_PTRACER
    fails:
#endif
      close (sv[0]);
      waitpid (forkret, &status, 0);
      return num;
    }
  else if (forkret == 0)
    {
      int writeret;
#ifdef PR_SET_PTRACER
      int val;
      int readret;
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

int
mem_modify (const struct mem_modify_instr **instr, int count_of_instr)
{
#ifdef USE_DUMPABLE
#undef USE_DUMPABLE
#endif // USE_DUMPABLE
#if defined(PR_GET_DUMPABLE) && defined(PR_SET_DUMPABLE)
#define USE_DUMPABLE
#endif // defined(PR_GET_DUMPABLE) && defined(PR_SET_DUMPABLE)
#ifdef USE_DUMPABLE
  int old_dumpable = prctl (PR_GET_DUMPABLE, 0, 0, 0, 0);
  if (old_dumpable < 0)
    {
      LOGE ("fails get dumpable: %s\n", strerror (errno));
      return 0;
    }
  if (-1 == prctl (PR_SET_DUMPABLE, 1, 0, 0, 0))
    {
      LOGE ("fails set dumpable: %s\n", strerror (errno));
      return 0;
    }
#endif // USE_DUMPABLE

  int ret = mem_modify_1 (instr, count_of_instr);
#ifdef USE_DUMPABLE
  if (-1 == prctl (PR_SET_DUMPABLE, old_dumpable, 0, 0, 0))
    {
      LOGE ("fails restore dumpable: %s\n", strerror (errno));
    }
#endif // USE_DUMPABLE
  return ret;
}
