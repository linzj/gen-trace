#include "code_modify.h"
#include "base_controller.h"
#include "log.h"
#include <memory>
#include <fstream>
#include <string>

extern "C" {
extern void __start_ctrace__ (void *original_ret, const char *name);
extern void *__end_ctrace__ (const char *);
}

namespace
{
class my_fp_line_client : public fp_line_client
{
public:
  my_fp_line_client (std::auto_ptr<std::ifstream> file);
  ~my_fp_line_client ();

private:
  virtual const char *next_line ();
  std::string line_buf_;
  std::auto_ptr<std::ifstream> file_;
};

my_fp_line_client::my_fp_line_client (std::auto_ptr<std::ifstream> file)
    : file_ (file)
{
}

my_fp_line_client::~my_fp_line_client () {}

const char *
my_fp_line_client::next_line ()
{
  if (!*file_)
    {
      return NULL;
    }
  line_buf_.clear ();
  std::getline (*file_, line_buf_);
  return line_buf_.c_str ();
}

class file_controller : public base_controller
{
public:
  file_controller (pfn_called_callback f1, pfn_ret_callback f2);

private:
  virtual fp_line_client *open_line_client ();
  virtual void destroy_line_client (fp_line_client *);
};

fp_line_client *
file_controller::open_line_client ()
{
#ifndef __ANDROID__
#define TRACE_FILE "./trace.config"
#else
#define TRACE_FILE "/sdcard/trace.config"
#endif
  std::auto_ptr<std::ifstream> file (new std::ifstream (TRACE_FILE));
  if (!*file)
    {
      return NULL;
    }
  return new my_fp_line_client (file);
}

void
file_controller::destroy_line_client (fp_line_client *fp)
{
  delete fp;
}
file_controller::file_controller (pfn_called_callback f1, pfn_ret_callback f2)
    : base_controller (f1, f2)
{
}
class init
{
public:
  init ();
  static void *init_worker (void *);
};
file_controller *g_controller;
init::init () { init_worker (NULL); }
void *
init::init_worker (void *)
{
  g_controller = new file_controller (__start_ctrace__, __end_ctrace__);
  g_controller->do_it ();
  g_controller->detain ();
  return NULL;
}
static init __g__init__ __attribute__ ((unused));
}
