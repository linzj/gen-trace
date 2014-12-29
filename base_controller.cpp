#include "code_modify.h"
#include "base_controller.h"
#include "config_reader.h"
#include "log.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

// machine base
#ifdef __x86_64__
#include "x64/x64_target_client.h"
#elif defined(__arm__)
#include "arm/arm_target_client.h"
#else
#error not supported machine
#endif

typedef struct
{
#define EI_NIDENT (16)
  unsigned char e_ident[EI_NIDENT]; /* Magic number and other info */
  uint16_t e_type;                  /* Object file type */
} compare_struct;

fp_line_client::~fp_line_client () {}
base_controller::base_controller (pfn_called_callback called_callback,
                                  pfn_ret_callback return_callback)
    : called_callback_ (called_callback), return_callback_ (return_callback),
      config_desc_ (NULL), ref_count_ (1)
{
}
base_controller::~base_controller ()
{
  if (config_desc_)
    {
      free (config_desc_);
    }
}

void
base_controller::do_it ()
{
  fp_line_client *fp_client = open_line_client ();
  if (!fp_client)
    {
      return;
    }
  config_desc *config_desc = fill_config (fp_client);
  destroy_line_client (fp_client);
  if (!config_desc)
    {
      return;
    }
  if (config_desc->sleep_sec != 0)
    {
      pthread_t mythread;
      config_desc_ = config_desc;
      retain ();
      pthread_create (&mythread, NULL, thread_worker, this);
      pthread_detach (mythread);
    }
  else
    {
      do_rest_with_config (config_desc);
      free (config_desc);
    }
}

void
base_controller::do_rest_with_config (config_desc *config_desc)
{
  for (int i = 0; i < config_desc->num_of_modules; ++i)
    {
      struct config_module *module = &config_desc->modules[i];
      intptr_t base = find_base (module);
      if (base == 0)
        {
          LOGE ("base_controller::do_rest_with_config base equals to zero for "
                "%s, %d symbols.\n",
                module->module_name, module->desc_array_size);
          // zero the code point to tell modifier to ignore them.
          for (int j = 0; j < module->desc_array_size; ++j)
            {
              module->desc_array[j].code_point = NULL;
            }
          continue;
        }
      if (should_add_base_to_sym_base (base))
        {
          for (int j = 0; j < module->desc_array_size; ++j)
            {
              intptr_t v = reinterpret_cast<intptr_t> (
                  module->desc_array[j].code_point);
              v += base;
              module->desc_array[j].code_point = reinterpret_cast<void *> (v);
            }
        }
    }
  do_modify (config_desc);
}

config_desc *
base_controller::fill_config (fp_line_client *fp_client)
{
  config_reader cr;
  const char *line;
  int _errno = errno;
  if (_errno)
    {
      LOGE ("errno is not zero %s\n", strerror (_errno));
      errno = 0;
    }

  while ((line = fp_client->next_line ()) != NULL)
    {
      // work around the stupid C implementation of android.
      errno = 0;
      cr.handle_line (line);
    }
  return cr.accumulate ();
}

intptr_t
base_controller::find_base (struct config_module *module)
{
  if (module->module_name[0] == '\0')
    return 0;
  FILE *fp = fopen ("/proc/self/maps", "r");
  if (!fp)
    {
      return 0;
    }
  char buf[512];
  char *str;
  std::string search_for_module (module->module_name);
  search_for_module.insert (0, "/");
  LOGI ("base_controller::find_base search for module: %s\n",
        search_for_module.c_str ());
  while ((str = fgets (buf, 512, fp)) != NULL)
    {
      if (strstr (str, search_for_module.c_str ()))
        {
          break;
        }
    }
  fclose (fp);
  if (str == NULL)
    {
      return 0;
    }
  // work around the stupid C implementation of android.
  errno = 0;
  unsigned long int l = strtoul (str, NULL, 16);
  if (errno != 0)
    {
      LOGE ("strtol fails %s for %s\n", strerror (errno), str);
      return 0;
    }
  return is_base_elf (l) ? l : 0;
}

bool
base_controller::should_add_base_to_sym_base (intptr_t module_base)
{
  const compare_struct *comp
      = reinterpret_cast<const compare_struct *> (module_base);
#define ET_DYN 3 /* Shared object file */
  return comp->e_type == ET_DYN;
}

void
base_controller::do_modify (config_desc *config_desc)
{
#ifdef __x86_64__
  target_client *_target_client = new x64_target_client;
#elif defined(__arm__)
  target_client *_target_client = new arm_target_client;
#endif
  LOGI ("base_controller::do_modify begin\n");
  code_modify_init (_target_client);
  code_modify_set_log_for_fail (config_desc->where_to_keep_log);
  int code_modified_count
      = code_modify (config_desc->all_desc, config_desc->num_of_all_desc,
                     called_callback_, return_callback_);
  LOGI ("base_controller::do_modify: code_modified_count = %d\n",
        code_modified_count);
}

bool
base_controller::is_base_elf (intptr_t base)
{
#define ELFMAG "\177ELF"
#define SELFMAG 4
  const compare_struct *comp = reinterpret_cast<const compare_struct *> (base);
  if (memcmp (comp->e_ident, ELFMAG, SELFMAG) != 0)
    {
      return false;
    }
  return true;
}

void *
base_controller::thread_worker (void *self)
{
  base_controller *_self = static_cast<base_controller *> (self);
  config_desc *config_desc = _self->config_desc_;
  LOGI ("base_controller::thread_worker, begin to sleep.\n");
  timespec spec = { config_desc->sleep_sec, 0 };
  nanosleep (&spec, NULL);
  LOGI ("base_controller::thread_worker, end sleep.\n");
  _self->do_rest_with_config (config_desc);
  _self->detain ();
  return NULL;
}

void
base_controller::retain ()
{
  int ref_count = __sync_fetch_and_add (&ref_count_, 1);
  assert (ref_count > 0);
}

void
base_controller::detain ()
{
  if (__sync_add_and_fetch (&ref_count_, -1) == 0)
    {
      delete this;
    }
}
