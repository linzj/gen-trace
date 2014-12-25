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
    : called_callback_ (called_callback), return_callback_ (return_callback)
{
}
base_controller::~base_controller () {}

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
  do_rest_with_config (config_desc);
  free (config_desc);
}

void
base_controller::do_rest_with_config (config_desc *config_desc)
{
  if (config_desc->sleep_sec != 0)
    {
      timespec spec = { config_desc->sleep_sec, 0 };
      nanosleep (&spec, NULL);
    }
  intptr_t base = find_base (config_desc);
  if (base == 0)
    {
      return;
    }
  if (should_add_base_to_sym_base (base))
    {
      for (int i = 0; i < config_desc->desc_array_size; ++i)
        {
          intptr_t v = reinterpret_cast<intptr_t> (
              config_desc->desc_array[i].code_point);
          v += base;
          config_desc->desc_array[i].code_point = reinterpret_cast<void *> (v);
        }
    }
  do_modify (config_desc);
}

config_desc *
base_controller::fill_config (fp_line_client *fp_client)
{
  config_reader cr;
  const char *line;
  while ((line = fp_client->next_line ()) != NULL)
    {
      cr.handle_line (line);
    }
  return cr.accumulate ();
}

intptr_t
base_controller::find_base (config_desc *config_desc)
{
  if (config_desc->module_name[0] == '\0')
    return 0;
  FILE *fp = fopen ("/proc/self/maps", "r");
  if (!fp)
    {
      return 0;
    }
  char buf[512];
  char *str;
  std::string search_for_module (config_desc->module_name);
  search_for_module.insert (0, "/");
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
  code_modify_init (_target_client);
  code_modify_set_log_for_fail (config_desc->where_to_keep_log);
  int code_modified_count
      = code_modify (config_desc->desc_array, config_desc->desc_array_size,
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
