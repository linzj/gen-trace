#ifndef DIS_GNU_H
#define DIS_GNU_H
typedef long bfd_int64_t;
typedef unsigned long bfd_uint64_t;
typedef unsigned long bfd_hostptr_t;

typedef struct bfd bfd;
typedef int bfd_boolean;
typedef unsigned long bfd_vma;
typedef long bfd_signed_vma;
typedef unsigned long bfd_size_type;
typedef unsigned long symvalue;
typedef long file_ptr;
typedef unsigned long ufile_ptr;

extern void bfd_sprintf_vma (bfd *, char *, bfd_vma);
extern void bfd_fprintf_vma (bfd *, void *, bfd_vma);

typedef unsigned int flagword;
typedef unsigned char bfd_byte;

typedef enum bfd_format
{
  bfd_unknown = 0,
  bfd_object,
  bfd_archive,
  bfd_core,
  bfd_type_end
} bfd_format;

typedef unsigned long symindex;

typedef const struct reloc_howto_struct reloc_howto_type;
typedef struct carsym
{
  char *name;
  file_ptr file_offset;
} carsym;

struct orl
{
  char **name;
  union
  {
    file_ptr pos;
    bfd *abfd;
  } u;
  int namidx;
};

typedef struct lineno_cache_entry
{
  unsigned int line_number;
  union
  {
    struct bfd_symbol *sym;
    bfd_vma offset;
  } u;
} alent;

typedef struct bfd_section *sec_ptr;
typedef enum bfd_print_symbol
{
  bfd_print_symbol_name,
  bfd_print_symbol_more,
  bfd_print_symbol_all
} bfd_print_symbol_type;

typedef struct _symbol_info
{
  symvalue value;
  char type;
  const char *name;
  unsigned char stab_type;
  char stab_other;
  short stab_desc;
  const char *stab_name;
} symbol_info;

extern const char *bfd_get_stab_name (int);

struct bfd_hash_entry
{

  struct bfd_hash_entry *next;

  const char *string;

  unsigned long hash;
};

struct bfd_hash_table
{

  struct bfd_hash_entry **table;

  struct bfd_hash_entry *(*newfunc)(struct bfd_hash_entry *,
                                    struct bfd_hash_table *, const char *);

  void *memory;

  unsigned int size;

  unsigned int count;

  unsigned int entsize;

  unsigned int frozen : 1;
};

extern bfd_boolean bfd_hash_table_init (
    struct bfd_hash_table *,
    struct bfd_hash_entry *(*)(struct bfd_hash_entry *,
                               struct bfd_hash_table *, const char *),
    unsigned int);

extern bfd_boolean bfd_hash_table_init_n (
    struct bfd_hash_table *,
    struct bfd_hash_entry *(*)(struct bfd_hash_entry *,
                               struct bfd_hash_table *, const char *),
    unsigned int, unsigned int);

extern void bfd_hash_table_free (struct bfd_hash_table *);

extern struct bfd_hash_entry *bfd_hash_lookup (struct bfd_hash_table *,
                                               const char *,
                                               bfd_boolean create,
                                               bfd_boolean copy);

extern struct bfd_hash_entry *bfd_hash_insert (struct bfd_hash_table *,
                                               const char *, unsigned long);

extern void bfd_hash_rename (struct bfd_hash_table *, const char *,
                             struct bfd_hash_entry *);

extern void bfd_hash_replace (struct bfd_hash_table *,
                              struct bfd_hash_entry *old,
                              struct bfd_hash_entry *nw);

extern struct bfd_hash_entry *bfd_hash_newfunc (struct bfd_hash_entry *,
                                                struct bfd_hash_table *,
                                                const char *);

extern void *bfd_hash_allocate (struct bfd_hash_table *, unsigned int);

extern void bfd_hash_traverse (struct bfd_hash_table *,
                               bfd_boolean (*)(struct bfd_hash_entry *,
                                               void *),
                               void *info);

extern unsigned long bfd_hash_set_default_size (unsigned long);

struct stab_info
{

  struct bfd_strtab_hash *strings;

  struct bfd_hash_table includes;

  struct bfd_section *stabstr;
};
extern bfd_size_type bfd_bread (void *, bfd_size_type, bfd *);
extern bfd_size_type bfd_bwrite (const void *, bfd_size_type, bfd *);
extern int bfd_seek (bfd *, file_ptr, int);
extern file_ptr bfd_tell (bfd *);
extern int bfd_flush (bfd *);
extern int bfd_stat (bfd *, struct stat *);
extern void warn_deprecated (const char *, const char *, int, const char *);
extern bfd_boolean bfd_cache_close (bfd *abfd);

extern bfd_boolean bfd_cache_close_all (void);

extern bfd_boolean bfd_record_phdr (bfd *, unsigned long, bfd_boolean,
                                    flagword, bfd_boolean, bfd_vma,
                                    bfd_boolean, bfd_boolean, unsigned int,
                                    struct bfd_section **);

bfd_uint64_t bfd_getb64 (const void *);
bfd_uint64_t bfd_getl64 (const void *);
bfd_int64_t bfd_getb_signed_64 (const void *);
bfd_int64_t bfd_getl_signed_64 (const void *);
bfd_vma bfd_getb32 (const void *);
bfd_vma bfd_getl32 (const void *);
bfd_signed_vma bfd_getb_signed_32 (const void *);
bfd_signed_vma bfd_getl_signed_32 (const void *);
bfd_vma bfd_getb16 (const void *);
bfd_vma bfd_getl16 (const void *);
bfd_signed_vma bfd_getb_signed_16 (const void *);
bfd_signed_vma bfd_getl_signed_16 (const void *);
void bfd_putb64 (bfd_uint64_t, void *);
void bfd_putl64 (bfd_uint64_t, void *);
void bfd_putb32 (bfd_vma, void *);
void bfd_putl32 (bfd_vma, void *);
void bfd_putb16 (bfd_vma, void *);
void bfd_putl16 (bfd_vma, void *);

bfd_uint64_t bfd_get_bits (const void *, int, bfd_boolean);
void bfd_put_bits (bfd_uint64_t, void *, int, bfd_boolean);

struct ecoff_debug_info;
struct ecoff_debug_swap;
struct ecoff_extr;
struct bfd_symbol;
struct bfd_link_info;
struct bfd_link_hash_entry;
struct bfd_section_already_linked;
struct bfd_elf_version_tree;

extern bfd_boolean bfd_section_already_linked_table_init (void);
extern void bfd_section_already_linked_table_free (void);
extern bfd_boolean
_bfd_handle_already_linked (struct bfd_section *,
                            struct bfd_section_already_linked *,
                            struct bfd_link_info *);

extern bfd_vma bfd_ecoff_get_gp_value (bfd *abfd);
extern bfd_boolean bfd_ecoff_set_gp_value (bfd *abfd, bfd_vma gp_value);
extern bfd_boolean bfd_ecoff_set_regmasks (bfd *abfd, unsigned long gprmask,
                                           unsigned long fprmask,
                                           unsigned long *cprmask);
extern void *bfd_ecoff_debug_init (bfd *output_bfd,
                                   struct ecoff_debug_info *output_debug,
                                   const struct ecoff_debug_swap *output_swap,
                                   struct bfd_link_info *);
extern void bfd_ecoff_debug_free (void *handle, bfd *output_bfd,
                                  struct ecoff_debug_info *output_debug,
                                  const struct ecoff_debug_swap *output_swap,
                                  struct bfd_link_info *);
extern bfd_boolean bfd_ecoff_debug_accumulate (
    void *handle, bfd *output_bfd, struct ecoff_debug_info *output_debug,
    const struct ecoff_debug_swap *output_swap, bfd *input_bfd,
    struct ecoff_debug_info *input_debug,
    const struct ecoff_debug_swap *input_swap, struct bfd_link_info *);
extern bfd_boolean
bfd_ecoff_debug_accumulate_other (void *handle, bfd *output_bfd,
                                  struct ecoff_debug_info *output_debug,
                                  const struct ecoff_debug_swap *output_swap,
                                  bfd *input_bfd, struct bfd_link_info *);
extern bfd_boolean bfd_ecoff_debug_externals (
    bfd *abfd, struct ecoff_debug_info *debug,
    const struct ecoff_debug_swap *swap, bfd_boolean relocatable,
    bfd_boolean (*get_extr)(struct bfd_symbol *, struct ecoff_extr *),
    void (*set_index)(struct bfd_symbol *, bfd_size_type));
extern bfd_boolean
bfd_ecoff_debug_one_external (bfd *abfd, struct ecoff_debug_info *debug,
                              const struct ecoff_debug_swap *swap,
                              const char *name, struct ecoff_extr *esym);
extern bfd_size_type
bfd_ecoff_debug_size (bfd *abfd, struct ecoff_debug_info *debug,
                      const struct ecoff_debug_swap *swap);
extern bfd_boolean bfd_ecoff_write_debug (bfd *abfd,
                                          struct ecoff_debug_info *debug,
                                          const struct ecoff_debug_swap *swap,
                                          file_ptr where);
extern bfd_boolean
bfd_ecoff_write_accumulated_debug (void *handle, bfd *abfd,
                                   struct ecoff_debug_info *debug,
                                   const struct ecoff_debug_swap *swap,
                                   struct bfd_link_info *info, file_ptr where);

struct bfd_link_needed_list
{
  struct bfd_link_needed_list *next;
  bfd *by;
  const char *name;
};

enum dynamic_lib_link_class
{
  DYN_NORMAL = 0,
  DYN_AS_NEEDED = 1,
  DYN_DT_NEEDED = 2,
  DYN_NO_ADD_NEEDED = 4,
  DYN_NO_NEEDED = 8
};

enum notice_asneeded_action
{
  notice_as_needed,
  notice_not_needed,
  notice_needed
};

extern bfd_boolean bfd_elf_record_link_assignment (bfd *,
                                                   struct bfd_link_info *,
                                                   const char *, bfd_boolean,
                                                   bfd_boolean);
extern struct bfd_link_needed_list *
bfd_elf_get_needed_list (bfd *, struct bfd_link_info *);
extern bfd_boolean
bfd_elf_get_bfd_needed_list (bfd *, struct bfd_link_needed_list **);
extern bfd_boolean bfd_elf_stack_segment_size (bfd *, struct bfd_link_info *,
                                               const char *, bfd_vma);
extern bfd_boolean
bfd_elf_size_dynamic_sections (bfd *, const char *, const char *, const char *,
                               const char *, const char *, const char *const *,
                               struct bfd_link_info *, struct bfd_section **);
extern bfd_boolean bfd_elf_size_dynsym_hash_dynstr (bfd *,
                                                    struct bfd_link_info *);
extern void bfd_elf_set_dt_needed_name (bfd *, const char *);
extern const char *bfd_elf_get_dt_soname (bfd *);
extern void bfd_elf_set_dyn_lib_class (bfd *, enum dynamic_lib_link_class);
extern int bfd_elf_get_dyn_lib_class (bfd *);
extern struct bfd_link_needed_list *
bfd_elf_get_runpath_list (bfd *, struct bfd_link_info *);
extern bfd_boolean bfd_elf_discard_info (bfd *, struct bfd_link_info *);
extern unsigned int _bfd_elf_default_action_discarded (struct bfd_section *);

extern long bfd_get_elf_phdr_upper_bound (bfd *abfd);
extern int bfd_get_elf_phdrs (bfd *abfd, void *phdrs);
extern bfd *bfd_elf_bfd_from_remote_memory (
    bfd *templ, bfd_vma ehdr_vma, bfd_size_type size, bfd_vma *loadbasep,
    int (*target_read_memory)(bfd_vma vma, bfd_byte *myaddr,
                              bfd_size_type len));

extern struct bfd_section *_bfd_elf_tls_setup (bfd *, struct bfd_link_info *);

extern struct bfd_section *_bfd_nearby_section (bfd *, struct bfd_section *,
                                                bfd_vma);

extern void _bfd_fix_excluded_sec_syms (bfd *, struct bfd_link_info *);

extern unsigned bfd_m68k_mach_to_features (int);

extern int bfd_m68k_features_to_mach (unsigned);

extern bfd_boolean
bfd_m68k_elf32_create_embedded_relocs (bfd *, struct bfd_link_info *,
                                       struct bfd_section *,
                                       struct bfd_section *, char **);

extern void bfd_elf_m68k_set_target_options (struct bfd_link_info *, int);

extern bfd_boolean
bfd_bfin_elf32_create_embedded_relocs (bfd *, struct bfd_link_info *,
                                       struct bfd_section *,
                                       struct bfd_section *, char **);

extern bfd_boolean
bfd_cr16_elf32_create_embedded_relocs (bfd *, struct bfd_link_info *,
                                       struct bfd_section *,
                                       struct bfd_section *, char **);

extern struct bfd_link_needed_list *
bfd_sunos_get_needed_list (bfd *, struct bfd_link_info *);
extern bfd_boolean
bfd_sunos_record_link_assignment (bfd *, struct bfd_link_info *, const char *);
extern bfd_boolean bfd_sunos_size_dynamic_sections (bfd *,
                                                    struct bfd_link_info *,
                                                    struct bfd_section **,
                                                    struct bfd_section **,
                                                    struct bfd_section **);

extern bfd_boolean
bfd_i386linux_size_dynamic_sections (bfd *, struct bfd_link_info *);
extern bfd_boolean
bfd_m68klinux_size_dynamic_sections (bfd *, struct bfd_link_info *);
extern bfd_boolean
bfd_sparclinux_size_dynamic_sections (bfd *, struct bfd_link_info *);

struct _bfd_window_internal;
typedef struct _bfd_window_internal bfd_window_internal;

typedef struct _bfd_window
{

  void *data;
  bfd_size_type size;

  struct _bfd_window_internal *i;
} bfd_window;

extern void bfd_init_window (bfd_window *);
extern void bfd_free_window (bfd_window *);
extern bfd_boolean bfd_get_file_window (bfd *, file_ptr, bfd_size_type,
                                        bfd_window *, bfd_boolean);

extern bfd_boolean bfd_xcoff_split_import_path (bfd *, const char *,
                                                const char **, const char **);
extern bfd_boolean bfd_xcoff_set_archive_import_path (struct bfd_link_info *,
                                                      bfd *, const char *);
extern bfd_boolean bfd_xcoff_link_record_set (bfd *, struct bfd_link_info *,
                                              struct bfd_link_hash_entry *,
                                              bfd_size_type);
extern bfd_boolean bfd_xcoff_import_symbol (bfd *, struct bfd_link_info *,
                                            struct bfd_link_hash_entry *,
                                            bfd_vma, const char *,
                                            const char *, const char *,
                                            unsigned int);
extern bfd_boolean bfd_xcoff_export_symbol (bfd *, struct bfd_link_info *,
                                            struct bfd_link_hash_entry *);
extern bfd_boolean bfd_xcoff_link_count_reloc (bfd *, struct bfd_link_info *,
                                               const char *);
extern bfd_boolean
bfd_xcoff_record_link_assignment (bfd *, struct bfd_link_info *, const char *);
extern bfd_boolean bfd_xcoff_size_dynamic_sections (
    bfd *, struct bfd_link_info *, const char *, const char *, unsigned long,
    unsigned long, unsigned long, bfd_boolean, int, bfd_boolean, unsigned int,
    struct bfd_section **, bfd_boolean);
extern bfd_boolean bfd_xcoff_link_generate_rtinit (bfd *, const char *,
                                                   const char *, bfd_boolean);

extern bfd_boolean bfd_xcoff_ar_archive_set_magic (bfd *, char *);

struct internal_syment;
union internal_auxent;

extern bfd_boolean bfd_coff_get_syment (bfd *, struct bfd_symbol *,
                                        struct internal_syment *);

extern bfd_boolean bfd_coff_get_auxent (bfd *, struct bfd_symbol *, int,
                                        union internal_auxent *);

extern bfd_boolean bfd_coff_set_symbol_class (bfd *, struct bfd_symbol *,
                                              unsigned int);

extern bfd_boolean
bfd_m68k_coff_create_embedded_relocs (bfd *, struct bfd_link_info *,
                                      struct bfd_section *,
                                      struct bfd_section *, char **);

typedef enum
{
  BFD_ARM_VFP11_FIX_DEFAULT,
  BFD_ARM_VFP11_FIX_NONE,
  BFD_ARM_VFP11_FIX_SCALAR,
  BFD_ARM_VFP11_FIX_VECTOR
} bfd_arm_vfp11_fix;

extern void bfd_elf32_arm_init_maps (bfd *);

extern void bfd_elf32_arm_set_vfp11_fix (bfd *, struct bfd_link_info *);

extern void bfd_elf32_arm_set_cortex_a8_fix (bfd *, struct bfd_link_info *);

extern bfd_boolean bfd_elf32_arm_vfp11_erratum_scan (bfd *,
                                                     struct bfd_link_info *);

extern void bfd_elf32_arm_vfp11_fix_veneer_locations (bfd *,
                                                      struct bfd_link_info *);

extern bfd_boolean
bfd_arm_allocate_interworking_sections (struct bfd_link_info *);

extern bfd_boolean
bfd_arm_process_before_allocation (bfd *, struct bfd_link_info *, int);

extern bfd_boolean bfd_arm_get_bfd_for_interworking (bfd *,
                                                     struct bfd_link_info *);

extern bfd_boolean
bfd_arm_pe_allocate_interworking_sections (struct bfd_link_info *);

extern bfd_boolean
bfd_arm_pe_process_before_allocation (bfd *, struct bfd_link_info *, int);

extern bfd_boolean
bfd_arm_pe_get_bfd_for_interworking (bfd *, struct bfd_link_info *);

extern bfd_boolean
bfd_elf32_arm_allocate_interworking_sections (struct bfd_link_info *);

extern bfd_boolean
bfd_elf32_arm_process_before_allocation (bfd *, struct bfd_link_info *);

void bfd_elf32_arm_set_target_relocs (bfd *, struct bfd_link_info *, int,
                                      char *, int, int, bfd_arm_vfp11_fix, int,
                                      int, int, int, int);

extern bfd_boolean
bfd_elf32_arm_get_bfd_for_interworking (bfd *, struct bfd_link_info *);

extern bfd_boolean
bfd_elf32_arm_add_glue_sections_to_bfd (bfd *, struct bfd_link_info *);

extern bfd_boolean bfd_is_arm_special_symbol_name (const char *, int);

extern void bfd_elf32_arm_set_byteswap_code (struct bfd_link_info *, int);

extern void bfd_elf32_arm_use_long_plt (void);

extern bfd_boolean bfd_arm_merge_machines (bfd *, bfd *);

extern bfd_boolean bfd_arm_update_notes (bfd *, const char *);

extern unsigned int bfd_arm_get_mach_from_notes (bfd *, const char *);

extern int elf32_arm_setup_section_lists (bfd *, struct bfd_link_info *);
extern void elf32_arm_next_input_section (struct bfd_link_info *,
                                          struct bfd_section *);
extern bfd_boolean elf32_arm_size_stubs (
    bfd *, bfd *, struct bfd_link_info *, bfd_signed_vma,
    struct bfd_section *(*)(const char *, struct bfd_section *, unsigned int),
    void (*)(void));
extern bfd_boolean elf32_arm_build_stubs (struct bfd_link_info *);

extern bfd_boolean elf32_arm_fix_exidx_coverage (struct bfd_section **,
                                                 unsigned int,
                                                 struct bfd_link_info *,
                                                 bfd_boolean);

extern bfd_boolean elf32_tic6x_fix_exidx_coverage (struct bfd_section **,
                                                   unsigned int,
                                                   struct bfd_link_info *,
                                                   bfd_boolean);

extern unsigned int _bfd_elf_ppc_at_tls_transform (unsigned int, unsigned int);

extern unsigned int _bfd_elf_ppc_at_tprel_transform (unsigned int,
                                                     unsigned int);

extern void bfd_elf64_aarch64_init_maps (bfd *);

extern void bfd_elf32_aarch64_init_maps (bfd *);

extern void bfd_elf64_aarch64_set_options (bfd *, struct bfd_link_info *, int,
                                           int, int);

extern void bfd_elf32_aarch64_set_options (bfd *, struct bfd_link_info *, int,
                                           int, int);

extern bfd_boolean bfd_is_aarch64_special_symbol_name (const char *name,
                                                       int type);

extern int elf64_aarch64_setup_section_lists (bfd *, struct bfd_link_info *);
extern void elf64_aarch64_next_input_section (struct bfd_link_info *,
                                              struct bfd_section *);
extern bfd_boolean elf64_aarch64_size_stubs (
    bfd *, bfd *, struct bfd_link_info *, bfd_signed_vma,
    struct bfd_section *(*)(const char *, struct bfd_section *),
    void (*)(void));
extern bfd_boolean elf64_aarch64_build_stubs (struct bfd_link_info *);

extern int elf32_aarch64_setup_section_lists (bfd *, struct bfd_link_info *);
extern void elf32_aarch64_next_input_section (struct bfd_link_info *,
                                              struct bfd_section *);
extern bfd_boolean elf32_aarch64_size_stubs (
    bfd *, bfd *, struct bfd_link_info *, bfd_signed_vma,
    struct bfd_section *(*)(const char *, struct bfd_section *),
    void (*)(void));
extern bfd_boolean elf32_aarch64_build_stubs (struct bfd_link_info *);

extern void bfd_ticoff_set_section_load_page (struct bfd_section *, int);

extern int bfd_ticoff_get_section_load_page (struct bfd_section *);

extern bfd_vma bfd_h8300_pad_address (bfd *, bfd_vma);

extern void bfd_elf32_ia64_after_parse (int);

extern void bfd_elf64_ia64_after_parse (int);

struct coff_comdat_info
{

  const char *name;

  long symbol;
};

extern struct coff_comdat_info *
bfd_coff_get_comdat_section (bfd *, struct bfd_section *);

void bfd_init (void);

extern unsigned int bfd_use_reserved_id;
bfd *bfd_fopen (const char *filename, const char *target, const char *mode,
                int fd);

bfd *bfd_openr (const char *filename, const char *target);

bfd *bfd_fdopenr (const char *filename, const char *target, int fd);

bfd *bfd_openstreamr (const char *filename, const char *target, void *stream);

bfd *bfd_openr_iovec (const char *filename, const char *target,
                      void *(*open_func)(struct bfd *nbfd, void *open_closure),
                      void *open_closure,
                      file_ptr (*pread_func)(struct bfd *nbfd, void *stream,
                                             void *buf, file_ptr nbytes,
                                             file_ptr offset),
                      int (*close_func)(struct bfd *nbfd, void *stream),
                      int (*stat_func)(struct bfd *abfd, void *stream,
                                       struct stat *sb));

bfd *bfd_openw (const char *filename, const char *target);

bfd_boolean bfd_close (bfd *abfd);

bfd_boolean bfd_close_all_done (bfd *);

bfd *bfd_create (const char *filename, bfd *templ);

bfd_boolean bfd_make_writable (bfd *abfd);

bfd_boolean bfd_make_readable (bfd *abfd);

void *bfd_alloc (bfd *abfd, bfd_size_type wanted);

void *bfd_zalloc (bfd *abfd, bfd_size_type wanted);

unsigned long bfd_calc_gnu_debuglink_crc32 (unsigned long crc,
                                            const unsigned char *buf,
                                            bfd_size_type len);

char *bfd_get_debug_link_info (bfd *abfd, unsigned long *crc32_out);

char *bfd_get_alt_debug_link_info (bfd *abfd, bfd_size_type *buildid_len,
                                   bfd_byte **buildid_out);

char *bfd_follow_gnu_debuglink (bfd *abfd, const char *dir);

char *bfd_follow_gnu_debugaltlink (bfd *abfd, const char *dir);

struct bfd_section *bfd_create_gnu_debuglink_section (bfd *abfd,
                                                      const char *filename);

bfd_boolean bfd_fill_in_gnu_debuglink_section (bfd *abfd,
                                               struct bfd_section *sect,
                                               const char *filename);
long bfd_get_mtime (bfd *abfd);

file_ptr bfd_get_size (bfd *abfd);

void *bfd_mmap (bfd *abfd, void *addr, bfd_size_type len, int prot, int flags,
                file_ptr offset, void **map_addr, bfd_size_type *map_len);

typedef struct bfd_section
{

  const char *name;

  int id;

  int index;

  struct bfd_section *next;

  struct bfd_section *prev;

  flagword flags;
  unsigned int user_set_vma : 1;

  unsigned int linker_mark : 1;

  unsigned int linker_has_input : 1;

  unsigned int gc_mark : 1;

  unsigned int compress_status : 2;

  unsigned int segment_mark : 1;

  unsigned int sec_info_type : 3;
  unsigned int use_rela_p : 1;

  unsigned int sec_flg0 : 1;
  unsigned int sec_flg1 : 1;
  unsigned int sec_flg2 : 1;
  unsigned int sec_flg3 : 1;
  unsigned int sec_flg4 : 1;
  unsigned int sec_flg5 : 1;
  bfd_vma vma;

  bfd_vma lma;

  bfd_size_type size;
  bfd_size_type rawsize;

  bfd_size_type compressed_size;

  struct relax_table *relax;

  int relax_count;
  bfd_vma output_offset;

  struct bfd_section *output_section;

  unsigned int alignment_power;

  struct reloc_cache_entry *relocation;

  struct reloc_cache_entry **orelocation;

  unsigned reloc_count;

  file_ptr filepos;

  file_ptr rel_filepos;

  file_ptr line_filepos;

  void *userdata;

  unsigned char *contents;

  alent *lineno;

  unsigned int lineno_count;

  unsigned int entsize;

  struct bfd_section *kept_section;

  file_ptr moving_line_filepos;

  int target_index;

  void *used_by_bfd;

  struct relent_chain *constructor_chain;

  bfd *owner;

  struct bfd_symbol *symbol;
  struct bfd_symbol **symbol_ptr_ptr;

  union
  {
    struct bfd_link_order *link_order;
    struct bfd_section *s;
  } map_head, map_tail;
} asection;

struct relax_table
{

  bfd_vma addr;

  int size;
};

static __inline__ bfd_boolean
bfd_set_section_userdata (bfd *abfd __attribute__ ((__unused__)),
                          asection *ptr, void *val)
{
  ptr->userdata = val;
  return 1;
}

static __inline__ bfd_boolean
bfd_set_section_vma (bfd *abfd __attribute__ ((__unused__)), asection *ptr,
                     bfd_vma val)
{
  ptr->vma = ptr->lma = val;
  ptr->user_set_vma = 1;
  return 1;
}

static __inline__ bfd_boolean
bfd_set_section_alignment (bfd *abfd __attribute__ ((__unused__)),
                           asection *ptr, unsigned int val)
{
  ptr->alignment_power = val;
  return 1;
}

extern asection _bfd_std_section[4];
void bfd_section_list_clear (bfd *);

asection *bfd_get_section_by_name (bfd *abfd, const char *name);

asection *bfd_get_next_section_by_name (asection *sec);

asection *bfd_get_linker_section (bfd *abfd, const char *name);

asection *bfd_get_section_by_name_if (
    bfd *abfd, const char *name,
    bfd_boolean (*func)(bfd *abfd, asection *sect, void *obj), void *obj);

char *bfd_get_unique_section_name (bfd *abfd, const char *templat, int *count);

asection *bfd_make_section_old_way (bfd *abfd, const char *name);

asection *bfd_make_section_anyway_with_flags (bfd *abfd, const char *name,
                                              flagword flags);

asection *bfd_make_section_anyway (bfd *abfd, const char *name);

asection *bfd_make_section_with_flags (bfd *, const char *name,
                                       flagword flags);

asection *bfd_make_section (bfd *, const char *name);

bfd_boolean bfd_set_section_flags (bfd *abfd, asection *sec, flagword flags);

void bfd_rename_section (bfd *abfd, asection *sec, const char *newname);

void bfd_map_over_sections (bfd *abfd,
                            void (*func)(bfd *abfd, asection *sect, void *obj),
                            void *obj);

asection *bfd_sections_find_if (
    bfd *abfd, bfd_boolean (*operation)(bfd *abfd, asection *sect, void *obj),
    void *obj);

bfd_boolean bfd_set_section_size (bfd *abfd, asection *sec, bfd_size_type val);

bfd_boolean bfd_set_section_contents (bfd *abfd, asection *section,
                                      const void *data, file_ptr offset,
                                      bfd_size_type count);

bfd_boolean bfd_get_section_contents (bfd *abfd, asection *section,
                                      void *location, file_ptr offset,
                                      bfd_size_type count);

bfd_boolean bfd_malloc_and_get_section (bfd *abfd, asection *section,
                                        bfd_byte **buf);

bfd_boolean bfd_copy_private_section_data (bfd *ibfd, asection *isec,
                                           bfd *obfd, asection *osec);

bfd_boolean bfd_generic_is_group_section (bfd *, const asection *sec);

bfd_boolean bfd_generic_discard_group (bfd *abfd, asection *group);

enum bfd_architecture
{
  bfd_arch_unknown,
  bfd_arch_obscure,
  bfd_arch_m68k,
  bfd_arch_vax,
  bfd_arch_i960,
  bfd_arch_or1k,

  bfd_arch_sparc,
  bfd_arch_spu,

  bfd_arch_mips,
  bfd_arch_i386,
  bfd_arch_l1om,

  bfd_arch_k1om,

  bfd_arch_we32k,
  bfd_arch_tahoe,
  bfd_arch_i860,
  bfd_arch_i370,
  bfd_arch_romp,
  bfd_arch_convex,
  bfd_arch_m88k,
  bfd_arch_m98k,
  bfd_arch_pyramid,
  bfd_arch_h8300,

  bfd_arch_pdp11,
  bfd_arch_plugin,
  bfd_arch_powerpc,
  bfd_arch_rs6000,

  bfd_arch_hppa,

  bfd_arch_d10v,

  bfd_arch_d30v,
  bfd_arch_dlx,
  bfd_arch_m68hc11,
  bfd_arch_m68hc12,

  bfd_arch_m9s12x,
  bfd_arch_m9s12xg,
  bfd_arch_z8k,

  bfd_arch_h8500,
  bfd_arch_sh,
  bfd_arch_alpha,

  bfd_arch_arm,
  bfd_arch_nds32,

  bfd_arch_ns32k,
  bfd_arch_w65,
  bfd_arch_tic30,
  bfd_arch_tic4x,

  bfd_arch_tic54x,
  bfd_arch_tic6x,
  bfd_arch_tic80,
  bfd_arch_v850,
  bfd_arch_v850_rh850,

  bfd_arch_arc,

  bfd_arch_m32c,

  bfd_arch_m32r,

  bfd_arch_mn10200,
  bfd_arch_mn10300,

  bfd_arch_fr30,

  bfd_arch_frv,
  bfd_arch_moxie,

  bfd_arch_mcore,
  bfd_arch_mep,

  bfd_arch_metag,

  bfd_arch_ia64,

  bfd_arch_ip2k,

  bfd_arch_iq2000,

  bfd_arch_epiphany,

  bfd_arch_mt,

  bfd_arch_pj,
  bfd_arch_avr,
  bfd_arch_bfin,

  bfd_arch_cr16,

  bfd_arch_cr16c,

  bfd_arch_crx,

  bfd_arch_cris,

  bfd_arch_rl78,

  bfd_arch_rx,

  bfd_arch_s390,

  bfd_arch_score,

  bfd_arch_mmix,
  bfd_arch_xstormy16,

  bfd_arch_msp430,
  bfd_arch_xc16x,

  bfd_arch_xgate,

  bfd_arch_xtensa,

  bfd_arch_z80,

  bfd_arch_lm32,

  bfd_arch_microblaze,
  bfd_arch_tilepro,
  bfd_arch_tilegx,

  bfd_arch_aarch64,

  bfd_arch_nios2,

  bfd_arch_last
};

typedef struct bfd_arch_info
{
  int bits_per_word;
  int bits_per_address;
  int bits_per_byte;
  enum bfd_architecture arch;
  unsigned long mach;
  const char *arch_name;
  const char *printable_name;
  unsigned int section_align_power;

  bfd_boolean the_default;
  const struct bfd_arch_info *(*compatible)(const struct bfd_arch_info *a,
                                            const struct bfd_arch_info *b);

  bfd_boolean (*scan)(const struct bfd_arch_info *, const char *);

  void *(*fill)(bfd_size_type count, bfd_boolean is_bigendian,
                bfd_boolean code);

  const struct bfd_arch_info *next;
} bfd_arch_info_type;

const char *bfd_printable_name (bfd *abfd);

const bfd_arch_info_type *bfd_scan_arch (const char *string);

const char **bfd_arch_list (void);

const bfd_arch_info_type *
bfd_arch_get_compatible (const bfd *abfd, const bfd *bbfd,
                         bfd_boolean accept_unknowns);

void bfd_set_arch_info (bfd *abfd, const bfd_arch_info_type *arg);

enum bfd_architecture bfd_get_arch (bfd *abfd);

unsigned long bfd_get_mach (bfd *abfd);

unsigned int bfd_arch_bits_per_byte (bfd *abfd);

unsigned int bfd_arch_bits_per_address (bfd *abfd);

const bfd_arch_info_type *bfd_get_arch_info (bfd *abfd);

const bfd_arch_info_type *bfd_lookup_arch (enum bfd_architecture arch,
                                           unsigned long machine);

const char *bfd_printable_arch_mach (enum bfd_architecture arch,
                                     unsigned long machine);

unsigned int bfd_octets_per_byte (bfd *abfd);

unsigned int bfd_arch_mach_octets_per_byte (enum bfd_architecture arch,
                                            unsigned long machine);

typedef enum bfd_reloc_status
{

  bfd_reloc_ok,

  bfd_reloc_overflow,

  bfd_reloc_outofrange,

  bfd_reloc_continue,

  bfd_reloc_notsupported,

  bfd_reloc_other,

  bfd_reloc_undefined,

  bfd_reloc_dangerous
} bfd_reloc_status_type;

typedef struct reloc_cache_entry
{

  struct bfd_symbol **sym_ptr_ptr;

  bfd_size_type address;

  bfd_vma addend;

  reloc_howto_type *howto;

} arelent;

enum complain_overflow
{

  complain_overflow_dont,

  complain_overflow_bitfield,

  complain_overflow_signed,

  complain_overflow_unsigned
};

struct reloc_howto_struct
{

  unsigned int type;

  unsigned int rightshift;

  int size;

  unsigned int bitsize;

  bfd_boolean pc_relative;

  unsigned int bitpos;

  enum complain_overflow complain_on_overflow;

  bfd_reloc_status_type (*special_function)(bfd *, arelent *,
                                            struct bfd_symbol *, void *,
                                            asection *, bfd *, char **);

  char *name;
  bfd_boolean partial_inplace;
  bfd_vma src_mask;

  bfd_vma dst_mask;

  bfd_boolean pcrel_offset;
};
unsigned int bfd_get_reloc_size (reloc_howto_type *);

typedef struct relent_chain
{
  arelent relent;
  struct relent_chain *next;
} arelent_chain;

bfd_reloc_status_type bfd_check_overflow (enum complain_overflow how,
                                          unsigned int bitsize,
                                          unsigned int rightshift,
                                          unsigned int addrsize,
                                          bfd_vma relocation);

bfd_reloc_status_type bfd_perform_relocation (bfd *abfd, arelent *reloc_entry,
                                              void *data,
                                              asection *input_section,
                                              bfd *output_bfd,
                                              char **error_message);

bfd_reloc_status_type bfd_install_relocation (bfd *abfd, arelent *reloc_entry,
                                              void *data, bfd_vma data_start,
                                              asection *input_section,
                                              char **error_message);

enum bfd_reloc_code_real
{
  _dummy_first_bfd_reloc_code_real,

  BFD_RELOC_64,
  BFD_RELOC_32,
  BFD_RELOC_26,
  BFD_RELOC_24,
  BFD_RELOC_16,
  BFD_RELOC_14,
  BFD_RELOC_8,

  BFD_RELOC_64_PCREL,
  BFD_RELOC_32_PCREL,
  BFD_RELOC_24_PCREL,
  BFD_RELOC_16_PCREL,
  BFD_RELOC_12_PCREL,
  BFD_RELOC_8_PCREL,

  BFD_RELOC_32_SECREL,

  BFD_RELOC_32_GOT_PCREL,
  BFD_RELOC_16_GOT_PCREL,
  BFD_RELOC_8_GOT_PCREL,
  BFD_RELOC_32_GOTOFF,
  BFD_RELOC_16_GOTOFF,
  BFD_RELOC_LO16_GOTOFF,
  BFD_RELOC_HI16_GOTOFF,
  BFD_RELOC_HI16_S_GOTOFF,
  BFD_RELOC_8_GOTOFF,
  BFD_RELOC_64_PLT_PCREL,
  BFD_RELOC_32_PLT_PCREL,
  BFD_RELOC_24_PLT_PCREL,
  BFD_RELOC_16_PLT_PCREL,
  BFD_RELOC_8_PLT_PCREL,
  BFD_RELOC_64_PLTOFF,
  BFD_RELOC_32_PLTOFF,
  BFD_RELOC_16_PLTOFF,
  BFD_RELOC_LO16_PLTOFF,
  BFD_RELOC_HI16_PLTOFF,
  BFD_RELOC_HI16_S_PLTOFF,
  BFD_RELOC_8_PLTOFF,

  BFD_RELOC_SIZE32,
  BFD_RELOC_SIZE64,

  BFD_RELOC_68K_GLOB_DAT,
  BFD_RELOC_68K_JMP_SLOT,
  BFD_RELOC_68K_RELATIVE,
  BFD_RELOC_68K_TLS_GD32,
  BFD_RELOC_68K_TLS_GD16,
  BFD_RELOC_68K_TLS_GD8,
  BFD_RELOC_68K_TLS_LDM32,
  BFD_RELOC_68K_TLS_LDM16,
  BFD_RELOC_68K_TLS_LDM8,
  BFD_RELOC_68K_TLS_LDO32,
  BFD_RELOC_68K_TLS_LDO16,
  BFD_RELOC_68K_TLS_LDO8,
  BFD_RELOC_68K_TLS_IE32,
  BFD_RELOC_68K_TLS_IE16,
  BFD_RELOC_68K_TLS_IE8,
  BFD_RELOC_68K_TLS_LE32,
  BFD_RELOC_68K_TLS_LE16,
  BFD_RELOC_68K_TLS_LE8,

  BFD_RELOC_32_BASEREL,
  BFD_RELOC_16_BASEREL,
  BFD_RELOC_LO16_BASEREL,
  BFD_RELOC_HI16_BASEREL,
  BFD_RELOC_HI16_S_BASEREL,
  BFD_RELOC_8_BASEREL,
  BFD_RELOC_RVA,

  BFD_RELOC_8_FFnn,

  BFD_RELOC_32_PCREL_S2,
  BFD_RELOC_16_PCREL_S2,
  BFD_RELOC_23_PCREL_S2,

  BFD_RELOC_HI22,
  BFD_RELOC_LO10,

  BFD_RELOC_GPREL16,
  BFD_RELOC_GPREL32,

  BFD_RELOC_I960_CALLJ,

  BFD_RELOC_NONE,
  BFD_RELOC_SPARC_WDISP22,
  BFD_RELOC_SPARC22,
  BFD_RELOC_SPARC13,
  BFD_RELOC_SPARC_GOT10,
  BFD_RELOC_SPARC_GOT13,
  BFD_RELOC_SPARC_GOT22,
  BFD_RELOC_SPARC_PC10,
  BFD_RELOC_SPARC_PC22,
  BFD_RELOC_SPARC_WPLT30,
  BFD_RELOC_SPARC_COPY,
  BFD_RELOC_SPARC_GLOB_DAT,
  BFD_RELOC_SPARC_JMP_SLOT,
  BFD_RELOC_SPARC_RELATIVE,
  BFD_RELOC_SPARC_UA16,
  BFD_RELOC_SPARC_UA32,
  BFD_RELOC_SPARC_UA64,
  BFD_RELOC_SPARC_GOTDATA_HIX22,
  BFD_RELOC_SPARC_GOTDATA_LOX10,
  BFD_RELOC_SPARC_GOTDATA_OP_HIX22,
  BFD_RELOC_SPARC_GOTDATA_OP_LOX10,
  BFD_RELOC_SPARC_GOTDATA_OP,
  BFD_RELOC_SPARC_JMP_IREL,
  BFD_RELOC_SPARC_IRELATIVE,

  BFD_RELOC_SPARC_BASE13,
  BFD_RELOC_SPARC_BASE22,

  BFD_RELOC_SPARC_10,
  BFD_RELOC_SPARC_11,
  BFD_RELOC_SPARC_OLO10,
  BFD_RELOC_SPARC_HH22,
  BFD_RELOC_SPARC_HM10,
  BFD_RELOC_SPARC_LM22,
  BFD_RELOC_SPARC_PC_HH22,
  BFD_RELOC_SPARC_PC_HM10,
  BFD_RELOC_SPARC_PC_LM22,
  BFD_RELOC_SPARC_WDISP16,
  BFD_RELOC_SPARC_WDISP19,
  BFD_RELOC_SPARC_7,
  BFD_RELOC_SPARC_6,
  BFD_RELOC_SPARC_5,

  BFD_RELOC_SPARC_PLT32,
  BFD_RELOC_SPARC_PLT64,
  BFD_RELOC_SPARC_HIX22,
  BFD_RELOC_SPARC_LOX10,
  BFD_RELOC_SPARC_H44,
  BFD_RELOC_SPARC_M44,
  BFD_RELOC_SPARC_L44,
  BFD_RELOC_SPARC_REGISTER,
  BFD_RELOC_SPARC_H34,
  BFD_RELOC_SPARC_SIZE32,
  BFD_RELOC_SPARC_SIZE64,
  BFD_RELOC_SPARC_WDISP10,

  BFD_RELOC_SPARC_REV32,

  BFD_RELOC_SPARC_TLS_GD_HI22,
  BFD_RELOC_SPARC_TLS_GD_LO10,
  BFD_RELOC_SPARC_TLS_GD_ADD,
  BFD_RELOC_SPARC_TLS_GD_CALL,
  BFD_RELOC_SPARC_TLS_LDM_HI22,
  BFD_RELOC_SPARC_TLS_LDM_LO10,
  BFD_RELOC_SPARC_TLS_LDM_ADD,
  BFD_RELOC_SPARC_TLS_LDM_CALL,
  BFD_RELOC_SPARC_TLS_LDO_HIX22,
  BFD_RELOC_SPARC_TLS_LDO_LOX10,
  BFD_RELOC_SPARC_TLS_LDO_ADD,
  BFD_RELOC_SPARC_TLS_IE_HI22,
  BFD_RELOC_SPARC_TLS_IE_LO10,
  BFD_RELOC_SPARC_TLS_IE_LD,
  BFD_RELOC_SPARC_TLS_IE_LDX,
  BFD_RELOC_SPARC_TLS_IE_ADD,
  BFD_RELOC_SPARC_TLS_LE_HIX22,
  BFD_RELOC_SPARC_TLS_LE_LOX10,
  BFD_RELOC_SPARC_TLS_DTPMOD32,
  BFD_RELOC_SPARC_TLS_DTPMOD64,
  BFD_RELOC_SPARC_TLS_DTPOFF32,
  BFD_RELOC_SPARC_TLS_DTPOFF64,
  BFD_RELOC_SPARC_TLS_TPOFF32,
  BFD_RELOC_SPARC_TLS_TPOFF64,

  BFD_RELOC_SPU_IMM7,
  BFD_RELOC_SPU_IMM8,
  BFD_RELOC_SPU_IMM10,
  BFD_RELOC_SPU_IMM10W,
  BFD_RELOC_SPU_IMM16,
  BFD_RELOC_SPU_IMM16W,
  BFD_RELOC_SPU_IMM18,
  BFD_RELOC_SPU_PCREL9a,
  BFD_RELOC_SPU_PCREL9b,
  BFD_RELOC_SPU_PCREL16,
  BFD_RELOC_SPU_LO16,
  BFD_RELOC_SPU_HI16,
  BFD_RELOC_SPU_PPU32,
  BFD_RELOC_SPU_PPU64,
  BFD_RELOC_SPU_ADD_PIC,

  BFD_RELOC_ALPHA_GPDISP_HI16,

  BFD_RELOC_ALPHA_GPDISP_LO16,

  BFD_RELOC_ALPHA_GPDISP,
  BFD_RELOC_ALPHA_LITERAL,
  BFD_RELOC_ALPHA_ELF_LITERAL,
  BFD_RELOC_ALPHA_LITUSE,

  BFD_RELOC_ALPHA_HINT,

  BFD_RELOC_ALPHA_LINKAGE,

  BFD_RELOC_ALPHA_CODEADDR,

  BFD_RELOC_ALPHA_GPREL_HI16,
  BFD_RELOC_ALPHA_GPREL_LO16,

  BFD_RELOC_ALPHA_BRSGP,

  BFD_RELOC_ALPHA_NOP,

  BFD_RELOC_ALPHA_BSR,

  BFD_RELOC_ALPHA_LDA,

  BFD_RELOC_ALPHA_BOH,

  BFD_RELOC_ALPHA_TLSGD,
  BFD_RELOC_ALPHA_TLSLDM,
  BFD_RELOC_ALPHA_DTPMOD64,
  BFD_RELOC_ALPHA_GOTDTPREL16,
  BFD_RELOC_ALPHA_DTPREL64,
  BFD_RELOC_ALPHA_DTPREL_HI16,
  BFD_RELOC_ALPHA_DTPREL_LO16,
  BFD_RELOC_ALPHA_DTPREL16,
  BFD_RELOC_ALPHA_GOTTPREL16,
  BFD_RELOC_ALPHA_TPREL64,
  BFD_RELOC_ALPHA_TPREL_HI16,
  BFD_RELOC_ALPHA_TPREL_LO16,
  BFD_RELOC_ALPHA_TPREL16,

  BFD_RELOC_MIPS_JMP,
  BFD_RELOC_MICROMIPS_JMP,

  BFD_RELOC_MIPS16_JMP,

  BFD_RELOC_MIPS16_GPREL,

  BFD_RELOC_HI16,

  BFD_RELOC_HI16_S,

  BFD_RELOC_LO16,

  BFD_RELOC_HI16_PCREL,

  BFD_RELOC_HI16_S_PCREL,

  BFD_RELOC_LO16_PCREL,

  BFD_RELOC_MIPS16_GOT16,
  BFD_RELOC_MIPS16_CALL16,

  BFD_RELOC_MIPS16_HI16,

  BFD_RELOC_MIPS16_HI16_S,

  BFD_RELOC_MIPS16_LO16,

  BFD_RELOC_MIPS16_TLS_GD,
  BFD_RELOC_MIPS16_TLS_LDM,
  BFD_RELOC_MIPS16_TLS_DTPREL_HI16,
  BFD_RELOC_MIPS16_TLS_DTPREL_LO16,
  BFD_RELOC_MIPS16_TLS_GOTTPREL,
  BFD_RELOC_MIPS16_TLS_TPREL_HI16,
  BFD_RELOC_MIPS16_TLS_TPREL_LO16,

  BFD_RELOC_MIPS_LITERAL,
  BFD_RELOC_MICROMIPS_LITERAL,

  BFD_RELOC_MICROMIPS_7_PCREL_S1,
  BFD_RELOC_MICROMIPS_10_PCREL_S1,
  BFD_RELOC_MICROMIPS_16_PCREL_S1,

  BFD_RELOC_MICROMIPS_GPREL16,
  BFD_RELOC_MICROMIPS_HI16,
  BFD_RELOC_MICROMIPS_HI16_S,
  BFD_RELOC_MICROMIPS_LO16,

  BFD_RELOC_MIPS_GOT16,
  BFD_RELOC_MICROMIPS_GOT16,
  BFD_RELOC_MIPS_CALL16,
  BFD_RELOC_MICROMIPS_CALL16,
  BFD_RELOC_MIPS_GOT_HI16,
  BFD_RELOC_MICROMIPS_GOT_HI16,
  BFD_RELOC_MIPS_GOT_LO16,
  BFD_RELOC_MICROMIPS_GOT_LO16,
  BFD_RELOC_MIPS_CALL_HI16,
  BFD_RELOC_MICROMIPS_CALL_HI16,
  BFD_RELOC_MIPS_CALL_LO16,
  BFD_RELOC_MICROMIPS_CALL_LO16,
  BFD_RELOC_MIPS_SUB,
  BFD_RELOC_MICROMIPS_SUB,
  BFD_RELOC_MIPS_GOT_PAGE,
  BFD_RELOC_MICROMIPS_GOT_PAGE,
  BFD_RELOC_MIPS_GOT_OFST,
  BFD_RELOC_MICROMIPS_GOT_OFST,
  BFD_RELOC_MIPS_GOT_DISP,
  BFD_RELOC_MICROMIPS_GOT_DISP,
  BFD_RELOC_MIPS_SHIFT5,
  BFD_RELOC_MIPS_SHIFT6,
  BFD_RELOC_MIPS_INSERT_A,
  BFD_RELOC_MIPS_INSERT_B,
  BFD_RELOC_MIPS_DELETE,
  BFD_RELOC_MIPS_HIGHEST,
  BFD_RELOC_MICROMIPS_HIGHEST,
  BFD_RELOC_MIPS_HIGHER,
  BFD_RELOC_MICROMIPS_HIGHER,
  BFD_RELOC_MIPS_SCN_DISP,
  BFD_RELOC_MICROMIPS_SCN_DISP,
  BFD_RELOC_MIPS_REL16,
  BFD_RELOC_MIPS_RELGOT,
  BFD_RELOC_MIPS_JALR,
  BFD_RELOC_MICROMIPS_JALR,
  BFD_RELOC_MIPS_TLS_DTPMOD32,
  BFD_RELOC_MIPS_TLS_DTPREL32,
  BFD_RELOC_MIPS_TLS_DTPMOD64,
  BFD_RELOC_MIPS_TLS_DTPREL64,
  BFD_RELOC_MIPS_TLS_GD,
  BFD_RELOC_MICROMIPS_TLS_GD,
  BFD_RELOC_MIPS_TLS_LDM,
  BFD_RELOC_MICROMIPS_TLS_LDM,
  BFD_RELOC_MIPS_TLS_DTPREL_HI16,
  BFD_RELOC_MICROMIPS_TLS_DTPREL_HI16,
  BFD_RELOC_MIPS_TLS_DTPREL_LO16,
  BFD_RELOC_MICROMIPS_TLS_DTPREL_LO16,
  BFD_RELOC_MIPS_TLS_GOTTPREL,
  BFD_RELOC_MICROMIPS_TLS_GOTTPREL,
  BFD_RELOC_MIPS_TLS_TPREL32,
  BFD_RELOC_MIPS_TLS_TPREL64,
  BFD_RELOC_MIPS_TLS_TPREL_HI16,
  BFD_RELOC_MICROMIPS_TLS_TPREL_HI16,
  BFD_RELOC_MIPS_TLS_TPREL_LO16,
  BFD_RELOC_MICROMIPS_TLS_TPREL_LO16,
  BFD_RELOC_MIPS_EH,

  BFD_RELOC_MIPS_COPY,
  BFD_RELOC_MIPS_JUMP_SLOT,

  BFD_RELOC_MOXIE_10_PCREL,

  BFD_RELOC_FRV_LABEL16,
  BFD_RELOC_FRV_LABEL24,
  BFD_RELOC_FRV_LO16,
  BFD_RELOC_FRV_HI16,
  BFD_RELOC_FRV_GPREL12,
  BFD_RELOC_FRV_GPRELU12,
  BFD_RELOC_FRV_GPREL32,
  BFD_RELOC_FRV_GPRELHI,
  BFD_RELOC_FRV_GPRELLO,
  BFD_RELOC_FRV_GOT12,
  BFD_RELOC_FRV_GOTHI,
  BFD_RELOC_FRV_GOTLO,
  BFD_RELOC_FRV_FUNCDESC,
  BFD_RELOC_FRV_FUNCDESC_GOT12,
  BFD_RELOC_FRV_FUNCDESC_GOTHI,
  BFD_RELOC_FRV_FUNCDESC_GOTLO,
  BFD_RELOC_FRV_FUNCDESC_VALUE,
  BFD_RELOC_FRV_FUNCDESC_GOTOFF12,
  BFD_RELOC_FRV_FUNCDESC_GOTOFFHI,
  BFD_RELOC_FRV_FUNCDESC_GOTOFFLO,
  BFD_RELOC_FRV_GOTOFF12,
  BFD_RELOC_FRV_GOTOFFHI,
  BFD_RELOC_FRV_GOTOFFLO,
  BFD_RELOC_FRV_GETTLSOFF,
  BFD_RELOC_FRV_TLSDESC_VALUE,
  BFD_RELOC_FRV_GOTTLSDESC12,
  BFD_RELOC_FRV_GOTTLSDESCHI,
  BFD_RELOC_FRV_GOTTLSDESCLO,
  BFD_RELOC_FRV_TLSMOFF12,
  BFD_RELOC_FRV_TLSMOFFHI,
  BFD_RELOC_FRV_TLSMOFFLO,
  BFD_RELOC_FRV_GOTTLSOFF12,
  BFD_RELOC_FRV_GOTTLSOFFHI,
  BFD_RELOC_FRV_GOTTLSOFFLO,
  BFD_RELOC_FRV_TLSOFF,
  BFD_RELOC_FRV_TLSDESC_RELAX,
  BFD_RELOC_FRV_GETTLSOFF_RELAX,
  BFD_RELOC_FRV_TLSOFF_RELAX,
  BFD_RELOC_FRV_TLSMOFF,

  BFD_RELOC_MN10300_GOTOFF24,

  BFD_RELOC_MN10300_GOT32,

  BFD_RELOC_MN10300_GOT24,

  BFD_RELOC_MN10300_GOT16,

  BFD_RELOC_MN10300_COPY,

  BFD_RELOC_MN10300_GLOB_DAT,

  BFD_RELOC_MN10300_JMP_SLOT,

  BFD_RELOC_MN10300_RELATIVE,

  BFD_RELOC_MN10300_SYM_DIFF,

  BFD_RELOC_MN10300_ALIGN,

  BFD_RELOC_MN10300_TLS_GD,
  BFD_RELOC_MN10300_TLS_LD,
  BFD_RELOC_MN10300_TLS_LDO,
  BFD_RELOC_MN10300_TLS_GOTIE,
  BFD_RELOC_MN10300_TLS_IE,
  BFD_RELOC_MN10300_TLS_LE,
  BFD_RELOC_MN10300_TLS_DTPMOD,
  BFD_RELOC_MN10300_TLS_DTPOFF,
  BFD_RELOC_MN10300_TLS_TPOFF,

  BFD_RELOC_MN10300_32_PCREL,

  BFD_RELOC_MN10300_16_PCREL,

  BFD_RELOC_386_GOT32,
  BFD_RELOC_386_PLT32,
  BFD_RELOC_386_COPY,
  BFD_RELOC_386_GLOB_DAT,
  BFD_RELOC_386_JUMP_SLOT,
  BFD_RELOC_386_RELATIVE,
  BFD_RELOC_386_GOTOFF,
  BFD_RELOC_386_GOTPC,
  BFD_RELOC_386_TLS_TPOFF,
  BFD_RELOC_386_TLS_IE,
  BFD_RELOC_386_TLS_GOTIE,
  BFD_RELOC_386_TLS_LE,
  BFD_RELOC_386_TLS_GD,
  BFD_RELOC_386_TLS_LDM,
  BFD_RELOC_386_TLS_LDO_32,
  BFD_RELOC_386_TLS_IE_32,
  BFD_RELOC_386_TLS_LE_32,
  BFD_RELOC_386_TLS_DTPMOD32,
  BFD_RELOC_386_TLS_DTPOFF32,
  BFD_RELOC_386_TLS_TPOFF32,
  BFD_RELOC_386_TLS_GOTDESC,
  BFD_RELOC_386_TLS_DESC_CALL,
  BFD_RELOC_386_TLS_DESC,
  BFD_RELOC_386_IRELATIVE,

  BFD_RELOC_X86_64_GOT32,
  BFD_RELOC_X86_64_PLT32,
  BFD_RELOC_X86_64_COPY,
  BFD_RELOC_X86_64_GLOB_DAT,
  BFD_RELOC_X86_64_JUMP_SLOT,
  BFD_RELOC_X86_64_RELATIVE,
  BFD_RELOC_X86_64_GOTPCREL,
  BFD_RELOC_X86_64_32S,
  BFD_RELOC_X86_64_DTPMOD64,
  BFD_RELOC_X86_64_DTPOFF64,
  BFD_RELOC_X86_64_TPOFF64,
  BFD_RELOC_X86_64_TLSGD,
  BFD_RELOC_X86_64_TLSLD,
  BFD_RELOC_X86_64_DTPOFF32,
  BFD_RELOC_X86_64_GOTTPOFF,
  BFD_RELOC_X86_64_TPOFF32,
  BFD_RELOC_X86_64_GOTOFF64,
  BFD_RELOC_X86_64_GOTPC32,
  BFD_RELOC_X86_64_GOT64,
  BFD_RELOC_X86_64_GOTPCREL64,
  BFD_RELOC_X86_64_GOTPC64,
  BFD_RELOC_X86_64_GOTPLT64,
  BFD_RELOC_X86_64_PLTOFF64,
  BFD_RELOC_X86_64_GOTPC32_TLSDESC,
  BFD_RELOC_X86_64_TLSDESC_CALL,
  BFD_RELOC_X86_64_TLSDESC,
  BFD_RELOC_X86_64_IRELATIVE,
  BFD_RELOC_X86_64_PC32_BND,
  BFD_RELOC_X86_64_PLT32_BND,

  BFD_RELOC_NS32K_IMM_8,
  BFD_RELOC_NS32K_IMM_16,
  BFD_RELOC_NS32K_IMM_32,
  BFD_RELOC_NS32K_IMM_8_PCREL,
  BFD_RELOC_NS32K_IMM_16_PCREL,
  BFD_RELOC_NS32K_IMM_32_PCREL,
  BFD_RELOC_NS32K_DISP_8,
  BFD_RELOC_NS32K_DISP_16,
  BFD_RELOC_NS32K_DISP_32,
  BFD_RELOC_NS32K_DISP_8_PCREL,
  BFD_RELOC_NS32K_DISP_16_PCREL,
  BFD_RELOC_NS32K_DISP_32_PCREL,

  BFD_RELOC_PDP11_DISP_8_PCREL,
  BFD_RELOC_PDP11_DISP_6_PCREL,

  BFD_RELOC_PJ_CODE_HI16,
  BFD_RELOC_PJ_CODE_LO16,
  BFD_RELOC_PJ_CODE_DIR16,
  BFD_RELOC_PJ_CODE_DIR32,
  BFD_RELOC_PJ_CODE_REL16,
  BFD_RELOC_PJ_CODE_REL32,

  BFD_RELOC_PPC_B26,
  BFD_RELOC_PPC_BA26,
  BFD_RELOC_PPC_TOC16,
  BFD_RELOC_PPC_B16,
  BFD_RELOC_PPC_B16_BRTAKEN,
  BFD_RELOC_PPC_B16_BRNTAKEN,
  BFD_RELOC_PPC_BA16,
  BFD_RELOC_PPC_BA16_BRTAKEN,
  BFD_RELOC_PPC_BA16_BRNTAKEN,
  BFD_RELOC_PPC_COPY,
  BFD_RELOC_PPC_GLOB_DAT,
  BFD_RELOC_PPC_JMP_SLOT,
  BFD_RELOC_PPC_RELATIVE,
  BFD_RELOC_PPC_LOCAL24PC,
  BFD_RELOC_PPC_EMB_NADDR32,
  BFD_RELOC_PPC_EMB_NADDR16,
  BFD_RELOC_PPC_EMB_NADDR16_LO,
  BFD_RELOC_PPC_EMB_NADDR16_HI,
  BFD_RELOC_PPC_EMB_NADDR16_HA,
  BFD_RELOC_PPC_EMB_SDAI16,
  BFD_RELOC_PPC_EMB_SDA2I16,
  BFD_RELOC_PPC_EMB_SDA2REL,
  BFD_RELOC_PPC_EMB_SDA21,
  BFD_RELOC_PPC_EMB_MRKREF,
  BFD_RELOC_PPC_EMB_RELSEC16,
  BFD_RELOC_PPC_EMB_RELST_LO,
  BFD_RELOC_PPC_EMB_RELST_HI,
  BFD_RELOC_PPC_EMB_RELST_HA,
  BFD_RELOC_PPC_EMB_BIT_FLD,
  BFD_RELOC_PPC_EMB_RELSDA,
  BFD_RELOC_PPC_VLE_REL8,
  BFD_RELOC_PPC_VLE_REL15,
  BFD_RELOC_PPC_VLE_REL24,
  BFD_RELOC_PPC_VLE_LO16A,
  BFD_RELOC_PPC_VLE_LO16D,
  BFD_RELOC_PPC_VLE_HI16A,
  BFD_RELOC_PPC_VLE_HI16D,
  BFD_RELOC_PPC_VLE_HA16A,
  BFD_RELOC_PPC_VLE_HA16D,
  BFD_RELOC_PPC_VLE_SDA21,
  BFD_RELOC_PPC_VLE_SDA21_LO,
  BFD_RELOC_PPC_VLE_SDAREL_LO16A,
  BFD_RELOC_PPC_VLE_SDAREL_LO16D,
  BFD_RELOC_PPC_VLE_SDAREL_HI16A,
  BFD_RELOC_PPC_VLE_SDAREL_HI16D,
  BFD_RELOC_PPC_VLE_SDAREL_HA16A,
  BFD_RELOC_PPC_VLE_SDAREL_HA16D,
  BFD_RELOC_PPC64_HIGHER,
  BFD_RELOC_PPC64_HIGHER_S,
  BFD_RELOC_PPC64_HIGHEST,
  BFD_RELOC_PPC64_HIGHEST_S,
  BFD_RELOC_PPC64_TOC16_LO,
  BFD_RELOC_PPC64_TOC16_HI,
  BFD_RELOC_PPC64_TOC16_HA,
  BFD_RELOC_PPC64_TOC,
  BFD_RELOC_PPC64_PLTGOT16,
  BFD_RELOC_PPC64_PLTGOT16_LO,
  BFD_RELOC_PPC64_PLTGOT16_HI,
  BFD_RELOC_PPC64_PLTGOT16_HA,
  BFD_RELOC_PPC64_ADDR16_DS,
  BFD_RELOC_PPC64_ADDR16_LO_DS,
  BFD_RELOC_PPC64_GOT16_DS,
  BFD_RELOC_PPC64_GOT16_LO_DS,
  BFD_RELOC_PPC64_PLT16_LO_DS,
  BFD_RELOC_PPC64_SECTOFF_DS,
  BFD_RELOC_PPC64_SECTOFF_LO_DS,
  BFD_RELOC_PPC64_TOC16_DS,
  BFD_RELOC_PPC64_TOC16_LO_DS,
  BFD_RELOC_PPC64_PLTGOT16_DS,
  BFD_RELOC_PPC64_PLTGOT16_LO_DS,
  BFD_RELOC_PPC64_ADDR16_HIGH,
  BFD_RELOC_PPC64_ADDR16_HIGHA,
  BFD_RELOC_PPC64_ADDR64_LOCAL,

  BFD_RELOC_PPC_TLS,
  BFD_RELOC_PPC_TLSGD,
  BFD_RELOC_PPC_TLSLD,
  BFD_RELOC_PPC_DTPMOD,
  BFD_RELOC_PPC_TPREL16,
  BFD_RELOC_PPC_TPREL16_LO,
  BFD_RELOC_PPC_TPREL16_HI,
  BFD_RELOC_PPC_TPREL16_HA,
  BFD_RELOC_PPC_TPREL,
  BFD_RELOC_PPC_DTPREL16,
  BFD_RELOC_PPC_DTPREL16_LO,
  BFD_RELOC_PPC_DTPREL16_HI,
  BFD_RELOC_PPC_DTPREL16_HA,
  BFD_RELOC_PPC_DTPREL,
  BFD_RELOC_PPC_GOT_TLSGD16,
  BFD_RELOC_PPC_GOT_TLSGD16_LO,
  BFD_RELOC_PPC_GOT_TLSGD16_HI,
  BFD_RELOC_PPC_GOT_TLSGD16_HA,
  BFD_RELOC_PPC_GOT_TLSLD16,
  BFD_RELOC_PPC_GOT_TLSLD16_LO,
  BFD_RELOC_PPC_GOT_TLSLD16_HI,
  BFD_RELOC_PPC_GOT_TLSLD16_HA,
  BFD_RELOC_PPC_GOT_TPREL16,
  BFD_RELOC_PPC_GOT_TPREL16_LO,
  BFD_RELOC_PPC_GOT_TPREL16_HI,
  BFD_RELOC_PPC_GOT_TPREL16_HA,
  BFD_RELOC_PPC_GOT_DTPREL16,
  BFD_RELOC_PPC_GOT_DTPREL16_LO,
  BFD_RELOC_PPC_GOT_DTPREL16_HI,
  BFD_RELOC_PPC_GOT_DTPREL16_HA,
  BFD_RELOC_PPC64_TPREL16_DS,
  BFD_RELOC_PPC64_TPREL16_LO_DS,
  BFD_RELOC_PPC64_TPREL16_HIGHER,
  BFD_RELOC_PPC64_TPREL16_HIGHERA,
  BFD_RELOC_PPC64_TPREL16_HIGHEST,
  BFD_RELOC_PPC64_TPREL16_HIGHESTA,
  BFD_RELOC_PPC64_DTPREL16_DS,
  BFD_RELOC_PPC64_DTPREL16_LO_DS,
  BFD_RELOC_PPC64_DTPREL16_HIGHER,
  BFD_RELOC_PPC64_DTPREL16_HIGHERA,
  BFD_RELOC_PPC64_DTPREL16_HIGHEST,
  BFD_RELOC_PPC64_DTPREL16_HIGHESTA,
  BFD_RELOC_PPC64_TPREL16_HIGH,
  BFD_RELOC_PPC64_TPREL16_HIGHA,
  BFD_RELOC_PPC64_DTPREL16_HIGH,
  BFD_RELOC_PPC64_DTPREL16_HIGHA,

  BFD_RELOC_I370_D12,

  BFD_RELOC_CTOR,

  BFD_RELOC_ARM_PCREL_BRANCH,

  BFD_RELOC_ARM_PCREL_BLX,

  BFD_RELOC_THUMB_PCREL_BLX,

  BFD_RELOC_ARM_PCREL_CALL,

  BFD_RELOC_ARM_PCREL_JUMP,

  BFD_RELOC_THUMB_PCREL_BRANCH7,
  BFD_RELOC_THUMB_PCREL_BRANCH9,
  BFD_RELOC_THUMB_PCREL_BRANCH12,
  BFD_RELOC_THUMB_PCREL_BRANCH20,
  BFD_RELOC_THUMB_PCREL_BRANCH23,
  BFD_RELOC_THUMB_PCREL_BRANCH25,

  BFD_RELOC_ARM_OFFSET_IMM,

  BFD_RELOC_ARM_THUMB_OFFSET,

  BFD_RELOC_ARM_TARGET1,

  BFD_RELOC_ARM_ROSEGREL32,

  BFD_RELOC_ARM_SBREL32,

  BFD_RELOC_ARM_TARGET2,

  BFD_RELOC_ARM_PREL31,

  BFD_RELOC_ARM_MOVW,
  BFD_RELOC_ARM_MOVT,
  BFD_RELOC_ARM_MOVW_PCREL,
  BFD_RELOC_ARM_MOVT_PCREL,
  BFD_RELOC_ARM_THUMB_MOVW,
  BFD_RELOC_ARM_THUMB_MOVT,
  BFD_RELOC_ARM_THUMB_MOVW_PCREL,
  BFD_RELOC_ARM_THUMB_MOVT_PCREL,

  BFD_RELOC_ARM_JUMP_SLOT,
  BFD_RELOC_ARM_GLOB_DAT,
  BFD_RELOC_ARM_GOT32,
  BFD_RELOC_ARM_PLT32,
  BFD_RELOC_ARM_RELATIVE,
  BFD_RELOC_ARM_GOTOFF,
  BFD_RELOC_ARM_GOTPC,
  BFD_RELOC_ARM_GOT_PREL,

  BFD_RELOC_ARM_TLS_GD32,
  BFD_RELOC_ARM_TLS_LDO32,
  BFD_RELOC_ARM_TLS_LDM32,
  BFD_RELOC_ARM_TLS_DTPOFF32,
  BFD_RELOC_ARM_TLS_DTPMOD32,
  BFD_RELOC_ARM_TLS_TPOFF32,
  BFD_RELOC_ARM_TLS_IE32,
  BFD_RELOC_ARM_TLS_LE32,
  BFD_RELOC_ARM_TLS_GOTDESC,
  BFD_RELOC_ARM_TLS_CALL,
  BFD_RELOC_ARM_THM_TLS_CALL,
  BFD_RELOC_ARM_TLS_DESCSEQ,
  BFD_RELOC_ARM_THM_TLS_DESCSEQ,
  BFD_RELOC_ARM_TLS_DESC,

  BFD_RELOC_ARM_ALU_PC_G0_NC,
  BFD_RELOC_ARM_ALU_PC_G0,
  BFD_RELOC_ARM_ALU_PC_G1_NC,
  BFD_RELOC_ARM_ALU_PC_G1,
  BFD_RELOC_ARM_ALU_PC_G2,
  BFD_RELOC_ARM_LDR_PC_G0,
  BFD_RELOC_ARM_LDR_PC_G1,
  BFD_RELOC_ARM_LDR_PC_G2,
  BFD_RELOC_ARM_LDRS_PC_G0,
  BFD_RELOC_ARM_LDRS_PC_G1,
  BFD_RELOC_ARM_LDRS_PC_G2,
  BFD_RELOC_ARM_LDC_PC_G0,
  BFD_RELOC_ARM_LDC_PC_G1,
  BFD_RELOC_ARM_LDC_PC_G2,
  BFD_RELOC_ARM_ALU_SB_G0_NC,
  BFD_RELOC_ARM_ALU_SB_G0,
  BFD_RELOC_ARM_ALU_SB_G1_NC,
  BFD_RELOC_ARM_ALU_SB_G1,
  BFD_RELOC_ARM_ALU_SB_G2,
  BFD_RELOC_ARM_LDR_SB_G0,
  BFD_RELOC_ARM_LDR_SB_G1,
  BFD_RELOC_ARM_LDR_SB_G2,
  BFD_RELOC_ARM_LDRS_SB_G0,
  BFD_RELOC_ARM_LDRS_SB_G1,
  BFD_RELOC_ARM_LDRS_SB_G2,
  BFD_RELOC_ARM_LDC_SB_G0,
  BFD_RELOC_ARM_LDC_SB_G1,
  BFD_RELOC_ARM_LDC_SB_G2,

  BFD_RELOC_ARM_V4BX,

  BFD_RELOC_ARM_IRELATIVE,

  BFD_RELOC_ARM_IMMEDIATE,
  BFD_RELOC_ARM_ADRL_IMMEDIATE,
  BFD_RELOC_ARM_T32_IMMEDIATE,
  BFD_RELOC_ARM_T32_ADD_IMM,
  BFD_RELOC_ARM_T32_IMM12,
  BFD_RELOC_ARM_T32_ADD_PC12,
  BFD_RELOC_ARM_SHIFT_IMM,
  BFD_RELOC_ARM_SMC,
  BFD_RELOC_ARM_HVC,
  BFD_RELOC_ARM_SWI,
  BFD_RELOC_ARM_MULTI,
  BFD_RELOC_ARM_CP_OFF_IMM,
  BFD_RELOC_ARM_CP_OFF_IMM_S2,
  BFD_RELOC_ARM_T32_CP_OFF_IMM,
  BFD_RELOC_ARM_T32_CP_OFF_IMM_S2,
  BFD_RELOC_ARM_ADR_IMM,
  BFD_RELOC_ARM_LDR_IMM,
  BFD_RELOC_ARM_LITERAL,
  BFD_RELOC_ARM_IN_POOL,
  BFD_RELOC_ARM_OFFSET_IMM8,
  BFD_RELOC_ARM_T32_OFFSET_U8,
  BFD_RELOC_ARM_T32_OFFSET_IMM,
  BFD_RELOC_ARM_HWLITERAL,
  BFD_RELOC_ARM_THUMB_ADD,
  BFD_RELOC_ARM_THUMB_IMM,
  BFD_RELOC_ARM_THUMB_SHIFT,

  BFD_RELOC_SH_PCDISP8BY2,
  BFD_RELOC_SH_PCDISP12BY2,
  BFD_RELOC_SH_IMM3,
  BFD_RELOC_SH_IMM3U,
  BFD_RELOC_SH_DISP12,
  BFD_RELOC_SH_DISP12BY2,
  BFD_RELOC_SH_DISP12BY4,
  BFD_RELOC_SH_DISP12BY8,
  BFD_RELOC_SH_DISP20,
  BFD_RELOC_SH_DISP20BY8,
  BFD_RELOC_SH_IMM4,
  BFD_RELOC_SH_IMM4BY2,
  BFD_RELOC_SH_IMM4BY4,
  BFD_RELOC_SH_IMM8,
  BFD_RELOC_SH_IMM8BY2,
  BFD_RELOC_SH_IMM8BY4,
  BFD_RELOC_SH_PCRELIMM8BY2,
  BFD_RELOC_SH_PCRELIMM8BY4,
  BFD_RELOC_SH_SWITCH16,
  BFD_RELOC_SH_SWITCH32,
  BFD_RELOC_SH_USES,
  BFD_RELOC_SH_COUNT,
  BFD_RELOC_SH_ALIGN,
  BFD_RELOC_SH_CODE,
  BFD_RELOC_SH_DATA,
  BFD_RELOC_SH_LABEL,
  BFD_RELOC_SH_LOOP_START,
  BFD_RELOC_SH_LOOP_END,
  BFD_RELOC_SH_COPY,
  BFD_RELOC_SH_GLOB_DAT,
  BFD_RELOC_SH_JMP_SLOT,
  BFD_RELOC_SH_RELATIVE,
  BFD_RELOC_SH_GOTPC,
  BFD_RELOC_SH_GOT_LOW16,
  BFD_RELOC_SH_GOT_MEDLOW16,
  BFD_RELOC_SH_GOT_MEDHI16,
  BFD_RELOC_SH_GOT_HI16,
  BFD_RELOC_SH_GOTPLT_LOW16,
  BFD_RELOC_SH_GOTPLT_MEDLOW16,
  BFD_RELOC_SH_GOTPLT_MEDHI16,
  BFD_RELOC_SH_GOTPLT_HI16,
  BFD_RELOC_SH_PLT_LOW16,
  BFD_RELOC_SH_PLT_MEDLOW16,
  BFD_RELOC_SH_PLT_MEDHI16,
  BFD_RELOC_SH_PLT_HI16,
  BFD_RELOC_SH_GOTOFF_LOW16,
  BFD_RELOC_SH_GOTOFF_MEDLOW16,
  BFD_RELOC_SH_GOTOFF_MEDHI16,
  BFD_RELOC_SH_GOTOFF_HI16,
  BFD_RELOC_SH_GOTPC_LOW16,
  BFD_RELOC_SH_GOTPC_MEDLOW16,
  BFD_RELOC_SH_GOTPC_MEDHI16,
  BFD_RELOC_SH_GOTPC_HI16,
  BFD_RELOC_SH_COPY64,
  BFD_RELOC_SH_GLOB_DAT64,
  BFD_RELOC_SH_JMP_SLOT64,
  BFD_RELOC_SH_RELATIVE64,
  BFD_RELOC_SH_GOT10BY4,
  BFD_RELOC_SH_GOT10BY8,
  BFD_RELOC_SH_GOTPLT10BY4,
  BFD_RELOC_SH_GOTPLT10BY8,
  BFD_RELOC_SH_GOTPLT32,
  BFD_RELOC_SH_SHMEDIA_CODE,
  BFD_RELOC_SH_IMMU5,
  BFD_RELOC_SH_IMMS6,
  BFD_RELOC_SH_IMMS6BY32,
  BFD_RELOC_SH_IMMU6,
  BFD_RELOC_SH_IMMS10,
  BFD_RELOC_SH_IMMS10BY2,
  BFD_RELOC_SH_IMMS10BY4,
  BFD_RELOC_SH_IMMS10BY8,
  BFD_RELOC_SH_IMMS16,
  BFD_RELOC_SH_IMMU16,
  BFD_RELOC_SH_IMM_LOW16,
  BFD_RELOC_SH_IMM_LOW16_PCREL,
  BFD_RELOC_SH_IMM_MEDLOW16,
  BFD_RELOC_SH_IMM_MEDLOW16_PCREL,
  BFD_RELOC_SH_IMM_MEDHI16,
  BFD_RELOC_SH_IMM_MEDHI16_PCREL,
  BFD_RELOC_SH_IMM_HI16,
  BFD_RELOC_SH_IMM_HI16_PCREL,
  BFD_RELOC_SH_PT_16,
  BFD_RELOC_SH_TLS_GD_32,
  BFD_RELOC_SH_TLS_LD_32,
  BFD_RELOC_SH_TLS_LDO_32,
  BFD_RELOC_SH_TLS_IE_32,
  BFD_RELOC_SH_TLS_LE_32,
  BFD_RELOC_SH_TLS_DTPMOD32,
  BFD_RELOC_SH_TLS_DTPOFF32,
  BFD_RELOC_SH_TLS_TPOFF32,
  BFD_RELOC_SH_GOT20,
  BFD_RELOC_SH_GOTOFF20,
  BFD_RELOC_SH_GOTFUNCDESC,
  BFD_RELOC_SH_GOTFUNCDESC20,
  BFD_RELOC_SH_GOTOFFFUNCDESC,
  BFD_RELOC_SH_GOTOFFFUNCDESC20,
  BFD_RELOC_SH_FUNCDESC,

  BFD_RELOC_ARC_B22_PCREL,

  BFD_RELOC_ARC_B26,

  BFD_RELOC_BFIN_16_IMM,

  BFD_RELOC_BFIN_16_HIGH,

  BFD_RELOC_BFIN_4_PCREL,

  BFD_RELOC_BFIN_5_PCREL,

  BFD_RELOC_BFIN_16_LOW,

  BFD_RELOC_BFIN_10_PCREL,

  BFD_RELOC_BFIN_11_PCREL,

  BFD_RELOC_BFIN_12_PCREL_JUMP,

  BFD_RELOC_BFIN_12_PCREL_JUMP_S,

  BFD_RELOC_BFIN_24_PCREL_CALL_X,

  BFD_RELOC_BFIN_24_PCREL_JUMP_L,

  BFD_RELOC_BFIN_GOT17M4,
  BFD_RELOC_BFIN_GOTHI,
  BFD_RELOC_BFIN_GOTLO,
  BFD_RELOC_BFIN_FUNCDESC,
  BFD_RELOC_BFIN_FUNCDESC_GOT17M4,
  BFD_RELOC_BFIN_FUNCDESC_GOTHI,
  BFD_RELOC_BFIN_FUNCDESC_GOTLO,
  BFD_RELOC_BFIN_FUNCDESC_VALUE,
  BFD_RELOC_BFIN_FUNCDESC_GOTOFF17M4,
  BFD_RELOC_BFIN_FUNCDESC_GOTOFFHI,
  BFD_RELOC_BFIN_FUNCDESC_GOTOFFLO,
  BFD_RELOC_BFIN_GOTOFF17M4,
  BFD_RELOC_BFIN_GOTOFFHI,
  BFD_RELOC_BFIN_GOTOFFLO,

  BFD_RELOC_BFIN_GOT,

  BFD_RELOC_BFIN_PLTPC,

  BFD_ARELOC_BFIN_PUSH,

  BFD_ARELOC_BFIN_CONST,

  BFD_ARELOC_BFIN_ADD,

  BFD_ARELOC_BFIN_SUB,

  BFD_ARELOC_BFIN_MULT,

  BFD_ARELOC_BFIN_DIV,

  BFD_ARELOC_BFIN_MOD,

  BFD_ARELOC_BFIN_LSHIFT,

  BFD_ARELOC_BFIN_RSHIFT,

  BFD_ARELOC_BFIN_AND,

  BFD_ARELOC_BFIN_OR,

  BFD_ARELOC_BFIN_XOR,

  BFD_ARELOC_BFIN_LAND,

  BFD_ARELOC_BFIN_LOR,

  BFD_ARELOC_BFIN_LEN,

  BFD_ARELOC_BFIN_NEG,

  BFD_ARELOC_BFIN_COMP,

  BFD_ARELOC_BFIN_PAGE,

  BFD_ARELOC_BFIN_HWPAGE,

  BFD_ARELOC_BFIN_ADDR,

  BFD_RELOC_D10V_10_PCREL_R,

  BFD_RELOC_D10V_10_PCREL_L,

  BFD_RELOC_D10V_18,

  BFD_RELOC_D10V_18_PCREL,

  BFD_RELOC_D30V_6,

  BFD_RELOC_D30V_9_PCREL,

  BFD_RELOC_D30V_9_PCREL_R,

  BFD_RELOC_D30V_15,

  BFD_RELOC_D30V_15_PCREL,

  BFD_RELOC_D30V_15_PCREL_R,

  BFD_RELOC_D30V_21,

  BFD_RELOC_D30V_21_PCREL,

  BFD_RELOC_D30V_21_PCREL_R,

  BFD_RELOC_D30V_32,

  BFD_RELOC_D30V_32_PCREL,

  BFD_RELOC_DLX_HI16_S,

  BFD_RELOC_DLX_LO16,

  BFD_RELOC_DLX_JMP26,

  BFD_RELOC_M32C_HI8,
  BFD_RELOC_M32C_RL_JUMP,
  BFD_RELOC_M32C_RL_1ADDR,
  BFD_RELOC_M32C_RL_2ADDR,

  BFD_RELOC_M32R_24,

  BFD_RELOC_M32R_10_PCREL,

  BFD_RELOC_M32R_18_PCREL,

  BFD_RELOC_M32R_26_PCREL,

  BFD_RELOC_M32R_HI16_ULO,

  BFD_RELOC_M32R_HI16_SLO,

  BFD_RELOC_M32R_LO16,

  BFD_RELOC_M32R_SDA16,

  BFD_RELOC_M32R_GOT24,
  BFD_RELOC_M32R_26_PLTREL,
  BFD_RELOC_M32R_COPY,
  BFD_RELOC_M32R_GLOB_DAT,
  BFD_RELOC_M32R_JMP_SLOT,
  BFD_RELOC_M32R_RELATIVE,
  BFD_RELOC_M32R_GOTOFF,
  BFD_RELOC_M32R_GOTOFF_HI_ULO,
  BFD_RELOC_M32R_GOTOFF_HI_SLO,
  BFD_RELOC_M32R_GOTOFF_LO,
  BFD_RELOC_M32R_GOTPC24,
  BFD_RELOC_M32R_GOT16_HI_ULO,
  BFD_RELOC_M32R_GOT16_HI_SLO,
  BFD_RELOC_M32R_GOT16_LO,
  BFD_RELOC_M32R_GOTPC_HI_ULO,
  BFD_RELOC_M32R_GOTPC_HI_SLO,
  BFD_RELOC_M32R_GOTPC_LO,

  BFD_RELOC_NDS32_20,

  BFD_RELOC_NDS32_9_PCREL,

  BFD_RELOC_NDS32_WORD_9_PCREL,

  BFD_RELOC_NDS32_15_PCREL,

  BFD_RELOC_NDS32_17_PCREL,

  BFD_RELOC_NDS32_25_PCREL,

  BFD_RELOC_NDS32_HI20,

  BFD_RELOC_NDS32_LO12S3,

  BFD_RELOC_NDS32_LO12S2,

  BFD_RELOC_NDS32_LO12S1,

  BFD_RELOC_NDS32_LO12S0,

  BFD_RELOC_NDS32_LO12S0_ORI,

  BFD_RELOC_NDS32_SDA15S3,

  BFD_RELOC_NDS32_SDA15S2,

  BFD_RELOC_NDS32_SDA15S1,

  BFD_RELOC_NDS32_SDA15S0,

  BFD_RELOC_NDS32_SDA16S3,

  BFD_RELOC_NDS32_SDA17S2,

  BFD_RELOC_NDS32_SDA18S1,

  BFD_RELOC_NDS32_SDA19S0,

  BFD_RELOC_NDS32_GOT20,
  BFD_RELOC_NDS32_9_PLTREL,
  BFD_RELOC_NDS32_25_PLTREL,
  BFD_RELOC_NDS32_COPY,
  BFD_RELOC_NDS32_GLOB_DAT,
  BFD_RELOC_NDS32_JMP_SLOT,
  BFD_RELOC_NDS32_RELATIVE,
  BFD_RELOC_NDS32_GOTOFF,
  BFD_RELOC_NDS32_GOTOFF_HI20,
  BFD_RELOC_NDS32_GOTOFF_LO12,
  BFD_RELOC_NDS32_GOTPC20,
  BFD_RELOC_NDS32_GOT_HI20,
  BFD_RELOC_NDS32_GOT_LO12,
  BFD_RELOC_NDS32_GOTPC_HI20,
  BFD_RELOC_NDS32_GOTPC_LO12,

  BFD_RELOC_NDS32_INSN16,
  BFD_RELOC_NDS32_LABEL,
  BFD_RELOC_NDS32_LONGCALL1,
  BFD_RELOC_NDS32_LONGCALL2,
  BFD_RELOC_NDS32_LONGCALL3,
  BFD_RELOC_NDS32_LONGJUMP1,
  BFD_RELOC_NDS32_LONGJUMP2,
  BFD_RELOC_NDS32_LONGJUMP3,
  BFD_RELOC_NDS32_LOADSTORE,
  BFD_RELOC_NDS32_9_FIXED,
  BFD_RELOC_NDS32_15_FIXED,
  BFD_RELOC_NDS32_17_FIXED,
  BFD_RELOC_NDS32_25_FIXED,

  BFD_RELOC_NDS32_PLTREL_HI20,
  BFD_RELOC_NDS32_PLTREL_LO12,
  BFD_RELOC_NDS32_PLT_GOTREL_HI20,
  BFD_RELOC_NDS32_PLT_GOTREL_LO12,

  BFD_RELOC_NDS32_SDA12S2_DP,
  BFD_RELOC_NDS32_SDA12S2_SP,
  BFD_RELOC_NDS32_LO12S2_DP,
  BFD_RELOC_NDS32_LO12S2_SP,

  BFD_RELOC_NDS32_DWARF2_OP1,
  BFD_RELOC_NDS32_DWARF2_OP2,
  BFD_RELOC_NDS32_DWARF2_LEB,

  BFD_RELOC_NDS32_UPDATE_TA,

  BFD_RELOC_NDS32_PLT_GOTREL_LO20,
  BFD_RELOC_NDS32_PLT_GOTREL_LO15,
  BFD_RELOC_NDS32_PLT_GOTREL_LO19,
  BFD_RELOC_NDS32_GOT_LO15,
  BFD_RELOC_NDS32_GOT_LO19,
  BFD_RELOC_NDS32_GOTOFF_LO15,
  BFD_RELOC_NDS32_GOTOFF_LO19,
  BFD_RELOC_NDS32_GOT15S2,
  BFD_RELOC_NDS32_GOT17S2,

  BFD_RELOC_NDS32_5,

  BFD_RELOC_NDS32_10_UPCREL,

  BFD_RELOC_NDS32_SDA_FP7U2_RELA,

  BFD_RELOC_NDS32_RELAX_ENTRY,
  BFD_RELOC_NDS32_GOT_SUFF,
  BFD_RELOC_NDS32_GOTOFF_SUFF,
  BFD_RELOC_NDS32_PLT_GOT_SUFF,
  BFD_RELOC_NDS32_MULCALL_SUFF,
  BFD_RELOC_NDS32_PTR,
  BFD_RELOC_NDS32_PTR_COUNT,
  BFD_RELOC_NDS32_PTR_RESOLVED,
  BFD_RELOC_NDS32_PLTBLOCK,
  BFD_RELOC_NDS32_RELAX_REGION_BEGIN,
  BFD_RELOC_NDS32_RELAX_REGION_END,
  BFD_RELOC_NDS32_MINUEND,
  BFD_RELOC_NDS32_SUBTRAHEND,
  BFD_RELOC_NDS32_DIFF8,
  BFD_RELOC_NDS32_DIFF16,
  BFD_RELOC_NDS32_DIFF32,
  BFD_RELOC_NDS32_DIFF_ULEB128,
  BFD_RELOC_NDS32_25_ABS,
  BFD_RELOC_NDS32_DATA,
  BFD_RELOC_NDS32_TRAN,
  BFD_RELOC_NDS32_17IFC_PCREL,
  BFD_RELOC_NDS32_10IFCU_PCREL,

  BFD_RELOC_V850_9_PCREL,

  BFD_RELOC_V850_22_PCREL,

  BFD_RELOC_V850_SDA_16_16_OFFSET,

  BFD_RELOC_V850_SDA_15_16_OFFSET,

  BFD_RELOC_V850_ZDA_16_16_OFFSET,

  BFD_RELOC_V850_ZDA_15_16_OFFSET,

  BFD_RELOC_V850_TDA_6_8_OFFSET,

  BFD_RELOC_V850_TDA_7_8_OFFSET,

  BFD_RELOC_V850_TDA_7_7_OFFSET,

  BFD_RELOC_V850_TDA_16_16_OFFSET,

  BFD_RELOC_V850_TDA_4_5_OFFSET,

  BFD_RELOC_V850_TDA_4_4_OFFSET,

  BFD_RELOC_V850_SDA_16_16_SPLIT_OFFSET,

  BFD_RELOC_V850_ZDA_16_16_SPLIT_OFFSET,

  BFD_RELOC_V850_CALLT_6_7_OFFSET,

  BFD_RELOC_V850_CALLT_16_16_OFFSET,

  BFD_RELOC_V850_LONGCALL,

  BFD_RELOC_V850_LONGJUMP,

  BFD_RELOC_V850_ALIGN,

  BFD_RELOC_V850_LO16_SPLIT_OFFSET,

  BFD_RELOC_V850_16_PCREL,

  BFD_RELOC_V850_17_PCREL,

  BFD_RELOC_V850_23,

  BFD_RELOC_V850_32_PCREL,

  BFD_RELOC_V850_32_ABS,

  BFD_RELOC_V850_16_SPLIT_OFFSET,

  BFD_RELOC_V850_16_S1,

  BFD_RELOC_V850_LO16_S1,

  BFD_RELOC_V850_CALLT_15_16_OFFSET,

  BFD_RELOC_V850_32_GOTPCREL,

  BFD_RELOC_V850_16_GOT,

  BFD_RELOC_V850_32_GOT,

  BFD_RELOC_V850_22_PLT_PCREL,

  BFD_RELOC_V850_32_PLT_PCREL,

  BFD_RELOC_V850_COPY,

  BFD_RELOC_V850_GLOB_DAT,

  BFD_RELOC_V850_JMP_SLOT,

  BFD_RELOC_V850_RELATIVE,

  BFD_RELOC_V850_16_GOTOFF,

  BFD_RELOC_V850_32_GOTOFF,

  BFD_RELOC_V850_CODE,

  BFD_RELOC_V850_DATA,

  BFD_RELOC_TIC30_LDP,

  BFD_RELOC_TIC54X_PARTLS7,

  BFD_RELOC_TIC54X_PARTMS9,

  BFD_RELOC_TIC54X_23,

  BFD_RELOC_TIC54X_16_OF_23,

  BFD_RELOC_TIC54X_MS7_OF_23,

  BFD_RELOC_C6000_PCR_S21,
  BFD_RELOC_C6000_PCR_S12,
  BFD_RELOC_C6000_PCR_S10,
  BFD_RELOC_C6000_PCR_S7,
  BFD_RELOC_C6000_ABS_S16,
  BFD_RELOC_C6000_ABS_L16,
  BFD_RELOC_C6000_ABS_H16,
  BFD_RELOC_C6000_SBR_U15_B,
  BFD_RELOC_C6000_SBR_U15_H,
  BFD_RELOC_C6000_SBR_U15_W,
  BFD_RELOC_C6000_SBR_S16,
  BFD_RELOC_C6000_SBR_L16_B,
  BFD_RELOC_C6000_SBR_L16_H,
  BFD_RELOC_C6000_SBR_L16_W,
  BFD_RELOC_C6000_SBR_H16_B,
  BFD_RELOC_C6000_SBR_H16_H,
  BFD_RELOC_C6000_SBR_H16_W,
  BFD_RELOC_C6000_SBR_GOT_U15_W,
  BFD_RELOC_C6000_SBR_GOT_L16_W,
  BFD_RELOC_C6000_SBR_GOT_H16_W,
  BFD_RELOC_C6000_DSBT_INDEX,
  BFD_RELOC_C6000_PREL31,
  BFD_RELOC_C6000_COPY,
  BFD_RELOC_C6000_JUMP_SLOT,
  BFD_RELOC_C6000_EHTYPE,
  BFD_RELOC_C6000_PCR_H16,
  BFD_RELOC_C6000_PCR_L16,
  BFD_RELOC_C6000_ALIGN,
  BFD_RELOC_C6000_FPHEAD,
  BFD_RELOC_C6000_NOCMP,

  BFD_RELOC_FR30_48,

  BFD_RELOC_FR30_20,

  BFD_RELOC_FR30_6_IN_4,

  BFD_RELOC_FR30_8_IN_8,

  BFD_RELOC_FR30_9_IN_8,

  BFD_RELOC_FR30_10_IN_8,

  BFD_RELOC_FR30_9_PCREL,

  BFD_RELOC_FR30_12_PCREL,

  BFD_RELOC_MCORE_PCREL_IMM8BY4,
  BFD_RELOC_MCORE_PCREL_IMM11BY2,
  BFD_RELOC_MCORE_PCREL_IMM4BY2,
  BFD_RELOC_MCORE_PCREL_32,
  BFD_RELOC_MCORE_PCREL_JSR_IMM11BY2,
  BFD_RELOC_MCORE_RVA,

  BFD_RELOC_MEP_8,
  BFD_RELOC_MEP_16,
  BFD_RELOC_MEP_32,
  BFD_RELOC_MEP_PCREL8A2,
  BFD_RELOC_MEP_PCREL12A2,
  BFD_RELOC_MEP_PCREL17A2,
  BFD_RELOC_MEP_PCREL24A2,
  BFD_RELOC_MEP_PCABS24A2,
  BFD_RELOC_MEP_LOW16,
  BFD_RELOC_MEP_HI16U,
  BFD_RELOC_MEP_HI16S,
  BFD_RELOC_MEP_GPREL,
  BFD_RELOC_MEP_TPREL,
  BFD_RELOC_MEP_TPREL7,
  BFD_RELOC_MEP_TPREL7A2,
  BFD_RELOC_MEP_TPREL7A4,
  BFD_RELOC_MEP_UIMM24,
  BFD_RELOC_MEP_ADDR24A4,
  BFD_RELOC_MEP_GNU_VTINHERIT,
  BFD_RELOC_MEP_GNU_VTENTRY,

  BFD_RELOC_METAG_HIADDR16,
  BFD_RELOC_METAG_LOADDR16,
  BFD_RELOC_METAG_RELBRANCH,
  BFD_RELOC_METAG_GETSETOFF,
  BFD_RELOC_METAG_HIOG,
  BFD_RELOC_METAG_LOOG,
  BFD_RELOC_METAG_REL8,
  BFD_RELOC_METAG_REL16,
  BFD_RELOC_METAG_HI16_GOTOFF,
  BFD_RELOC_METAG_LO16_GOTOFF,
  BFD_RELOC_METAG_GETSET_GOTOFF,
  BFD_RELOC_METAG_GETSET_GOT,
  BFD_RELOC_METAG_HI16_GOTPC,
  BFD_RELOC_METAG_LO16_GOTPC,
  BFD_RELOC_METAG_HI16_PLT,
  BFD_RELOC_METAG_LO16_PLT,
  BFD_RELOC_METAG_RELBRANCH_PLT,
  BFD_RELOC_METAG_GOTOFF,
  BFD_RELOC_METAG_PLT,
  BFD_RELOC_METAG_COPY,
  BFD_RELOC_METAG_JMP_SLOT,
  BFD_RELOC_METAG_RELATIVE,
  BFD_RELOC_METAG_GLOB_DAT,
  BFD_RELOC_METAG_TLS_GD,
  BFD_RELOC_METAG_TLS_LDM,
  BFD_RELOC_METAG_TLS_LDO_HI16,
  BFD_RELOC_METAG_TLS_LDO_LO16,
  BFD_RELOC_METAG_TLS_LDO,
  BFD_RELOC_METAG_TLS_IE,
  BFD_RELOC_METAG_TLS_IENONPIC,
  BFD_RELOC_METAG_TLS_IENONPIC_HI16,
  BFD_RELOC_METAG_TLS_IENONPIC_LO16,
  BFD_RELOC_METAG_TLS_TPOFF,
  BFD_RELOC_METAG_TLS_DTPMOD,
  BFD_RELOC_METAG_TLS_DTPOFF,
  BFD_RELOC_METAG_TLS_LE,
  BFD_RELOC_METAG_TLS_LE_HI16,
  BFD_RELOC_METAG_TLS_LE_LO16,

  BFD_RELOC_MMIX_GETA,
  BFD_RELOC_MMIX_GETA_1,
  BFD_RELOC_MMIX_GETA_2,
  BFD_RELOC_MMIX_GETA_3,

  BFD_RELOC_MMIX_CBRANCH,
  BFD_RELOC_MMIX_CBRANCH_J,
  BFD_RELOC_MMIX_CBRANCH_1,
  BFD_RELOC_MMIX_CBRANCH_2,
  BFD_RELOC_MMIX_CBRANCH_3,

  BFD_RELOC_MMIX_PUSHJ,
  BFD_RELOC_MMIX_PUSHJ_1,
  BFD_RELOC_MMIX_PUSHJ_2,
  BFD_RELOC_MMIX_PUSHJ_3,
  BFD_RELOC_MMIX_PUSHJ_STUBBABLE,

  BFD_RELOC_MMIX_JMP,
  BFD_RELOC_MMIX_JMP_1,
  BFD_RELOC_MMIX_JMP_2,
  BFD_RELOC_MMIX_JMP_3,

  BFD_RELOC_MMIX_ADDR19,

  BFD_RELOC_MMIX_ADDR27,

  BFD_RELOC_MMIX_REG_OR_BYTE,

  BFD_RELOC_MMIX_REG,

  BFD_RELOC_MMIX_BASE_PLUS_OFFSET,

  BFD_RELOC_MMIX_LOCAL,

  BFD_RELOC_AVR_7_PCREL,

  BFD_RELOC_AVR_13_PCREL,

  BFD_RELOC_AVR_16_PM,

  BFD_RELOC_AVR_LO8_LDI,

  BFD_RELOC_AVR_HI8_LDI,

  BFD_RELOC_AVR_HH8_LDI,

  BFD_RELOC_AVR_MS8_LDI,

  BFD_RELOC_AVR_LO8_LDI_NEG,

  BFD_RELOC_AVR_HI8_LDI_NEG,

  BFD_RELOC_AVR_HH8_LDI_NEG,

  BFD_RELOC_AVR_MS8_LDI_NEG,

  BFD_RELOC_AVR_LO8_LDI_PM,

  BFD_RELOC_AVR_LO8_LDI_GS,

  BFD_RELOC_AVR_HI8_LDI_PM,

  BFD_RELOC_AVR_HI8_LDI_GS,

  BFD_RELOC_AVR_HH8_LDI_PM,

  BFD_RELOC_AVR_LO8_LDI_PM_NEG,

  BFD_RELOC_AVR_HI8_LDI_PM_NEG,

  BFD_RELOC_AVR_HH8_LDI_PM_NEG,

  BFD_RELOC_AVR_CALL,

  BFD_RELOC_AVR_LDI,

  BFD_RELOC_AVR_6,

  BFD_RELOC_AVR_6_ADIW,

  BFD_RELOC_AVR_8_LO,

  BFD_RELOC_AVR_8_HI,

  BFD_RELOC_AVR_8_HLO,

  BFD_RELOC_AVR_DIFF8,
  BFD_RELOC_AVR_DIFF16,
  BFD_RELOC_AVR_DIFF32,

  BFD_RELOC_RL78_NEG8,
  BFD_RELOC_RL78_NEG16,
  BFD_RELOC_RL78_NEG24,
  BFD_RELOC_RL78_NEG32,
  BFD_RELOC_RL78_16_OP,
  BFD_RELOC_RL78_24_OP,
  BFD_RELOC_RL78_32_OP,
  BFD_RELOC_RL78_8U,
  BFD_RELOC_RL78_16U,
  BFD_RELOC_RL78_24U,
  BFD_RELOC_RL78_DIR3U_PCREL,
  BFD_RELOC_RL78_DIFF,
  BFD_RELOC_RL78_GPRELB,
  BFD_RELOC_RL78_GPRELW,
  BFD_RELOC_RL78_GPRELL,
  BFD_RELOC_RL78_SYM,
  BFD_RELOC_RL78_OP_SUBTRACT,
  BFD_RELOC_RL78_OP_NEG,
  BFD_RELOC_RL78_OP_AND,
  BFD_RELOC_RL78_OP_SHRA,
  BFD_RELOC_RL78_ABS8,
  BFD_RELOC_RL78_ABS16,
  BFD_RELOC_RL78_ABS16_REV,
  BFD_RELOC_RL78_ABS32,
  BFD_RELOC_RL78_ABS32_REV,
  BFD_RELOC_RL78_ABS16U,
  BFD_RELOC_RL78_ABS16UW,
  BFD_RELOC_RL78_ABS16UL,
  BFD_RELOC_RL78_RELAX,
  BFD_RELOC_RL78_HI16,
  BFD_RELOC_RL78_HI8,
  BFD_RELOC_RL78_LO16,
  BFD_RELOC_RL78_CODE,

  BFD_RELOC_RX_NEG8,
  BFD_RELOC_RX_NEG16,
  BFD_RELOC_RX_NEG24,
  BFD_RELOC_RX_NEG32,
  BFD_RELOC_RX_16_OP,
  BFD_RELOC_RX_24_OP,
  BFD_RELOC_RX_32_OP,
  BFD_RELOC_RX_8U,
  BFD_RELOC_RX_16U,
  BFD_RELOC_RX_24U,
  BFD_RELOC_RX_DIR3U_PCREL,
  BFD_RELOC_RX_DIFF,
  BFD_RELOC_RX_GPRELB,
  BFD_RELOC_RX_GPRELW,
  BFD_RELOC_RX_GPRELL,
  BFD_RELOC_RX_SYM,
  BFD_RELOC_RX_OP_SUBTRACT,
  BFD_RELOC_RX_OP_NEG,
  BFD_RELOC_RX_ABS8,
  BFD_RELOC_RX_ABS16,
  BFD_RELOC_RX_ABS16_REV,
  BFD_RELOC_RX_ABS32,
  BFD_RELOC_RX_ABS32_REV,
  BFD_RELOC_RX_ABS16U,
  BFD_RELOC_RX_ABS16UW,
  BFD_RELOC_RX_ABS16UL,
  BFD_RELOC_RX_RELAX,

  BFD_RELOC_390_12,

  BFD_RELOC_390_GOT12,

  BFD_RELOC_390_PLT32,

  BFD_RELOC_390_COPY,

  BFD_RELOC_390_GLOB_DAT,

  BFD_RELOC_390_JMP_SLOT,

  BFD_RELOC_390_RELATIVE,

  BFD_RELOC_390_GOTPC,

  BFD_RELOC_390_GOT16,

  BFD_RELOC_390_PC12DBL,

  BFD_RELOC_390_PLT12DBL,

  BFD_RELOC_390_PC16DBL,

  BFD_RELOC_390_PLT16DBL,

  BFD_RELOC_390_PC24DBL,

  BFD_RELOC_390_PLT24DBL,

  BFD_RELOC_390_PC32DBL,

  BFD_RELOC_390_PLT32DBL,

  BFD_RELOC_390_GOTPCDBL,

  BFD_RELOC_390_GOT64,

  BFD_RELOC_390_PLT64,

  BFD_RELOC_390_GOTENT,

  BFD_RELOC_390_GOTOFF64,

  BFD_RELOC_390_GOTPLT12,

  BFD_RELOC_390_GOTPLT16,

  BFD_RELOC_390_GOTPLT32,

  BFD_RELOC_390_GOTPLT64,

  BFD_RELOC_390_GOTPLTENT,

  BFD_RELOC_390_PLTOFF16,

  BFD_RELOC_390_PLTOFF32,

  BFD_RELOC_390_PLTOFF64,

  BFD_RELOC_390_TLS_LOAD,
  BFD_RELOC_390_TLS_GDCALL,
  BFD_RELOC_390_TLS_LDCALL,
  BFD_RELOC_390_TLS_GD32,
  BFD_RELOC_390_TLS_GD64,
  BFD_RELOC_390_TLS_GOTIE12,
  BFD_RELOC_390_TLS_GOTIE32,
  BFD_RELOC_390_TLS_GOTIE64,
  BFD_RELOC_390_TLS_LDM32,
  BFD_RELOC_390_TLS_LDM64,
  BFD_RELOC_390_TLS_IE32,
  BFD_RELOC_390_TLS_IE64,
  BFD_RELOC_390_TLS_IEENT,
  BFD_RELOC_390_TLS_LE32,
  BFD_RELOC_390_TLS_LE64,
  BFD_RELOC_390_TLS_LDO32,
  BFD_RELOC_390_TLS_LDO64,
  BFD_RELOC_390_TLS_DTPMOD,
  BFD_RELOC_390_TLS_DTPOFF,
  BFD_RELOC_390_TLS_TPOFF,

  BFD_RELOC_390_20,
  BFD_RELOC_390_GOT20,
  BFD_RELOC_390_GOTPLT20,
  BFD_RELOC_390_TLS_GOTIE20,

  BFD_RELOC_390_IRELATIVE,

  BFD_RELOC_SCORE_GPREL15,

  BFD_RELOC_SCORE_DUMMY2,
  BFD_RELOC_SCORE_JMP,

  BFD_RELOC_SCORE_BRANCH,

  BFD_RELOC_SCORE_IMM30,

  BFD_RELOC_SCORE_IMM32,

  BFD_RELOC_SCORE16_JMP,

  BFD_RELOC_SCORE16_BRANCH,

  BFD_RELOC_SCORE_BCMP,

  BFD_RELOC_SCORE_GOT15,
  BFD_RELOC_SCORE_GOT_LO16,
  BFD_RELOC_SCORE_CALL15,
  BFD_RELOC_SCORE_DUMMY_HI16,

  BFD_RELOC_IP2K_FR9,

  BFD_RELOC_IP2K_BANK,

  BFD_RELOC_IP2K_ADDR16CJP,

  BFD_RELOC_IP2K_PAGE3,

  BFD_RELOC_IP2K_LO8DATA,
  BFD_RELOC_IP2K_HI8DATA,
  BFD_RELOC_IP2K_EX8DATA,

  BFD_RELOC_IP2K_LO8INSN,
  BFD_RELOC_IP2K_HI8INSN,

  BFD_RELOC_IP2K_PC_SKIP,

  BFD_RELOC_IP2K_TEXT,

  BFD_RELOC_IP2K_FR_OFFSET,

  BFD_RELOC_VPE4KMATH_DATA,
  BFD_RELOC_VPE4KMATH_INSN,
  BFD_RELOC_VTABLE_INHERIT,
  BFD_RELOC_VTABLE_ENTRY,

  BFD_RELOC_IA64_IMM14,
  BFD_RELOC_IA64_IMM22,
  BFD_RELOC_IA64_IMM64,
  BFD_RELOC_IA64_DIR32MSB,
  BFD_RELOC_IA64_DIR32LSB,
  BFD_RELOC_IA64_DIR64MSB,
  BFD_RELOC_IA64_DIR64LSB,
  BFD_RELOC_IA64_GPREL22,
  BFD_RELOC_IA64_GPREL64I,
  BFD_RELOC_IA64_GPREL32MSB,
  BFD_RELOC_IA64_GPREL32LSB,
  BFD_RELOC_IA64_GPREL64MSB,
  BFD_RELOC_IA64_GPREL64LSB,
  BFD_RELOC_IA64_LTOFF22,
  BFD_RELOC_IA64_LTOFF64I,
  BFD_RELOC_IA64_PLTOFF22,
  BFD_RELOC_IA64_PLTOFF64I,
  BFD_RELOC_IA64_PLTOFF64MSB,
  BFD_RELOC_IA64_PLTOFF64LSB,
  BFD_RELOC_IA64_FPTR64I,
  BFD_RELOC_IA64_FPTR32MSB,
  BFD_RELOC_IA64_FPTR32LSB,
  BFD_RELOC_IA64_FPTR64MSB,
  BFD_RELOC_IA64_FPTR64LSB,
  BFD_RELOC_IA64_PCREL21B,
  BFD_RELOC_IA64_PCREL21BI,
  BFD_RELOC_IA64_PCREL21M,
  BFD_RELOC_IA64_PCREL21F,
  BFD_RELOC_IA64_PCREL22,
  BFD_RELOC_IA64_PCREL60B,
  BFD_RELOC_IA64_PCREL64I,
  BFD_RELOC_IA64_PCREL32MSB,
  BFD_RELOC_IA64_PCREL32LSB,
  BFD_RELOC_IA64_PCREL64MSB,
  BFD_RELOC_IA64_PCREL64LSB,
  BFD_RELOC_IA64_LTOFF_FPTR22,
  BFD_RELOC_IA64_LTOFF_FPTR64I,
  BFD_RELOC_IA64_LTOFF_FPTR32MSB,
  BFD_RELOC_IA64_LTOFF_FPTR32LSB,
  BFD_RELOC_IA64_LTOFF_FPTR64MSB,
  BFD_RELOC_IA64_LTOFF_FPTR64LSB,
  BFD_RELOC_IA64_SEGREL32MSB,
  BFD_RELOC_IA64_SEGREL32LSB,
  BFD_RELOC_IA64_SEGREL64MSB,
  BFD_RELOC_IA64_SEGREL64LSB,
  BFD_RELOC_IA64_SECREL32MSB,
  BFD_RELOC_IA64_SECREL32LSB,
  BFD_RELOC_IA64_SECREL64MSB,
  BFD_RELOC_IA64_SECREL64LSB,
  BFD_RELOC_IA64_REL32MSB,
  BFD_RELOC_IA64_REL32LSB,
  BFD_RELOC_IA64_REL64MSB,
  BFD_RELOC_IA64_REL64LSB,
  BFD_RELOC_IA64_LTV32MSB,
  BFD_RELOC_IA64_LTV32LSB,
  BFD_RELOC_IA64_LTV64MSB,
  BFD_RELOC_IA64_LTV64LSB,
  BFD_RELOC_IA64_IPLTMSB,
  BFD_RELOC_IA64_IPLTLSB,
  BFD_RELOC_IA64_COPY,
  BFD_RELOC_IA64_LTOFF22X,
  BFD_RELOC_IA64_LDXMOV,
  BFD_RELOC_IA64_TPREL14,
  BFD_RELOC_IA64_TPREL22,
  BFD_RELOC_IA64_TPREL64I,
  BFD_RELOC_IA64_TPREL64MSB,
  BFD_RELOC_IA64_TPREL64LSB,
  BFD_RELOC_IA64_LTOFF_TPREL22,
  BFD_RELOC_IA64_DTPMOD64MSB,
  BFD_RELOC_IA64_DTPMOD64LSB,
  BFD_RELOC_IA64_LTOFF_DTPMOD22,
  BFD_RELOC_IA64_DTPREL14,
  BFD_RELOC_IA64_DTPREL22,
  BFD_RELOC_IA64_DTPREL64I,
  BFD_RELOC_IA64_DTPREL32MSB,
  BFD_RELOC_IA64_DTPREL32LSB,
  BFD_RELOC_IA64_DTPREL64MSB,
  BFD_RELOC_IA64_DTPREL64LSB,
  BFD_RELOC_IA64_LTOFF_DTPREL22,

  BFD_RELOC_M68HC11_HI8,

  BFD_RELOC_M68HC11_LO8,

  BFD_RELOC_M68HC11_3B,

  BFD_RELOC_M68HC11_RL_JUMP,

  BFD_RELOC_M68HC11_RL_GROUP,

  BFD_RELOC_M68HC11_LO16,

  BFD_RELOC_M68HC11_PAGE,

  BFD_RELOC_M68HC11_24,

  BFD_RELOC_M68HC12_5B,

  BFD_RELOC_XGATE_RL_JUMP,

  BFD_RELOC_XGATE_RL_GROUP,

  BFD_RELOC_XGATE_LO16,

  BFD_RELOC_XGATE_GPAGE,

  BFD_RELOC_XGATE_24,

  BFD_RELOC_XGATE_PCREL_9,

  BFD_RELOC_XGATE_PCREL_10,

  BFD_RELOC_XGATE_IMM8_LO,

  BFD_RELOC_XGATE_IMM8_HI,

  BFD_RELOC_XGATE_IMM3,

  BFD_RELOC_XGATE_IMM4,

  BFD_RELOC_XGATE_IMM5,

  BFD_RELOC_M68HC12_9B,

  BFD_RELOC_M68HC12_16B,

  BFD_RELOC_M68HC12_9_PCREL,

  BFD_RELOC_M68HC12_10_PCREL,

  BFD_RELOC_M68HC12_LO8XG,

  BFD_RELOC_M68HC12_HI8XG,

  BFD_RELOC_16C_NUM08,
  BFD_RELOC_16C_NUM08_C,
  BFD_RELOC_16C_NUM16,
  BFD_RELOC_16C_NUM16_C,
  BFD_RELOC_16C_NUM32,
  BFD_RELOC_16C_NUM32_C,
  BFD_RELOC_16C_DISP04,
  BFD_RELOC_16C_DISP04_C,
  BFD_RELOC_16C_DISP08,
  BFD_RELOC_16C_DISP08_C,
  BFD_RELOC_16C_DISP16,
  BFD_RELOC_16C_DISP16_C,
  BFD_RELOC_16C_DISP24,
  BFD_RELOC_16C_DISP24_C,
  BFD_RELOC_16C_DISP24a,
  BFD_RELOC_16C_DISP24a_C,
  BFD_RELOC_16C_REG04,
  BFD_RELOC_16C_REG04_C,
  BFD_RELOC_16C_REG04a,
  BFD_RELOC_16C_REG04a_C,
  BFD_RELOC_16C_REG14,
  BFD_RELOC_16C_REG14_C,
  BFD_RELOC_16C_REG16,
  BFD_RELOC_16C_REG16_C,
  BFD_RELOC_16C_REG20,
  BFD_RELOC_16C_REG20_C,
  BFD_RELOC_16C_ABS20,
  BFD_RELOC_16C_ABS20_C,
  BFD_RELOC_16C_ABS24,
  BFD_RELOC_16C_ABS24_C,
  BFD_RELOC_16C_IMM04,
  BFD_RELOC_16C_IMM04_C,
  BFD_RELOC_16C_IMM16,
  BFD_RELOC_16C_IMM16_C,
  BFD_RELOC_16C_IMM20,
  BFD_RELOC_16C_IMM20_C,
  BFD_RELOC_16C_IMM24,
  BFD_RELOC_16C_IMM24_C,
  BFD_RELOC_16C_IMM32,
  BFD_RELOC_16C_IMM32_C,

  BFD_RELOC_CR16_NUM8,
  BFD_RELOC_CR16_NUM16,
  BFD_RELOC_CR16_NUM32,
  BFD_RELOC_CR16_NUM32a,
  BFD_RELOC_CR16_REGREL0,
  BFD_RELOC_CR16_REGREL4,
  BFD_RELOC_CR16_REGREL4a,
  BFD_RELOC_CR16_REGREL14,
  BFD_RELOC_CR16_REGREL14a,
  BFD_RELOC_CR16_REGREL16,
  BFD_RELOC_CR16_REGREL20,
  BFD_RELOC_CR16_REGREL20a,
  BFD_RELOC_CR16_ABS20,
  BFD_RELOC_CR16_ABS24,
  BFD_RELOC_CR16_IMM4,
  BFD_RELOC_CR16_IMM8,
  BFD_RELOC_CR16_IMM16,
  BFD_RELOC_CR16_IMM20,
  BFD_RELOC_CR16_IMM24,
  BFD_RELOC_CR16_IMM32,
  BFD_RELOC_CR16_IMM32a,
  BFD_RELOC_CR16_DISP4,
  BFD_RELOC_CR16_DISP8,
  BFD_RELOC_CR16_DISP16,
  BFD_RELOC_CR16_DISP20,
  BFD_RELOC_CR16_DISP24,
  BFD_RELOC_CR16_DISP24a,
  BFD_RELOC_CR16_SWITCH8,
  BFD_RELOC_CR16_SWITCH16,
  BFD_RELOC_CR16_SWITCH32,
  BFD_RELOC_CR16_GOT_REGREL20,
  BFD_RELOC_CR16_GOTC_REGREL20,
  BFD_RELOC_CR16_GLOB_DAT,

  BFD_RELOC_CRX_REL4,
  BFD_RELOC_CRX_REL8,
  BFD_RELOC_CRX_REL8_CMP,
  BFD_RELOC_CRX_REL16,
  BFD_RELOC_CRX_REL24,
  BFD_RELOC_CRX_REL32,
  BFD_RELOC_CRX_REGREL12,
  BFD_RELOC_CRX_REGREL22,
  BFD_RELOC_CRX_REGREL28,
  BFD_RELOC_CRX_REGREL32,
  BFD_RELOC_CRX_ABS16,
  BFD_RELOC_CRX_ABS32,
  BFD_RELOC_CRX_NUM8,
  BFD_RELOC_CRX_NUM16,
  BFD_RELOC_CRX_NUM32,
  BFD_RELOC_CRX_IMM16,
  BFD_RELOC_CRX_IMM32,
  BFD_RELOC_CRX_SWITCH8,
  BFD_RELOC_CRX_SWITCH16,
  BFD_RELOC_CRX_SWITCH32,

  BFD_RELOC_CRIS_BDISP8,
  BFD_RELOC_CRIS_UNSIGNED_5,
  BFD_RELOC_CRIS_SIGNED_6,
  BFD_RELOC_CRIS_UNSIGNED_6,
  BFD_RELOC_CRIS_SIGNED_8,
  BFD_RELOC_CRIS_UNSIGNED_8,
  BFD_RELOC_CRIS_SIGNED_16,
  BFD_RELOC_CRIS_UNSIGNED_16,
  BFD_RELOC_CRIS_LAPCQ_OFFSET,
  BFD_RELOC_CRIS_UNSIGNED_4,

  BFD_RELOC_CRIS_COPY,
  BFD_RELOC_CRIS_GLOB_DAT,
  BFD_RELOC_CRIS_JUMP_SLOT,
  BFD_RELOC_CRIS_RELATIVE,

  BFD_RELOC_CRIS_32_GOT,

  BFD_RELOC_CRIS_16_GOT,

  BFD_RELOC_CRIS_32_GOTPLT,

  BFD_RELOC_CRIS_16_GOTPLT,

  BFD_RELOC_CRIS_32_GOTREL,

  BFD_RELOC_CRIS_32_PLT_GOTREL,

  BFD_RELOC_CRIS_32_PLT_PCREL,

  BFD_RELOC_CRIS_32_GOT_GD,
  BFD_RELOC_CRIS_16_GOT_GD,
  BFD_RELOC_CRIS_32_GD,
  BFD_RELOC_CRIS_DTP,
  BFD_RELOC_CRIS_32_DTPREL,
  BFD_RELOC_CRIS_16_DTPREL,
  BFD_RELOC_CRIS_32_GOT_TPREL,
  BFD_RELOC_CRIS_16_GOT_TPREL,
  BFD_RELOC_CRIS_32_TPREL,
  BFD_RELOC_CRIS_16_TPREL,
  BFD_RELOC_CRIS_DTPMOD,
  BFD_RELOC_CRIS_32_IE,

  BFD_RELOC_860_COPY,
  BFD_RELOC_860_GLOB_DAT,
  BFD_RELOC_860_JUMP_SLOT,
  BFD_RELOC_860_RELATIVE,
  BFD_RELOC_860_PC26,
  BFD_RELOC_860_PLT26,
  BFD_RELOC_860_PC16,
  BFD_RELOC_860_LOW0,
  BFD_RELOC_860_SPLIT0,
  BFD_RELOC_860_LOW1,
  BFD_RELOC_860_SPLIT1,
  BFD_RELOC_860_LOW2,
  BFD_RELOC_860_SPLIT2,
  BFD_RELOC_860_LOW3,
  BFD_RELOC_860_LOGOT0,
  BFD_RELOC_860_SPGOT0,
  BFD_RELOC_860_LOGOT1,
  BFD_RELOC_860_SPGOT1,
  BFD_RELOC_860_LOGOTOFF0,
  BFD_RELOC_860_SPGOTOFF0,
  BFD_RELOC_860_LOGOTOFF1,
  BFD_RELOC_860_SPGOTOFF1,
  BFD_RELOC_860_LOGOTOFF2,
  BFD_RELOC_860_LOGOTOFF3,
  BFD_RELOC_860_LOPC,
  BFD_RELOC_860_HIGHADJ,
  BFD_RELOC_860_HAGOT,
  BFD_RELOC_860_HAGOTOFF,
  BFD_RELOC_860_HAPC,
  BFD_RELOC_860_HIGH,
  BFD_RELOC_860_HIGOT,
  BFD_RELOC_860_HIGOTOFF,

  BFD_RELOC_OR1K_REL_26,
  BFD_RELOC_OR1K_GOTPC_HI16,
  BFD_RELOC_OR1K_GOTPC_LO16,
  BFD_RELOC_OR1K_GOT16,
  BFD_RELOC_OR1K_PLT26,
  BFD_RELOC_OR1K_GOTOFF_HI16,
  BFD_RELOC_OR1K_GOTOFF_LO16,
  BFD_RELOC_OR1K_COPY,
  BFD_RELOC_OR1K_GLOB_DAT,
  BFD_RELOC_OR1K_JMP_SLOT,
  BFD_RELOC_OR1K_RELATIVE,
  BFD_RELOC_OR1K_TLS_GD_HI16,
  BFD_RELOC_OR1K_TLS_GD_LO16,
  BFD_RELOC_OR1K_TLS_LDM_HI16,
  BFD_RELOC_OR1K_TLS_LDM_LO16,
  BFD_RELOC_OR1K_TLS_LDO_HI16,
  BFD_RELOC_OR1K_TLS_LDO_LO16,
  BFD_RELOC_OR1K_TLS_IE_HI16,
  BFD_RELOC_OR1K_TLS_IE_LO16,
  BFD_RELOC_OR1K_TLS_LE_HI16,
  BFD_RELOC_OR1K_TLS_LE_LO16,
  BFD_RELOC_OR1K_TLS_TPOFF,
  BFD_RELOC_OR1K_TLS_DTPOFF,
  BFD_RELOC_OR1K_TLS_DTPMOD,

  BFD_RELOC_H8_DIR16A8,
  BFD_RELOC_H8_DIR16R8,
  BFD_RELOC_H8_DIR24A8,
  BFD_RELOC_H8_DIR24R8,
  BFD_RELOC_H8_DIR32A16,
  BFD_RELOC_H8_DISP32A16,

  BFD_RELOC_XSTORMY16_REL_12,
  BFD_RELOC_XSTORMY16_12,
  BFD_RELOC_XSTORMY16_24,
  BFD_RELOC_XSTORMY16_FPTR16,

  BFD_RELOC_RELC,

  BFD_RELOC_XC16X_PAG,
  BFD_RELOC_XC16X_POF,
  BFD_RELOC_XC16X_SEG,
  BFD_RELOC_XC16X_SOF,

  BFD_RELOC_VAX_GLOB_DAT,
  BFD_RELOC_VAX_JMP_SLOT,
  BFD_RELOC_VAX_RELATIVE,

  BFD_RELOC_MT_PC16,

  BFD_RELOC_MT_HI16,

  BFD_RELOC_MT_LO16,

  BFD_RELOC_MT_GNU_VTINHERIT,

  BFD_RELOC_MT_GNU_VTENTRY,

  BFD_RELOC_MT_PCINSN8,

  BFD_RELOC_MSP430_10_PCREL,
  BFD_RELOC_MSP430_16_PCREL,
  BFD_RELOC_MSP430_16,
  BFD_RELOC_MSP430_16_PCREL_BYTE,
  BFD_RELOC_MSP430_16_BYTE,
  BFD_RELOC_MSP430_2X_PCREL,
  BFD_RELOC_MSP430_RL_PCREL,
  BFD_RELOC_MSP430_ABS8,
  BFD_RELOC_MSP430X_PCR20_EXT_SRC,
  BFD_RELOC_MSP430X_PCR20_EXT_DST,
  BFD_RELOC_MSP430X_PCR20_EXT_ODST,
  BFD_RELOC_MSP430X_ABS20_EXT_SRC,
  BFD_RELOC_MSP430X_ABS20_EXT_DST,
  BFD_RELOC_MSP430X_ABS20_EXT_ODST,
  BFD_RELOC_MSP430X_ABS20_ADR_SRC,
  BFD_RELOC_MSP430X_ABS20_ADR_DST,
  BFD_RELOC_MSP430X_PCR16,
  BFD_RELOC_MSP430X_PCR20_CALL,
  BFD_RELOC_MSP430X_ABS16,
  BFD_RELOC_MSP430_ABS_HI16,
  BFD_RELOC_MSP430_PREL31,
  BFD_RELOC_MSP430_SYM_DIFF,

  BFD_RELOC_NIOS2_S16,
  BFD_RELOC_NIOS2_U16,
  BFD_RELOC_NIOS2_CALL26,
  BFD_RELOC_NIOS2_IMM5,
  BFD_RELOC_NIOS2_CACHE_OPX,
  BFD_RELOC_NIOS2_IMM6,
  BFD_RELOC_NIOS2_IMM8,
  BFD_RELOC_NIOS2_HI16,
  BFD_RELOC_NIOS2_LO16,
  BFD_RELOC_NIOS2_HIADJ16,
  BFD_RELOC_NIOS2_GPREL,
  BFD_RELOC_NIOS2_UJMP,
  BFD_RELOC_NIOS2_CJMP,
  BFD_RELOC_NIOS2_CALLR,
  BFD_RELOC_NIOS2_ALIGN,
  BFD_RELOC_NIOS2_GOT16,
  BFD_RELOC_NIOS2_CALL16,
  BFD_RELOC_NIOS2_GOTOFF_LO,
  BFD_RELOC_NIOS2_GOTOFF_HA,
  BFD_RELOC_NIOS2_PCREL_LO,
  BFD_RELOC_NIOS2_PCREL_HA,
  BFD_RELOC_NIOS2_TLS_GD16,
  BFD_RELOC_NIOS2_TLS_LDM16,
  BFD_RELOC_NIOS2_TLS_LDO16,
  BFD_RELOC_NIOS2_TLS_IE16,
  BFD_RELOC_NIOS2_TLS_LE16,
  BFD_RELOC_NIOS2_TLS_DTPMOD,
  BFD_RELOC_NIOS2_TLS_DTPREL,
  BFD_RELOC_NIOS2_TLS_TPREL,
  BFD_RELOC_NIOS2_COPY,
  BFD_RELOC_NIOS2_GLOB_DAT,
  BFD_RELOC_NIOS2_JUMP_SLOT,
  BFD_RELOC_NIOS2_RELATIVE,
  BFD_RELOC_NIOS2_GOTOFF,
  BFD_RELOC_NIOS2_CALL26_NOAT,
  BFD_RELOC_NIOS2_GOT_LO,
  BFD_RELOC_NIOS2_GOT_HA,
  BFD_RELOC_NIOS2_CALL_LO,
  BFD_RELOC_NIOS2_CALL_HA,

  BFD_RELOC_IQ2000_OFFSET_16,
  BFD_RELOC_IQ2000_OFFSET_21,
  BFD_RELOC_IQ2000_UHI16,

  BFD_RELOC_XTENSA_RTLD,

  BFD_RELOC_XTENSA_GLOB_DAT,
  BFD_RELOC_XTENSA_JMP_SLOT,
  BFD_RELOC_XTENSA_RELATIVE,

  BFD_RELOC_XTENSA_PLT,

  BFD_RELOC_XTENSA_DIFF8,
  BFD_RELOC_XTENSA_DIFF16,
  BFD_RELOC_XTENSA_DIFF32,

  BFD_RELOC_XTENSA_SLOT0_OP,
  BFD_RELOC_XTENSA_SLOT1_OP,
  BFD_RELOC_XTENSA_SLOT2_OP,
  BFD_RELOC_XTENSA_SLOT3_OP,
  BFD_RELOC_XTENSA_SLOT4_OP,
  BFD_RELOC_XTENSA_SLOT5_OP,
  BFD_RELOC_XTENSA_SLOT6_OP,
  BFD_RELOC_XTENSA_SLOT7_OP,
  BFD_RELOC_XTENSA_SLOT8_OP,
  BFD_RELOC_XTENSA_SLOT9_OP,
  BFD_RELOC_XTENSA_SLOT10_OP,
  BFD_RELOC_XTENSA_SLOT11_OP,
  BFD_RELOC_XTENSA_SLOT12_OP,
  BFD_RELOC_XTENSA_SLOT13_OP,
  BFD_RELOC_XTENSA_SLOT14_OP,

  BFD_RELOC_XTENSA_SLOT0_ALT,
  BFD_RELOC_XTENSA_SLOT1_ALT,
  BFD_RELOC_XTENSA_SLOT2_ALT,
  BFD_RELOC_XTENSA_SLOT3_ALT,
  BFD_RELOC_XTENSA_SLOT4_ALT,
  BFD_RELOC_XTENSA_SLOT5_ALT,
  BFD_RELOC_XTENSA_SLOT6_ALT,
  BFD_RELOC_XTENSA_SLOT7_ALT,
  BFD_RELOC_XTENSA_SLOT8_ALT,
  BFD_RELOC_XTENSA_SLOT9_ALT,
  BFD_RELOC_XTENSA_SLOT10_ALT,
  BFD_RELOC_XTENSA_SLOT11_ALT,
  BFD_RELOC_XTENSA_SLOT12_ALT,
  BFD_RELOC_XTENSA_SLOT13_ALT,
  BFD_RELOC_XTENSA_SLOT14_ALT,

  BFD_RELOC_XTENSA_OP0,
  BFD_RELOC_XTENSA_OP1,
  BFD_RELOC_XTENSA_OP2,

  BFD_RELOC_XTENSA_ASM_EXPAND,

  BFD_RELOC_XTENSA_ASM_SIMPLIFY,

  BFD_RELOC_XTENSA_TLSDESC_FN,
  BFD_RELOC_XTENSA_TLSDESC_ARG,
  BFD_RELOC_XTENSA_TLS_DTPOFF,
  BFD_RELOC_XTENSA_TLS_TPOFF,
  BFD_RELOC_XTENSA_TLS_FUNC,
  BFD_RELOC_XTENSA_TLS_ARG,
  BFD_RELOC_XTENSA_TLS_CALL,

  BFD_RELOC_Z80_DISP8,

  BFD_RELOC_Z8K_DISP7,

  BFD_RELOC_Z8K_CALLR,

  BFD_RELOC_Z8K_IMM4L,

  BFD_RELOC_LM32_CALL,
  BFD_RELOC_LM32_BRANCH,
  BFD_RELOC_LM32_16_GOT,
  BFD_RELOC_LM32_GOTOFF_HI16,
  BFD_RELOC_LM32_GOTOFF_LO16,
  BFD_RELOC_LM32_COPY,
  BFD_RELOC_LM32_GLOB_DAT,
  BFD_RELOC_LM32_JMP_SLOT,
  BFD_RELOC_LM32_RELATIVE,

  BFD_RELOC_MACH_O_SECTDIFF,

  BFD_RELOC_MACH_O_LOCAL_SECTDIFF,

  BFD_RELOC_MACH_O_PAIR,

  BFD_RELOC_MACH_O_X86_64_BRANCH32,
  BFD_RELOC_MACH_O_X86_64_BRANCH8,

  BFD_RELOC_MACH_O_X86_64_GOT,

  BFD_RELOC_MACH_O_X86_64_GOT_LOAD,

  BFD_RELOC_MACH_O_X86_64_SUBTRACTOR32,

  BFD_RELOC_MACH_O_X86_64_SUBTRACTOR64,

  BFD_RELOC_MACH_O_X86_64_PCREL32_1,

  BFD_RELOC_MACH_O_X86_64_PCREL32_2,

  BFD_RELOC_MACH_O_X86_64_PCREL32_4,

  BFD_RELOC_MICROBLAZE_32_LO,

  BFD_RELOC_MICROBLAZE_32_LO_PCREL,

  BFD_RELOC_MICROBLAZE_32_ROSDA,

  BFD_RELOC_MICROBLAZE_32_RWSDA,

  BFD_RELOC_MICROBLAZE_32_SYM_OP_SYM,

  BFD_RELOC_MICROBLAZE_64_NONE,

  BFD_RELOC_MICROBLAZE_64_GOTPC,

  BFD_RELOC_MICROBLAZE_64_GOT,

  BFD_RELOC_MICROBLAZE_64_PLT,

  BFD_RELOC_MICROBLAZE_64_GOTOFF,

  BFD_RELOC_MICROBLAZE_32_GOTOFF,

  BFD_RELOC_MICROBLAZE_COPY,

  BFD_RELOC_MICROBLAZE_64_TLS,

  BFD_RELOC_MICROBLAZE_64_TLSGD,

  BFD_RELOC_MICROBLAZE_64_TLSLD,

  BFD_RELOC_MICROBLAZE_32_TLSDTPMOD,

  BFD_RELOC_MICROBLAZE_32_TLSDTPREL,

  BFD_RELOC_MICROBLAZE_64_TLSDTPREL,

  BFD_RELOC_MICROBLAZE_64_TLSGOTTPREL,

  BFD_RELOC_MICROBLAZE_64_TLSTPREL,

  BFD_RELOC_AARCH64_RELOC_START,

  BFD_RELOC_AARCH64_NONE,

  BFD_RELOC_AARCH64_64,
  BFD_RELOC_AARCH64_32,
  BFD_RELOC_AARCH64_16,

  BFD_RELOC_AARCH64_64_PCREL,
  BFD_RELOC_AARCH64_32_PCREL,
  BFD_RELOC_AARCH64_16_PCREL,

  BFD_RELOC_AARCH64_MOVW_G0,

  BFD_RELOC_AARCH64_MOVW_G0_NC,

  BFD_RELOC_AARCH64_MOVW_G1,

  BFD_RELOC_AARCH64_MOVW_G1_NC,

  BFD_RELOC_AARCH64_MOVW_G2,

  BFD_RELOC_AARCH64_MOVW_G2_NC,

  BFD_RELOC_AARCH64_MOVW_G3,

  BFD_RELOC_AARCH64_MOVW_G0_S,

  BFD_RELOC_AARCH64_MOVW_G1_S,

  BFD_RELOC_AARCH64_MOVW_G2_S,

  BFD_RELOC_AARCH64_LD_LO19_PCREL,

  BFD_RELOC_AARCH64_ADR_LO21_PCREL,

  BFD_RELOC_AARCH64_ADR_HI21_PCREL,

  BFD_RELOC_AARCH64_ADR_HI21_NC_PCREL,

  BFD_RELOC_AARCH64_ADD_LO12,

  BFD_RELOC_AARCH64_LDST8_LO12,

  BFD_RELOC_AARCH64_TSTBR14,

  BFD_RELOC_AARCH64_BRANCH19,

  BFD_RELOC_AARCH64_JUMP26,

  BFD_RELOC_AARCH64_CALL26,

  BFD_RELOC_AARCH64_LDST16_LO12,

  BFD_RELOC_AARCH64_LDST32_LO12,

  BFD_RELOC_AARCH64_LDST64_LO12,

  BFD_RELOC_AARCH64_LDST128_LO12,

  BFD_RELOC_AARCH64_GOT_LD_PREL19,

  BFD_RELOC_AARCH64_ADR_GOT_PAGE,

  BFD_RELOC_AARCH64_LD64_GOT_LO12_NC,

  BFD_RELOC_AARCH64_LD32_GOT_LO12_NC,

  BFD_RELOC_AARCH64_TLSGD_ADR_PAGE21,

  BFD_RELOC_AARCH64_TLSGD_ADD_LO12_NC,

  BFD_RELOC_AARCH64_TLSIE_MOVW_GOTTPREL_G1,

  BFD_RELOC_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC,

  BFD_RELOC_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21,

  BFD_RELOC_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC,

  BFD_RELOC_AARCH64_TLSIE_LD32_GOTTPREL_LO12_NC,

  BFD_RELOC_AARCH64_TLSIE_LD_GOTTPREL_PREL19,

  BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G2,

  BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G1,

  BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G1_NC,

  BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G0,

  BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G0_NC,

  BFD_RELOC_AARCH64_TLSLE_ADD_TPREL_HI12,

  BFD_RELOC_AARCH64_TLSLE_ADD_TPREL_LO12,

  BFD_RELOC_AARCH64_TLSLE_ADD_TPREL_LO12_NC,

  BFD_RELOC_AARCH64_TLSDESC_LD_PREL19,

  BFD_RELOC_AARCH64_TLSDESC_ADR_PREL21,

  BFD_RELOC_AARCH64_TLSDESC_ADR_PAGE21,

  BFD_RELOC_AARCH64_TLSDESC_LD64_LO12_NC,

  BFD_RELOC_AARCH64_TLSDESC_LD32_LO12_NC,

  BFD_RELOC_AARCH64_TLSDESC_ADD_LO12_NC,

  BFD_RELOC_AARCH64_TLSDESC_OFF_G1,

  BFD_RELOC_AARCH64_TLSDESC_OFF_G0_NC,

  BFD_RELOC_AARCH64_TLSDESC_LDR,

  BFD_RELOC_AARCH64_TLSDESC_ADD,

  BFD_RELOC_AARCH64_TLSDESC_CALL,

  BFD_RELOC_AARCH64_COPY,

  BFD_RELOC_AARCH64_GLOB_DAT,

  BFD_RELOC_AARCH64_JUMP_SLOT,

  BFD_RELOC_AARCH64_RELATIVE,

  BFD_RELOC_AARCH64_TLS_DTPMOD,

  BFD_RELOC_AARCH64_TLS_DTPREL,

  BFD_RELOC_AARCH64_TLS_TPREL,

  BFD_RELOC_AARCH64_TLSDESC,

  BFD_RELOC_AARCH64_IRELATIVE,

  BFD_RELOC_AARCH64_RELOC_END,

  BFD_RELOC_AARCH64_GAS_INTERNAL_FIXUP,

  BFD_RELOC_AARCH64_LDST_LO12,

  BFD_RELOC_AARCH64_LD_GOT_LO12_NC,

  BFD_RELOC_AARCH64_TLSIE_LD_GOTTPREL_LO12_NC,

  BFD_RELOC_AARCH64_TLSDESC_LD_LO12_NC,

  BFD_RELOC_TILEPRO_COPY,
  BFD_RELOC_TILEPRO_GLOB_DAT,
  BFD_RELOC_TILEPRO_JMP_SLOT,
  BFD_RELOC_TILEPRO_RELATIVE,
  BFD_RELOC_TILEPRO_BROFF_X1,
  BFD_RELOC_TILEPRO_JOFFLONG_X1,
  BFD_RELOC_TILEPRO_JOFFLONG_X1_PLT,
  BFD_RELOC_TILEPRO_IMM8_X0,
  BFD_RELOC_TILEPRO_IMM8_Y0,
  BFD_RELOC_TILEPRO_IMM8_X1,
  BFD_RELOC_TILEPRO_IMM8_Y1,
  BFD_RELOC_TILEPRO_DEST_IMM8_X1,
  BFD_RELOC_TILEPRO_MT_IMM15_X1,
  BFD_RELOC_TILEPRO_MF_IMM15_X1,
  BFD_RELOC_TILEPRO_IMM16_X0,
  BFD_RELOC_TILEPRO_IMM16_X1,
  BFD_RELOC_TILEPRO_IMM16_X0_LO,
  BFD_RELOC_TILEPRO_IMM16_X1_LO,
  BFD_RELOC_TILEPRO_IMM16_X0_HI,
  BFD_RELOC_TILEPRO_IMM16_X1_HI,
  BFD_RELOC_TILEPRO_IMM16_X0_HA,
  BFD_RELOC_TILEPRO_IMM16_X1_HA,
  BFD_RELOC_TILEPRO_IMM16_X0_PCREL,
  BFD_RELOC_TILEPRO_IMM16_X1_PCREL,
  BFD_RELOC_TILEPRO_IMM16_X0_LO_PCREL,
  BFD_RELOC_TILEPRO_IMM16_X1_LO_PCREL,
  BFD_RELOC_TILEPRO_IMM16_X0_HI_PCREL,
  BFD_RELOC_TILEPRO_IMM16_X1_HI_PCREL,
  BFD_RELOC_TILEPRO_IMM16_X0_HA_PCREL,
  BFD_RELOC_TILEPRO_IMM16_X1_HA_PCREL,
  BFD_RELOC_TILEPRO_IMM16_X0_GOT,
  BFD_RELOC_TILEPRO_IMM16_X1_GOT,
  BFD_RELOC_TILEPRO_IMM16_X0_GOT_LO,
  BFD_RELOC_TILEPRO_IMM16_X1_GOT_LO,
  BFD_RELOC_TILEPRO_IMM16_X0_GOT_HI,
  BFD_RELOC_TILEPRO_IMM16_X1_GOT_HI,
  BFD_RELOC_TILEPRO_IMM16_X0_GOT_HA,
  BFD_RELOC_TILEPRO_IMM16_X1_GOT_HA,
  BFD_RELOC_TILEPRO_MMSTART_X0,
  BFD_RELOC_TILEPRO_MMEND_X0,
  BFD_RELOC_TILEPRO_MMSTART_X1,
  BFD_RELOC_TILEPRO_MMEND_X1,
  BFD_RELOC_TILEPRO_SHAMT_X0,
  BFD_RELOC_TILEPRO_SHAMT_X1,
  BFD_RELOC_TILEPRO_SHAMT_Y0,
  BFD_RELOC_TILEPRO_SHAMT_Y1,
  BFD_RELOC_TILEPRO_TLS_GD_CALL,
  BFD_RELOC_TILEPRO_IMM8_X0_TLS_GD_ADD,
  BFD_RELOC_TILEPRO_IMM8_X1_TLS_GD_ADD,
  BFD_RELOC_TILEPRO_IMM8_Y0_TLS_GD_ADD,
  BFD_RELOC_TILEPRO_IMM8_Y1_TLS_GD_ADD,
  BFD_RELOC_TILEPRO_TLS_IE_LOAD,
  BFD_RELOC_TILEPRO_IMM16_X0_TLS_GD,
  BFD_RELOC_TILEPRO_IMM16_X1_TLS_GD,
  BFD_RELOC_TILEPRO_IMM16_X0_TLS_GD_LO,
  BFD_RELOC_TILEPRO_IMM16_X1_TLS_GD_LO,
  BFD_RELOC_TILEPRO_IMM16_X0_TLS_GD_HI,
  BFD_RELOC_TILEPRO_IMM16_X1_TLS_GD_HI,
  BFD_RELOC_TILEPRO_IMM16_X0_TLS_GD_HA,
  BFD_RELOC_TILEPRO_IMM16_X1_TLS_GD_HA,
  BFD_RELOC_TILEPRO_IMM16_X0_TLS_IE,
  BFD_RELOC_TILEPRO_IMM16_X1_TLS_IE,
  BFD_RELOC_TILEPRO_IMM16_X0_TLS_IE_LO,
  BFD_RELOC_TILEPRO_IMM16_X1_TLS_IE_LO,
  BFD_RELOC_TILEPRO_IMM16_X0_TLS_IE_HI,
  BFD_RELOC_TILEPRO_IMM16_X1_TLS_IE_HI,
  BFD_RELOC_TILEPRO_IMM16_X0_TLS_IE_HA,
  BFD_RELOC_TILEPRO_IMM16_X1_TLS_IE_HA,
  BFD_RELOC_TILEPRO_TLS_DTPMOD32,
  BFD_RELOC_TILEPRO_TLS_DTPOFF32,
  BFD_RELOC_TILEPRO_TLS_TPOFF32,
  BFD_RELOC_TILEPRO_IMM16_X0_TLS_LE,
  BFD_RELOC_TILEPRO_IMM16_X1_TLS_LE,
  BFD_RELOC_TILEPRO_IMM16_X0_TLS_LE_LO,
  BFD_RELOC_TILEPRO_IMM16_X1_TLS_LE_LO,
  BFD_RELOC_TILEPRO_IMM16_X0_TLS_LE_HI,
  BFD_RELOC_TILEPRO_IMM16_X1_TLS_LE_HI,
  BFD_RELOC_TILEPRO_IMM16_X0_TLS_LE_HA,
  BFD_RELOC_TILEPRO_IMM16_X1_TLS_LE_HA,

  BFD_RELOC_TILEGX_HW0,
  BFD_RELOC_TILEGX_HW1,
  BFD_RELOC_TILEGX_HW2,
  BFD_RELOC_TILEGX_HW3,
  BFD_RELOC_TILEGX_HW0_LAST,
  BFD_RELOC_TILEGX_HW1_LAST,
  BFD_RELOC_TILEGX_HW2_LAST,
  BFD_RELOC_TILEGX_COPY,
  BFD_RELOC_TILEGX_GLOB_DAT,
  BFD_RELOC_TILEGX_JMP_SLOT,
  BFD_RELOC_TILEGX_RELATIVE,
  BFD_RELOC_TILEGX_BROFF_X1,
  BFD_RELOC_TILEGX_JUMPOFF_X1,
  BFD_RELOC_TILEGX_JUMPOFF_X1_PLT,
  BFD_RELOC_TILEGX_IMM8_X0,
  BFD_RELOC_TILEGX_IMM8_Y0,
  BFD_RELOC_TILEGX_IMM8_X1,
  BFD_RELOC_TILEGX_IMM8_Y1,
  BFD_RELOC_TILEGX_DEST_IMM8_X1,
  BFD_RELOC_TILEGX_MT_IMM14_X1,
  BFD_RELOC_TILEGX_MF_IMM14_X1,
  BFD_RELOC_TILEGX_MMSTART_X0,
  BFD_RELOC_TILEGX_MMEND_X0,
  BFD_RELOC_TILEGX_SHAMT_X0,
  BFD_RELOC_TILEGX_SHAMT_X1,
  BFD_RELOC_TILEGX_SHAMT_Y0,
  BFD_RELOC_TILEGX_SHAMT_Y1,
  BFD_RELOC_TILEGX_IMM16_X0_HW0,
  BFD_RELOC_TILEGX_IMM16_X1_HW0,
  BFD_RELOC_TILEGX_IMM16_X0_HW1,
  BFD_RELOC_TILEGX_IMM16_X1_HW1,
  BFD_RELOC_TILEGX_IMM16_X0_HW2,
  BFD_RELOC_TILEGX_IMM16_X1_HW2,
  BFD_RELOC_TILEGX_IMM16_X0_HW3,
  BFD_RELOC_TILEGX_IMM16_X1_HW3,
  BFD_RELOC_TILEGX_IMM16_X0_HW0_LAST,
  BFD_RELOC_TILEGX_IMM16_X1_HW0_LAST,
  BFD_RELOC_TILEGX_IMM16_X0_HW1_LAST,
  BFD_RELOC_TILEGX_IMM16_X1_HW1_LAST,
  BFD_RELOC_TILEGX_IMM16_X0_HW2_LAST,
  BFD_RELOC_TILEGX_IMM16_X1_HW2_LAST,
  BFD_RELOC_TILEGX_IMM16_X0_HW0_PCREL,
  BFD_RELOC_TILEGX_IMM16_X1_HW0_PCREL,
  BFD_RELOC_TILEGX_IMM16_X0_HW1_PCREL,
  BFD_RELOC_TILEGX_IMM16_X1_HW1_PCREL,
  BFD_RELOC_TILEGX_IMM16_X0_HW2_PCREL,
  BFD_RELOC_TILEGX_IMM16_X1_HW2_PCREL,
  BFD_RELOC_TILEGX_IMM16_X0_HW3_PCREL,
  BFD_RELOC_TILEGX_IMM16_X1_HW3_PCREL,
  BFD_RELOC_TILEGX_IMM16_X0_HW0_LAST_PCREL,
  BFD_RELOC_TILEGX_IMM16_X1_HW0_LAST_PCREL,
  BFD_RELOC_TILEGX_IMM16_X0_HW1_LAST_PCREL,
  BFD_RELOC_TILEGX_IMM16_X1_HW1_LAST_PCREL,
  BFD_RELOC_TILEGX_IMM16_X0_HW2_LAST_PCREL,
  BFD_RELOC_TILEGX_IMM16_X1_HW2_LAST_PCREL,
  BFD_RELOC_TILEGX_IMM16_X0_HW0_GOT,
  BFD_RELOC_TILEGX_IMM16_X1_HW0_GOT,
  BFD_RELOC_TILEGX_IMM16_X0_HW0_PLT_PCREL,
  BFD_RELOC_TILEGX_IMM16_X1_HW0_PLT_PCREL,
  BFD_RELOC_TILEGX_IMM16_X0_HW1_PLT_PCREL,
  BFD_RELOC_TILEGX_IMM16_X1_HW1_PLT_PCREL,
  BFD_RELOC_TILEGX_IMM16_X0_HW2_PLT_PCREL,
  BFD_RELOC_TILEGX_IMM16_X1_HW2_PLT_PCREL,
  BFD_RELOC_TILEGX_IMM16_X0_HW0_LAST_GOT,
  BFD_RELOC_TILEGX_IMM16_X1_HW0_LAST_GOT,
  BFD_RELOC_TILEGX_IMM16_X0_HW1_LAST_GOT,
  BFD_RELOC_TILEGX_IMM16_X1_HW1_LAST_GOT,
  BFD_RELOC_TILEGX_IMM16_X0_HW3_PLT_PCREL,
  BFD_RELOC_TILEGX_IMM16_X1_HW3_PLT_PCREL,
  BFD_RELOC_TILEGX_IMM16_X0_HW0_TLS_GD,
  BFD_RELOC_TILEGX_IMM16_X1_HW0_TLS_GD,
  BFD_RELOC_TILEGX_IMM16_X0_HW0_TLS_LE,
  BFD_RELOC_TILEGX_IMM16_X1_HW0_TLS_LE,
  BFD_RELOC_TILEGX_IMM16_X0_HW0_LAST_TLS_LE,
  BFD_RELOC_TILEGX_IMM16_X1_HW0_LAST_TLS_LE,
  BFD_RELOC_TILEGX_IMM16_X0_HW1_LAST_TLS_LE,
  BFD_RELOC_TILEGX_IMM16_X1_HW1_LAST_TLS_LE,
  BFD_RELOC_TILEGX_IMM16_X0_HW0_LAST_TLS_GD,
  BFD_RELOC_TILEGX_IMM16_X1_HW0_LAST_TLS_GD,
  BFD_RELOC_TILEGX_IMM16_X0_HW1_LAST_TLS_GD,
  BFD_RELOC_TILEGX_IMM16_X1_HW1_LAST_TLS_GD,
  BFD_RELOC_TILEGX_IMM16_X0_HW0_TLS_IE,
  BFD_RELOC_TILEGX_IMM16_X1_HW0_TLS_IE,
  BFD_RELOC_TILEGX_IMM16_X0_HW0_LAST_PLT_PCREL,
  BFD_RELOC_TILEGX_IMM16_X1_HW0_LAST_PLT_PCREL,
  BFD_RELOC_TILEGX_IMM16_X0_HW1_LAST_PLT_PCREL,
  BFD_RELOC_TILEGX_IMM16_X1_HW1_LAST_PLT_PCREL,
  BFD_RELOC_TILEGX_IMM16_X0_HW2_LAST_PLT_PCREL,
  BFD_RELOC_TILEGX_IMM16_X1_HW2_LAST_PLT_PCREL,
  BFD_RELOC_TILEGX_IMM16_X0_HW0_LAST_TLS_IE,
  BFD_RELOC_TILEGX_IMM16_X1_HW0_LAST_TLS_IE,
  BFD_RELOC_TILEGX_IMM16_X0_HW1_LAST_TLS_IE,
  BFD_RELOC_TILEGX_IMM16_X1_HW1_LAST_TLS_IE,
  BFD_RELOC_TILEGX_TLS_DTPMOD64,
  BFD_RELOC_TILEGX_TLS_DTPOFF64,
  BFD_RELOC_TILEGX_TLS_TPOFF64,
  BFD_RELOC_TILEGX_TLS_DTPMOD32,
  BFD_RELOC_TILEGX_TLS_DTPOFF32,
  BFD_RELOC_TILEGX_TLS_TPOFF32,
  BFD_RELOC_TILEGX_TLS_GD_CALL,
  BFD_RELOC_TILEGX_IMM8_X0_TLS_GD_ADD,
  BFD_RELOC_TILEGX_IMM8_X1_TLS_GD_ADD,
  BFD_RELOC_TILEGX_IMM8_Y0_TLS_GD_ADD,
  BFD_RELOC_TILEGX_IMM8_Y1_TLS_GD_ADD,
  BFD_RELOC_TILEGX_TLS_IE_LOAD,
  BFD_RELOC_TILEGX_IMM8_X0_TLS_ADD,
  BFD_RELOC_TILEGX_IMM8_X1_TLS_ADD,
  BFD_RELOC_TILEGX_IMM8_Y0_TLS_ADD,
  BFD_RELOC_TILEGX_IMM8_Y1_TLS_ADD,

  BFD_RELOC_EPIPHANY_SIMM8,

  BFD_RELOC_EPIPHANY_SIMM24,

  BFD_RELOC_EPIPHANY_HIGH,

  BFD_RELOC_EPIPHANY_LOW,

  BFD_RELOC_EPIPHANY_SIMM11,

  BFD_RELOC_EPIPHANY_IMM11,

  BFD_RELOC_EPIPHANY_IMM8,
  BFD_RELOC_UNUSED
};
typedef enum bfd_reloc_code_real bfd_reloc_code_real_type;
reloc_howto_type *bfd_reloc_type_lookup (bfd *abfd,
                                         bfd_reloc_code_real_type code);
reloc_howto_type *bfd_reloc_name_lookup (bfd *abfd, const char *reloc_name);

const char *bfd_get_reloc_code_name (bfd_reloc_code_real_type code);

typedef struct bfd_symbol
{
  struct bfd *the_bfd;

  const char *name;

  symvalue value;
  flagword flags;

  struct bfd_section *section;

  union
  {
    void *p;
    bfd_vma i;
  } udata;
} asymbol;

bfd_boolean bfd_is_local_label (bfd *abfd, asymbol *sym);

bfd_boolean bfd_is_local_label_name (bfd *abfd, const char *name);

bfd_boolean bfd_is_target_special_symbol (bfd *abfd, asymbol *sym);

bfd_boolean bfd_set_symtab (bfd *abfd, asymbol **location, unsigned int count);

void bfd_print_symbol_vandf (bfd *abfd, void *file, asymbol *symbol);

asymbol *_bfd_generic_make_empty_symbol (bfd *);

int bfd_decode_symclass (asymbol *symbol);

bfd_boolean bfd_is_undefined_symclass (int symclass);

void bfd_symbol_info (asymbol *symbol, symbol_info *ret);

bfd_boolean bfd_copy_private_symbol_data (bfd *ibfd, asymbol *isym, bfd *obfd,
                                          asymbol *osym);

enum bfd_direction
{
  no_direction = 0,
  read_direction = 1,
  write_direction = 2,
  both_direction = 3
};

struct bfd
{

  unsigned int id;

  const char *filename;

  const struct bfd_target *xvec;

  void *iostream;
  const struct bfd_iovec *iovec;

  struct bfd *lru_prev, *lru_next;

  ufile_ptr where;

  long mtime;

  int ifd;

  bfd_format format;

  enum bfd_direction direction;

  flagword flags;
  ufile_ptr origin;

  ufile_ptr proxy_origin;

  struct bfd_hash_table section_htab;

  struct bfd_section *sections;

  struct bfd_section *section_last;

  unsigned int section_count;

  bfd_vma start_address;

  unsigned int symcount;

  struct bfd_symbol **outsymbols;

  unsigned int dynsymcount;

  const struct bfd_arch_info *arch_info;

  void *arelt_data;
  struct bfd *my_archive;
  struct bfd *archive_next;
  struct bfd *archive_head;
  struct bfd *nested_archives;

  struct bfd *link_next;

  int archive_pass;

  union
  {
    struct aout_data_struct *aout_data;
    struct artdata *aout_ar_data;
    struct _oasys_data *oasys_obj_data;
    struct _oasys_ar_data *oasys_ar_data;
    struct coff_tdata *coff_obj_data;
    struct pe_tdata *pe_obj_data;
    struct xcoff_tdata *xcoff_obj_data;
    struct ecoff_tdata *ecoff_obj_data;
    struct ieee_data_struct *ieee_data;
    struct ieee_ar_data_struct *ieee_ar_data;
    struct srec_data_struct *srec_data;
    struct verilog_data_struct *verilog_data;
    struct ihex_data_struct *ihex_data;
    struct tekhex_data_struct *tekhex_data;
    struct elf_obj_tdata *elf_obj_data;
    struct nlm_obj_tdata *nlm_obj_data;
    struct bout_data_struct *bout_data;
    struct mmo_data_struct *mmo_data;
    struct sun_core_struct *sun_core_data;
    struct sco5_core_struct *sco5_core_data;
    struct trad_core_struct *trad_core_data;
    struct som_data_struct *som_data;
    struct hpux_core_struct *hpux_core_data;
    struct hppabsd_core_struct *hppabsd_core_data;
    struct sgi_core_struct *sgi_core_data;
    struct lynx_core_struct *lynx_core_data;
    struct osf_core_struct *osf_core_data;
    struct cisco_core_struct *cisco_core_data;
    struct versados_data_struct *versados_data;
    struct netbsd_core_struct *netbsd_core_data;
    struct mach_o_data_struct *mach_o_data;
    struct mach_o_fat_data_struct *mach_o_fat_data;
    struct plugin_data_struct *plugin_data;
    struct bfd_pef_data_struct *pef_data;
    struct bfd_pef_xlib_data_struct *pef_xlib_data;
    struct bfd_sym_data_struct *sym_data;
    void *any;
  } tdata;

  void *usrdata;

  void *memory;

  unsigned int cacheable : 1;

  unsigned int target_defaulted : 1;

  unsigned int opened_once : 1;

  unsigned int mtime_set : 1;

  unsigned int no_export : 1;

  unsigned int output_has_begun : 1;

  unsigned int has_armap : 1;

  unsigned int is_thin_archive : 1;

  unsigned int selective_search : 1;
};

static __inline__ bfd_boolean
bfd_set_cacheable (bfd *abfd, bfd_boolean val)
{
  abfd->cacheable = val;
  return 1;
}

typedef enum bfd_error
{
  bfd_error_no_error = 0,
  bfd_error_system_call,
  bfd_error_invalid_target,
  bfd_error_wrong_format,
  bfd_error_wrong_object_format,
  bfd_error_invalid_operation,
  bfd_error_no_memory,
  bfd_error_no_symbols,
  bfd_error_no_armap,
  bfd_error_no_more_archived_files,
  bfd_error_malformed_archive,
  bfd_error_missing_dso,
  bfd_error_file_not_recognized,
  bfd_error_file_ambiguously_recognized,
  bfd_error_no_contents,
  bfd_error_nonrepresentable_section,
  bfd_error_no_debug_section,
  bfd_error_bad_value,
  bfd_error_file_truncated,
  bfd_error_file_too_big,
  bfd_error_on_input,
  bfd_error_invalid_error_code
} bfd_error_type;

bfd_error_type bfd_get_error (void);

void bfd_set_error (bfd_error_type error_tag, ...);

const char *bfd_errmsg (bfd_error_type error_tag);

void bfd_perror (const char *message);

typedef void (*bfd_error_handler_type)(const char *, ...);

bfd_error_handler_type bfd_set_error_handler (bfd_error_handler_type);

void bfd_set_error_program_name (const char *);

bfd_error_handler_type bfd_get_error_handler (void);

typedef void (*bfd_assert_handler_type)(const char *bfd_formatmsg,
                                        const char *bfd_version,
                                        const char *bfd_file, int bfd_line);

bfd_assert_handler_type bfd_set_assert_handler (bfd_assert_handler_type);

bfd_assert_handler_type bfd_get_assert_handler (void);

long bfd_get_reloc_upper_bound (bfd *abfd, asection *sect);

long bfd_canonicalize_reloc (bfd *abfd, asection *sec, arelent **loc,
                             asymbol **syms);

void bfd_set_reloc (bfd *abfd, asection *sec, arelent **rel,
                    unsigned int count);

bfd_boolean bfd_set_file_flags (bfd *abfd, flagword flags);

int bfd_get_arch_size (bfd *abfd);

int bfd_get_sign_extend_vma (bfd *abfd);

bfd_boolean bfd_set_start_address (bfd *abfd, bfd_vma vma);

unsigned int bfd_get_gp_size (bfd *abfd);

void bfd_set_gp_size (bfd *abfd, unsigned int i);

bfd_vma bfd_scan_vma (const char *string, const char **end, int base);

bfd_boolean bfd_copy_private_header_data (bfd *ibfd, bfd *obfd);

bfd_boolean bfd_copy_private_bfd_data (bfd *ibfd, bfd *obfd);

bfd_boolean bfd_merge_private_bfd_data (bfd *ibfd, bfd *obfd);

bfd_boolean bfd_set_private_flags (bfd *abfd, flagword flags);
extern bfd_byte *bfd_get_relocated_section_contents (bfd *,
                                                     struct bfd_link_info *,
                                                     struct bfd_link_order *,
                                                     bfd_byte *, bfd_boolean,
                                                     asymbol **);

bfd_boolean bfd_alt_mach_code (bfd *abfd, int alternative);

bfd_vma bfd_emul_get_maxpagesize (const char *);

void bfd_emul_set_maxpagesize (const char *, bfd_vma);

bfd_vma bfd_emul_get_commonpagesize (const char *);

void bfd_emul_set_commonpagesize (const char *, bfd_vma);

char *bfd_demangle (bfd *, const char *, int);

symindex bfd_get_next_mapent (bfd *abfd, symindex previous, carsym **sym);

bfd_boolean bfd_set_archive_head (bfd *output, bfd *new_head);

bfd *bfd_openr_next_archived_file (bfd *archive, bfd *previous);

const char *bfd_core_file_failing_command (bfd *abfd);

int bfd_core_file_failing_signal (bfd *abfd);

int bfd_core_file_pid (bfd *abfd);

bfd_boolean core_file_matches_executable_p (bfd *core_bfd, bfd *exec_bfd);

bfd_boolean generic_core_file_matches_executable_p (bfd *core_bfd,
                                                    bfd *exec_bfd);
enum bfd_flavour
{
  bfd_target_unknown_flavour,
  bfd_target_aout_flavour,
  bfd_target_coff_flavour,
  bfd_target_ecoff_flavour,
  bfd_target_xcoff_flavour,
  bfd_target_elf_flavour,
  bfd_target_ieee_flavour,
  bfd_target_nlm_flavour,
  bfd_target_oasys_flavour,
  bfd_target_tekhex_flavour,
  bfd_target_srec_flavour,
  bfd_target_verilog_flavour,
  bfd_target_ihex_flavour,
  bfd_target_som_flavour,
  bfd_target_os9k_flavour,
  bfd_target_versados_flavour,
  bfd_target_msdos_flavour,
  bfd_target_ovax_flavour,
  bfd_target_evax_flavour,
  bfd_target_mmo_flavour,
  bfd_target_mach_o_flavour,
  bfd_target_pef_flavour,
  bfd_target_pef_xlib_flavour,
  bfd_target_sym_flavour
};

enum bfd_endian
{
  BFD_ENDIAN_BIG,
  BFD_ENDIAN_LITTLE,
  BFD_ENDIAN_UNKNOWN
};

typedef struct bfd_link_info _bfd_link_info;

typedef struct flag_info flag_info;

typedef struct bfd_target
{

  char *name;

  enum bfd_flavour flavour;

  enum bfd_endian byteorder;

  enum bfd_endian header_byteorder;

  flagword object_flags;

  flagword section_flags;

  char symbol_leading_char;

  char ar_pad_char;

  unsigned char ar_max_namelen;

  unsigned char match_priority;

  bfd_uint64_t (*bfd_getx64)(const void *);
  bfd_int64_t (*bfd_getx_signed_64)(const void *);
  void (*bfd_putx64)(bfd_uint64_t, void *);
  bfd_vma (*bfd_getx32)(const void *);
  bfd_signed_vma (*bfd_getx_signed_32)(const void *);
  void (*bfd_putx32)(bfd_vma, void *);
  bfd_vma (*bfd_getx16)(const void *);
  bfd_signed_vma (*bfd_getx_signed_16)(const void *);
  void (*bfd_putx16)(bfd_vma, void *);

  bfd_uint64_t (*bfd_h_getx64)(const void *);
  bfd_int64_t (*bfd_h_getx_signed_64)(const void *);
  void (*bfd_h_putx64)(bfd_uint64_t, void *);
  bfd_vma (*bfd_h_getx32)(const void *);
  bfd_signed_vma (*bfd_h_getx_signed_32)(const void *);
  void (*bfd_h_putx32)(bfd_vma, void *);
  bfd_vma (*bfd_h_getx16)(const void *);
  bfd_signed_vma (*bfd_h_getx_signed_16)(const void *);
  void (*bfd_h_putx16)(bfd_vma, void *);

  const struct bfd_target *(*_bfd_check_format[bfd_type_end])(bfd *);

  bfd_boolean (*_bfd_set_format[bfd_type_end])(bfd *);

  bfd_boolean (*_bfd_write_contents[bfd_type_end])(bfd *);
  bfd_boolean (*_close_and_cleanup)(bfd *);

  bfd_boolean (*_bfd_free_cached_info)(bfd *);

  bfd_boolean (*_new_section_hook)(bfd *, sec_ptr);

  bfd_boolean (*_bfd_get_section_contents)(bfd *, sec_ptr, void *, file_ptr,
                                           bfd_size_type);
  bfd_boolean (*_bfd_get_section_contents_in_window)(bfd *, sec_ptr,
                                                     bfd_window *, file_ptr,
                                                     bfd_size_type);
  bfd_boolean (*_bfd_copy_private_bfd_data)(bfd *, bfd *);

  bfd_boolean (*_bfd_merge_private_bfd_data)(bfd *, bfd *);

  bfd_boolean (*_bfd_init_private_section_data)(bfd *, sec_ptr, bfd *, sec_ptr,
                                                struct bfd_link_info *);

  bfd_boolean (*_bfd_copy_private_section_data)(bfd *, sec_ptr, bfd *,
                                                sec_ptr);

  bfd_boolean (*_bfd_copy_private_symbol_data)(bfd *, asymbol *, bfd *,
                                               asymbol *);

  bfd_boolean (*_bfd_copy_private_header_data)(bfd *, bfd *);

  bfd_boolean (*_bfd_set_private_flags)(bfd *, flagword);

  bfd_boolean (*_bfd_print_private_bfd_data)(bfd *, void *);
  char *(*_core_file_failing_command)(bfd *);
  int (*_core_file_failing_signal)(bfd *);
  bfd_boolean (*_core_file_matches_executable_p)(bfd *, bfd *);
  int (*_core_file_pid)(bfd *);
  bfd_boolean (*_bfd_slurp_armap)(bfd *);
  bfd_boolean (*_bfd_slurp_extended_name_table)(bfd *);
  bfd_boolean (*_bfd_construct_extended_name_table)(bfd *, char **,
                                                    bfd_size_type *,
                                                    const char **);
  void (*_bfd_truncate_arname)(bfd *, const char *, char *);
  bfd_boolean (*write_armap)(bfd *, unsigned int, struct orl *, unsigned int,
                             int);
  void *(*_bfd_read_ar_hdr_fn)(bfd *);
  bfd_boolean (*_bfd_write_ar_hdr_fn)(bfd *, bfd *);
  bfd *(*openr_next_archived_file)(bfd *, bfd *);

  bfd *(*_bfd_get_elt_at_index)(bfd *, symindex);
  int (*_bfd_stat_arch_elt)(bfd *, struct stat *);
  bfd_boolean (*_bfd_update_armap_timestamp)(bfd *);
  long (*_bfd_get_symtab_upper_bound)(bfd *);
  long (*_bfd_canonicalize_symtab)(bfd *, struct bfd_symbol **);
  struct bfd_symbol *(*_bfd_make_empty_symbol)(bfd *);
  void (*_bfd_print_symbol)(bfd *, void *, struct bfd_symbol *,
                            bfd_print_symbol_type);

  void (*_bfd_get_symbol_info)(bfd *, struct bfd_symbol *, symbol_info *);

  bfd_boolean (*_bfd_is_local_label_name)(bfd *, const char *);
  bfd_boolean (*_bfd_is_target_special_symbol)(bfd *, asymbol *);
  alent *(*_get_lineno)(bfd *, struct bfd_symbol *);
  bfd_boolean (*_bfd_find_nearest_line)(bfd *, struct bfd_section *,
                                        struct bfd_symbol **, bfd_vma,
                                        const char **, const char **,
                                        unsigned int *);
  bfd_boolean (*_bfd_find_nearest_line_discriminator)(
      bfd *, struct bfd_section *, struct bfd_symbol **, bfd_vma,
      const char **, const char **, unsigned int *, unsigned int *);
  bfd_boolean (*_bfd_find_line)(bfd *, struct bfd_symbol **,
                                struct bfd_symbol *, const char **,
                                unsigned int *);
  bfd_boolean (*_bfd_find_inliner_info)(bfd *, const char **, const char **,
                                        unsigned int *);

  asymbol *(*_bfd_make_debug_symbol)(bfd *, void *, unsigned long size);

  long (*_read_minisymbols)(bfd *, bfd_boolean, void **, unsigned int *);

  asymbol *(*_minisymbol_to_symbol)(bfd *, bfd_boolean, const void *,
                                    asymbol *);
  long (*_get_reloc_upper_bound)(bfd *, sec_ptr);
  long (*_bfd_canonicalize_reloc)(bfd *, sec_ptr, arelent **,
                                  struct bfd_symbol **);

  reloc_howto_type *(*reloc_type_lookup)(bfd *, bfd_reloc_code_real_type);
  reloc_howto_type *(*reloc_name_lookup)(bfd *, const char *);

  bfd_boolean (*_bfd_set_arch_mach)(bfd *, enum bfd_architecture,
                                    unsigned long);
  bfd_boolean (*_bfd_set_section_contents)(bfd *, sec_ptr, const void *,
                                           file_ptr, bfd_size_type);
  int (*_bfd_sizeof_headers)(bfd *, struct bfd_link_info *);
  bfd_byte *(*_bfd_get_relocated_section_contents)(bfd *,
                                                   struct bfd_link_info *,
                                                   struct bfd_link_order *,
                                                   bfd_byte *, bfd_boolean,
                                                   struct bfd_symbol **);

  bfd_boolean (*_bfd_relax_section)(bfd *, struct bfd_section *,
                                    struct bfd_link_info *, bfd_boolean *);

  struct bfd_link_hash_table *(*_bfd_link_hash_table_create)(bfd *);

  void (*_bfd_link_hash_table_free)(struct bfd_link_hash_table *);

  bfd_boolean (*_bfd_link_add_symbols)(bfd *, struct bfd_link_info *);

  void (*_bfd_link_just_syms)(asection *, struct bfd_link_info *);

  void (*_bfd_copy_link_hash_symbol_type)(bfd *, struct bfd_link_hash_entry *,
                                          struct bfd_link_hash_entry *);

  bfd_boolean (*_bfd_final_link)(bfd *, struct bfd_link_info *);

  bfd_boolean (*_bfd_link_split_section)(bfd *, struct bfd_section *);

  bfd_boolean (*_bfd_gc_sections)(bfd *, struct bfd_link_info *);

  bfd_boolean (*_bfd_lookup_section_flags)(struct bfd_link_info *,
                                           struct flag_info *, asection *);

  bfd_boolean (*_bfd_merge_sections)(bfd *, struct bfd_link_info *);

  bfd_boolean (*_bfd_is_group_section)(bfd *, const struct bfd_section *);

  bfd_boolean (*_bfd_discard_group)(bfd *, struct bfd_section *);

  bfd_boolean (*_section_already_linked)(bfd *, asection *,
                                         struct bfd_link_info *);

  bfd_boolean (*_bfd_define_common_symbol)(bfd *, struct bfd_link_info *,
                                           struct bfd_link_hash_entry *);
  long (*_bfd_get_dynamic_symtab_upper_bound)(bfd *);

  long (*_bfd_canonicalize_dynamic_symtab)(bfd *, struct bfd_symbol **);

  long (*_bfd_get_synthetic_symtab)(bfd *, long, struct bfd_symbol **, long,
                                    struct bfd_symbol **,
                                    struct bfd_symbol **);

  long (*_bfd_get_dynamic_reloc_upper_bound)(bfd *);

  long (*_bfd_canonicalize_dynamic_reloc)(bfd *, arelent **,
                                          struct bfd_symbol **);

  const struct bfd_target *alternative_target;

  const void *backend_data;

} bfd_target;

bfd_boolean bfd_set_default_target (const char *name);

const bfd_target *bfd_find_target (const char *target_name, bfd *abfd);

const bfd_target *bfd_get_target_info (const char *target_name, bfd *abfd,
                                       bfd_boolean *is_bigendian,
                                       int *underscoring,
                                       const char **def_target_arch);
const char **bfd_target_list (void);

const bfd_target *
bfd_search_for_target (int (*search_func)(const bfd_target *, void *), void *);

bfd_boolean bfd_check_format (bfd *abfd, bfd_format format);

bfd_boolean bfd_check_format_matches (bfd *abfd, bfd_format format,
                                      char ***matching);

bfd_boolean bfd_set_format (bfd *abfd, bfd_format format);

const char *bfd_format_string (bfd_format format);

bfd_boolean bfd_link_split_section (bfd *abfd, asection *sec);

bfd_boolean bfd_section_already_linked (bfd *abfd, asection *sec,
                                        struct bfd_link_info *info);

bfd_boolean bfd_generic_define_common_symbol (bfd *output_bfd,
                                              struct bfd_link_info *info,
                                              struct bfd_link_hash_entry *h);

struct bfd_elf_version_tree *
bfd_find_version_for_sym (struct bfd_elf_version_tree *verdefs,
                          const char *sym_name, bfd_boolean *hide);

bfd_boolean bfd_hide_sym_by_version (struct bfd_elf_version_tree *verdefs,
                                     const char *sym_name);

bfd_byte *bfd_simple_get_relocated_section_contents (bfd *abfd, asection *sec,
                                                     bfd_byte *outbuf,
                                                     asymbol **symbol_table);

bfd_boolean bfd_compress_section_contents (bfd *abfd, asection *section,
                                           bfd_byte *uncompressed_buffer,
                                           bfd_size_type uncompressed_size);

bfd_boolean bfd_get_full_section_contents (bfd *abfd, asection *section,
                                           bfd_byte **ptr);

void bfd_cache_section_contents (asection *sec, void *contents);

bfd_boolean bfd_is_section_compressed (bfd *abfd, asection *section);

bfd_boolean bfd_init_section_decompress_status (bfd *abfd, asection *section);

bfd_boolean bfd_init_section_compress_status (bfd *abfd, asection *section);

typedef int (*fprintf_ftype)(void *, const char *, ...)
    __attribute__ ((__format__ (__printf__, 2, 3)))
    __attribute__ ((__nonnull__ (2)));

enum dis_insn_type
{
  dis_noninsn,
  dis_nonbranch,
  dis_branch,
  dis_condbranch,
  dis_jsr,
  dis_condjsr,
  dis_dref,
  dis_dref2
};

typedef struct disassemble_info
{
  fprintf_ftype fprintf_func;
  void *stream;

  int mach;

  void *private_data;

  int (*read_memory_func)(bfd_vma memaddr, bfd_byte *myaddr,
                          unsigned int length, struct disassemble_info *dinfo);

  void (*memory_error_func)(int status, bfd_vma memaddr,
                            struct disassemble_info *dinfo);

  void (*print_address_func)(bfd_vma addr, struct disassemble_info *dinfo);

  int bytes_per_line;
  int bytes_per_chunk;
  int display_endian;

} disassemble_info;
#endif /* DIS_GNU_H */

