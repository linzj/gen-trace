#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include "dis_gnu.h"
#define dcgettext(a,b,c) b
typedef int (*disassembler_ftype) (bfd_vma, disassemble_info *);

extern int print_insn_aarch64 (bfd_vma, disassemble_info *);
extern int print_insn_alpha (bfd_vma, disassemble_info *);
extern int print_insn_avr (bfd_vma, disassemble_info *);
extern int print_insn_bfin (bfd_vma, disassemble_info *);
extern int print_insn_big_arm (bfd_vma, disassemble_info *);
extern int print_insn_big_mips (bfd_vma, disassemble_info *);
extern int print_insn_big_nios2 (bfd_vma, disassemble_info *);
extern int print_insn_big_powerpc (bfd_vma, disassemble_info *);
extern int print_insn_big_score (bfd_vma, disassemble_info *);
extern int print_insn_cr16 (bfd_vma, disassemble_info *);
extern int print_insn_crx (bfd_vma, disassemble_info *);
extern int print_insn_d10v (bfd_vma, disassemble_info *);
extern int print_insn_d30v (bfd_vma, disassemble_info *);
extern int print_insn_dlx (bfd_vma, disassemble_info *);
extern int print_insn_epiphany (bfd_vma, disassemble_info *);
extern int print_insn_fr30 (bfd_vma, disassemble_info *);
extern int print_insn_frv (bfd_vma, disassemble_info *);
extern int print_insn_h8300 (bfd_vma, disassemble_info *);
extern int print_insn_h8300h (bfd_vma, disassemble_info *);
extern int print_insn_h8300s (bfd_vma, disassemble_info *);
extern int print_insn_h8500 (bfd_vma, disassemble_info *);
extern int print_insn_hppa (bfd_vma, disassemble_info *);
extern int print_insn_i370 (bfd_vma, disassemble_info *);
extern int print_insn_i386 (bfd_vma, disassemble_info *);
extern int print_insn_i386_att (bfd_vma, disassemble_info *);
extern int print_insn_i386_intel (bfd_vma, disassemble_info *);
extern int print_insn_i860 (bfd_vma, disassemble_info *);
extern int print_insn_i960 (bfd_vma, disassemble_info *);
extern int print_insn_ia64 (bfd_vma, disassemble_info *);
extern int print_insn_ip2k (bfd_vma, disassemble_info *);
extern int print_insn_iq2000 (bfd_vma, disassemble_info *);
extern int print_insn_little_arm (bfd_vma, disassemble_info *);
extern int print_insn_little_mips (bfd_vma, disassemble_info *);
extern int print_insn_little_nios2 (bfd_vma, disassemble_info *);
extern int print_insn_little_powerpc (bfd_vma, disassemble_info *);
extern int print_insn_little_score (bfd_vma, disassemble_info *);
extern int print_insn_lm32 (bfd_vma, disassemble_info *);
extern int print_insn_m32c (bfd_vma, disassemble_info *);
extern int print_insn_m32r (bfd_vma, disassemble_info *);
extern int print_insn_m68hc11 (bfd_vma, disassemble_info *);
extern int print_insn_m68hc12 (bfd_vma, disassemble_info *);
extern int print_insn_m9s12x (bfd_vma, disassemble_info *);
extern int print_insn_m9s12xg (bfd_vma, disassemble_info *);
extern int print_insn_m68k (bfd_vma, disassemble_info *);
extern int print_insn_m88k (bfd_vma, disassemble_info *);
extern int print_insn_mcore (bfd_vma, disassemble_info *);
extern int print_insn_mep (bfd_vma, disassemble_info *);
extern int print_insn_metag (bfd_vma, disassemble_info *);
extern int print_insn_microblaze (bfd_vma, disassemble_info *);
extern int print_insn_mmix (bfd_vma, disassemble_info *);
extern int print_insn_mn10200 (bfd_vma, disassemble_info *);
extern int print_insn_mn10300 (bfd_vma, disassemble_info *);
extern int print_insn_moxie (bfd_vma, disassemble_info *);
extern int print_insn_msp430 (bfd_vma, disassemble_info *);
extern int print_insn_mt (bfd_vma, disassemble_info *);
extern int print_insn_nds32 (bfd_vma, disassemble_info *);
extern int print_insn_ns32k (bfd_vma, disassemble_info *);
extern int print_insn_or1k (bfd_vma, disassemble_info *);
extern int print_insn_pdp11 (bfd_vma, disassemble_info *);
extern int print_insn_pj (bfd_vma, disassemble_info *);
extern int print_insn_rs6000 (bfd_vma, disassemble_info *);
extern int print_insn_s390 (bfd_vma, disassemble_info *);
extern int print_insn_sh (bfd_vma, disassemble_info *);
extern int print_insn_sh64 (bfd_vma, disassemble_info *);
extern int print_insn_sh64x_media (bfd_vma, disassemble_info *);
extern int print_insn_sparc (bfd_vma, disassemble_info *);
extern int print_insn_spu (bfd_vma, disassemble_info *);
extern int print_insn_tic30 (bfd_vma, disassemble_info *);
extern int print_insn_tic4x (bfd_vma, disassemble_info *);
extern int print_insn_tic54x (bfd_vma, disassemble_info *);
extern int print_insn_tic6x (bfd_vma, disassemble_info *);
extern int print_insn_tic80 (bfd_vma, disassemble_info *);
extern int print_insn_tilegx (bfd_vma, disassemble_info *);
extern int print_insn_tilepro (bfd_vma, disassemble_info *);
extern int print_insn_v850 (bfd_vma, disassemble_info *);
extern int print_insn_vax (bfd_vma, disassemble_info *);
extern int print_insn_w65 (bfd_vma, disassemble_info *);
extern int print_insn_xc16x (bfd_vma, disassemble_info *);
extern int print_insn_xgate (bfd_vma, disassemble_info *);
extern int print_insn_xstormy16 (bfd_vma, disassemble_info *);
extern int print_insn_xtensa (bfd_vma, disassemble_info *);
extern int print_insn_z80 (bfd_vma, disassemble_info *);
extern int print_insn_z8001 (bfd_vma, disassemble_info *);
extern int print_insn_z8002 (bfd_vma, disassemble_info *);
extern int print_insn_rx (bfd_vma, disassemble_info *);
extern int print_insn_rl78 (bfd_vma, disassemble_info *);

extern disassembler_ftype arc_get_disassembler (void *);
extern disassembler_ftype cris_get_disassembler (bfd *);

extern void print_aarch64_disassembler_options (FILE *);
extern void print_i386_disassembler_options (FILE *);
extern void print_mips_disassembler_options (FILE *);
extern void print_ppc_disassembler_options (FILE *);
extern void print_arm_disassembler_options (FILE *);
extern void print_s390_disassembler_options (FILE *);
extern int get_arm_regname_num_options (void);
extern int set_arm_regname_option (int);
extern int get_arm_regnames (int, const char **, const char **, const char *const **);
extern bfd_boolean aarch64_symbol_is_valid (asymbol *, struct disassemble_info *);
extern bfd_boolean arm_symbol_is_valid (asymbol *, struct disassemble_info *);
extern void disassemble_init_powerpc (struct disassemble_info *);


extern disassembler_ftype disassembler (bfd *);



extern void disassemble_init_for_target (struct disassemble_info * dinfo);


extern void disassembler_usage (FILE *);







extern int buffer_read_memory
  (bfd_vma, bfd_byte *, unsigned int, struct disassemble_info *);



extern void perror_memory (int, bfd_vma, struct disassemble_info *);





extern void generic_print_address
  (bfd_vma, struct disassemble_info *);


extern int generic_symbol_at_address
  (bfd_vma, struct disassemble_info *);


extern bfd_boolean generic_symbol_is_valid
  (asymbol *, struct disassemble_info *);



extern void init_disassemble_info (struct disassemble_info *dinfo, void *stream,
       fprintf_ftype fprintf_func);
typedef struct
{
  unsigned long core;
  unsigned long coproc;
} arm_feature_set;

struct internal_extra_pe_filehdr
{

  unsigned short e_magic;
  unsigned short e_cblp;
  unsigned short e_cp;
  unsigned short e_crlc;
  unsigned short e_cparhdr;
  unsigned short e_minalloc;
  unsigned short e_maxalloc;
  unsigned short e_ss;
  unsigned short e_sp;
  unsigned short e_csum;
  unsigned short e_ip;
  unsigned short e_cs;
  unsigned short e_lfarlc;
  unsigned short e_ovno;
  unsigned short e_res[4];
  unsigned short e_oemid;
  unsigned short e_oeminfo;
  unsigned short e_res2[10];
  bfd_vma e_lfanew;
  unsigned long dos_message[16];
  bfd_vma nt_signature;
};



struct internal_filehdr
{
  struct internal_extra_pe_filehdr pe;






  char go32stub[2048];


  unsigned short f_magic;
  unsigned int f_nscns;
  long f_timdat;
  bfd_vma f_symptr;
  long f_nsyms;
  unsigned short f_opthdr;
  unsigned short f_flags;
  unsigned short f_target_id;
};
typedef struct _IMAGE_DATA_DIRECTORY
{
  bfd_vma VirtualAddress;
  long Size;
} IMAGE_DATA_DIRECTORY;
struct internal_IMAGE_DEBUG_DIRECTORY
{
  unsigned long Characteristics;
  unsigned long TimeDateStamp;
  unsigned short MajorVersion;
  unsigned short MinorVersion;
  unsigned long Type;
  unsigned long SizeOfData;
  unsigned long AddressOfRawData;
  unsigned long PointerToRawData;
};
typedef struct _CODEVIEW_INFO
{
  unsigned long CVSignature;
  char Signature[16];
  unsigned int SignatureLength;
  unsigned long Age;

} CODEVIEW_INFO;
struct internal_extra_pe_aouthdr
{




  short Magic;

  char MajorLinkerVersion;

  char MinorLinkerVersion;

  long SizeOfCode;

  long SizeOfInitializedData;

  long SizeOfUninitializedData;

  bfd_vma AddressOfEntryPoint;

  bfd_vma BaseOfCode;

  bfd_vma BaseOfData;


  bfd_vma ImageBase;


  bfd_vma SectionAlignment;
  bfd_vma FileAlignment;
  short MajorOperatingSystemVersion;
  short MinorOperatingSystemVersion;
  short MajorImageVersion;
  short MinorImageVersion;
  short MajorSubsystemVersion;
  short MinorSubsystemVersion;
  long Reserved1;
  long SizeOfImage;
  long SizeOfHeaders;
  long CheckSum;
  short Subsystem;
  unsigned short DllCharacteristics;
  bfd_vma SizeOfStackReserve;
  bfd_vma SizeOfStackCommit;

  bfd_vma SizeOfHeapReserve;
  bfd_vma SizeOfHeapCommit;
  long LoaderFlags;
  long NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[16];
};


struct internal_aouthdr
{
  short magic;
  short vstamp;
  bfd_vma tsize;
  bfd_vma dsize;
  bfd_vma bsize;
  bfd_vma entry;
  bfd_vma text_start;
  bfd_vma data_start;


  unsigned long tagentries;


  bfd_vma o_toc;
  short o_snentry;
  short o_sntext;
  short o_sndata;
  short o_sntoc;
  short o_snloader;
  short o_snbss;
  short o_algntext;
  short o_algndata;
  short o_modtype;
  short o_cputype;
  bfd_vma o_maxstack;
  bfd_vma o_maxdata;


  bfd_vma bss_start;
  bfd_vma gp_value;
  unsigned long gprmask;
  unsigned long cprmask[4];
  unsigned long fprmask;


  long o_inlib;
  long o_sri;
  long vid[2];

  struct internal_extra_pe_aouthdr pe;
};
struct internal_scnhdr
{
  char s_name[(8)];





  bfd_vma s_paddr;

  bfd_vma s_vaddr;
  bfd_vma s_size;
  bfd_vma s_scnptr;
  bfd_vma s_relptr;
  bfd_vma s_lnnoptr;
  unsigned long s_nreloc;
  unsigned long s_nlnno;
  long s_flags;
  long s_align;
  unsigned char s_page;
};
struct internal_lineno
{
  union
  {
    bfd_signed_vma l_symndx;
    bfd_signed_vma l_paddr;
  } l_addr;
  unsigned long l_lnno;
};







struct internal_syment
{
  union
  {
    char _n_name[8];
    struct
    {
      bfd_hostptr_t _n_zeroes;
      bfd_hostptr_t _n_offset;
    } _n_n;
    char *_n_nptr[2];
  } _n;
  bfd_vma n_value;
  short n_scnum;
  unsigned short n_flags;
  unsigned short n_type;
  unsigned char n_sclass;
  unsigned char n_numaux;
};
union internal_auxent
{
  struct
  {

    union
    {
      long l;
      struct coff_ptr_struct *p;
    } x_tagndx;

    union
    {
      struct
      {
 unsigned short x_lnno;
 unsigned short x_size;
      } x_lnsz;
      long x_fsize;
    } x_misc;

    union
    {
      struct
      {
 bfd_signed_vma x_lnnoptr;
 union
 {
   long l;
   struct coff_ptr_struct *p;
 } x_endndx;
      } x_fcn;

      struct
      {
 unsigned short x_dimen[4];
      } x_ary;
    } x_fcnary;

    unsigned short x_tvndx;
  } x_sym;

  union
  {
    char x_fname[14];
    struct
    {
      long x_zeroes;
      long x_offset;
    } x_n;
  } x_file;

  struct
  {
    long x_scnlen;
    unsigned short x_nreloc;
    unsigned short x_nlinno;
    unsigned long x_checksum;
    unsigned short x_associated;
    unsigned char x_comdat;
  } x_scn;

  struct
  {
    long x_tvfill;
    unsigned short x_tvlen;
    unsigned short x_tvran[2];
  } x_tv;




  struct
  {
    union
      {
 bfd_signed_vma l;
 struct coff_ptr_struct *p;
      } x_scnlen;
    long x_parmhash;
    unsigned short x_snhash;
    unsigned char x_smtyp;


    unsigned char x_smclas;
    long x_stab;
    unsigned short x_snstab;
  } x_csect;
  struct
  {


    long x_stindx;
  } x_sc;

  struct
  {
    unsigned long x_balntry;
  } x_bal;

  struct
  {
    unsigned long x_timestamp;
    char x_idstring[20];
  } x_ident;

};



struct internal_reloc
{
  bfd_vma r_vaddr;
  long r_symndx;
  unsigned short r_type;
  unsigned char r_size;
  unsigned char r_extern;
  unsigned long r_offset;
};
enum bfd_link_strip
{
  strip_none,
  strip_debugger,
  strip_some,
  strip_all
};



enum bfd_link_discard
{
  discard_sec_merge,

  discard_none,
  discard_l,
  discard_all
};




enum bfd_link_hash_table_type
  {
    bfd_link_generic_hash_table,
    bfd_link_elf_hash_table
  };




enum bfd_link_hash_type
{
  bfd_link_hash_new,
  bfd_link_hash_undefined,
  bfd_link_hash_undefweak,
  bfd_link_hash_defined,
  bfd_link_hash_defweak,
  bfd_link_hash_common,
  bfd_link_hash_indirect,
  bfd_link_hash_warning
};

enum bfd_link_common_skip_ar_symbols
{
  bfd_link_common_skip_none,
  bfd_link_common_skip_text,
  bfd_link_common_skip_data,
  bfd_link_common_skip_all
};

struct bfd_link_hash_common_entry
  {
    unsigned int alignment_power;
    asection *section;
  };




struct bfd_link_hash_entry
{

  struct bfd_hash_entry root;


  __extension__ enum bfd_link_hash_type type : 8;

  unsigned int non_ir_ref : 1;


  union
    {


      struct
 {
   struct bfd_link_hash_entry *next;
   bfd *abfd;
 } undef;

      struct
 {
   struct bfd_link_hash_entry *next;
   asection *section;
   bfd_vma value;
 } def;

      struct
 {
   struct bfd_link_hash_entry *next;
   struct bfd_link_hash_entry *link;
   const char *warning;
 } i;

      struct
 {
   struct bfd_link_hash_entry *next;
   struct bfd_link_hash_common_entry *p;
   bfd_size_type size;
 } c;
    } u;
};




struct bfd_link_hash_table
{

  struct bfd_hash_table table;


  struct bfd_link_hash_entry *undefs;

  struct bfd_link_hash_entry *undefs_tail;

  enum bfd_link_hash_table_type type;
};




extern struct bfd_link_hash_entry *bfd_link_hash_lookup
  (struct bfd_link_hash_table *, const char *, bfd_boolean create,
   bfd_boolean copy, bfd_boolean follow);





extern struct bfd_link_hash_entry *bfd_wrapped_link_hash_lookup
  (bfd *, struct bfd_link_info *, const char *, bfd_boolean,
   bfd_boolean, bfd_boolean);




extern struct bfd_link_hash_entry *unwrap_hash_lookup
  (struct bfd_link_info *, bfd *, struct bfd_link_hash_entry *);


extern void bfd_link_hash_traverse
  (struct bfd_link_hash_table *,
    bfd_boolean (*) (struct bfd_link_hash_entry *, void *),
    void *);


extern void bfd_link_add_undef
  (struct bfd_link_hash_table *, struct bfd_link_hash_entry *);


extern void bfd_link_repair_undef_list
  (struct bfd_link_hash_table *table);


extern bfd_boolean bfd_generic_link_read_symbols (bfd *);

struct bfd_sym_chain
{
  struct bfd_sym_chain *next;
  const char *name;
};



enum report_method
{



  RM_NOT_YET_SET = 0,
  RM_IGNORE,
  RM_GENERATE_WARNING,
  RM_GENERATE_ERROR
};

typedef enum {with_flags, without_flags} flag_type;


struct flag_info_list
{
  flag_type with;
  const char *name;
  bfd_boolean valid;
  struct flag_info_list *next;
};


struct flag_info
{
  flagword only_with_flags;
  flagword not_with_flags;
  struct flag_info_list *flag_list;
  bfd_boolean flags_initialized;
};

struct bfd_elf_dynamic_list;
struct bfd_elf_version_tree;




struct bfd_link_info
{

  unsigned int shared: 1;


  unsigned int executable : 1;


  unsigned int pie: 1;


  unsigned int relocatable: 1;


  unsigned int symbolic: 1;



  unsigned int nocopyreloc: 1;



  unsigned int export_dynamic: 1;



  unsigned int create_default_symver: 1;


  unsigned int gc_sections: 1;



  unsigned int notice_all: 1;


  unsigned int loading_lto_outputs: 1;


  unsigned int strip_discarded: 1;


  unsigned int dynamic_data: 1;


  __extension__ enum bfd_link_strip strip : 2;


  __extension__ enum bfd_link_discard discard : 2;



  __extension__ enum bfd_link_common_skip_ar_symbols common_skip_ar_symbols : 2;






  __extension__ enum report_method unresolved_syms_in_objects : 2;



  __extension__ enum report_method unresolved_syms_in_shared_libs : 2;


  unsigned int static_link: 1;



  unsigned int keep_memory: 1;



  unsigned int emitrelocations: 1;


  unsigned int relro: 1;



  unsigned int eh_frame_hdr: 1;


  unsigned int warn_shared_textrel: 1;


  unsigned int error_textrel: 1;


  unsigned int emit_hash: 1;


  unsigned int emit_gnu_hash: 1;




  unsigned int reduce_memory_overheads: 1;





  unsigned int traditional_format: 1;



  unsigned int combreloc: 1;



  unsigned int default_imported_symver: 1;


  unsigned int new_dtags: 1;



  unsigned int no_ld_generated_unwind_info: 1;




  unsigned int task_link: 1;


  unsigned int allow_multiple_definition: 1;


  unsigned int allow_undefined_version: 1;



  unsigned int dynamic: 1;



  unsigned int execstack: 1;



  unsigned int noexecstack: 1;



  unsigned int optimize: 1;


  unsigned int print_gc_sections: 1;


  unsigned int warn_alternate_em: 1;


  unsigned int user_phdrs: 1;




  char wrap_char;


  char path_separator;



  bfd_signed_vma stacksize;
  signed int disable_target_specific_optimizations;


  const struct bfd_link_callbacks *callbacks;


  struct bfd_link_hash_table *hash;



  struct bfd_hash_table *keep_hash;




  struct bfd_hash_table *notice_hash;



  struct bfd_hash_table *wrap_hash;



  struct bfd_hash_table *ignore_hash;


  bfd *output_bfd;



  bfd *input_bfds;
  bfd **input_bfds_tail;






  asection *create_object_symbols_section;



  struct bfd_sym_chain *gc_sym_list;


  void *base_file;



  const char *init_function;



  const char *fini_function;





  int relax_pass;




  int relax_trip;




  int pei386_auto_import;




  int pei386_runtime_pseudo_reloc;


  unsigned int spare_dynamic_tags;


  bfd_vma flags;


  bfd_vma flags_1;


  bfd_vma relro_start, relro_end;


  struct bfd_elf_dynamic_list *dynamic_list;


  struct bfd_elf_version_tree *version_info;
};
struct bfd_link_callbacks
{






  bfd_boolean (*add_archive_element)
    (struct bfd_link_info *, bfd *abfd, const char *name, bfd **subsbfd);




  bfd_boolean (*multiple_definition)
    (struct bfd_link_info *, struct bfd_link_hash_entry *h,
     bfd *nbfd, asection *nsec, bfd_vma nval);






  bfd_boolean (*multiple_common)
    (struct bfd_link_info *, struct bfd_link_hash_entry *h,
     bfd *nbfd, enum bfd_link_hash_type ntype, bfd_vma nsize);






  bfd_boolean (*add_to_set)
    (struct bfd_link_info *, struct bfd_link_hash_entry *entry,
     bfd_reloc_code_real_type reloc, bfd *abfd, asection *sec, bfd_vma value);






  bfd_boolean (*constructor)
    (struct bfd_link_info *, bfd_boolean constructor, const char *name,
     bfd *abfd, asection *sec, bfd_vma value);







  bfd_boolean (*warning)
    (struct bfd_link_info *, const char *warning, const char *symbol,
     bfd *abfd, asection *section, bfd_vma address);





  bfd_boolean (*undefined_symbol)
    (struct bfd_link_info *, const char *name, bfd *abfd,
     asection *section, bfd_vma address, bfd_boolean is_fatal);
  bfd_boolean (*reloc_overflow)
    (struct bfd_link_info *, struct bfd_link_hash_entry *entry,
     const char *name, const char *reloc_name, bfd_vma addend,
     bfd *abfd, asection *section, bfd_vma address);






  bfd_boolean (*reloc_dangerous)
    (struct bfd_link_info *, const char *message,
     bfd *abfd, asection *section, bfd_vma address);






  bfd_boolean (*unattached_reloc)
    (struct bfd_link_info *, const char *name,
     bfd *abfd, asection *section, bfd_vma address);






  bfd_boolean (*notice)
    (struct bfd_link_info *, struct bfd_link_hash_entry *h,
     bfd *abfd, asection *section, bfd_vma address, flagword flags,
     const char *string);

  void (*einfo)
    (const char *fmt, ...);

  void (*info)
    (const char *fmt, ...);

  void (*minfo)
    (const char *fmt, ...);



  bfd_boolean (*override_segment_assignment)
    (struct bfd_link_info *, bfd * abfd,
     asection * current_section, asection * previous_section,
     bfd_boolean new_segment);
};






enum bfd_link_order_type
{
  bfd_undefined_link_order,
  bfd_indirect_link_order,
  bfd_data_link_order,
  bfd_section_reloc_link_order,
  bfd_symbol_reloc_link_order
};




struct bfd_link_order
{

  struct bfd_link_order *next;

  enum bfd_link_order_type type;

  bfd_vma offset;

  bfd_size_type size;

  union
    {
      struct
 {






   asection *section;
 } indirect;
      struct
 {




   unsigned int size;

   bfd_byte *contents;
 } data;
      struct
 {



   struct bfd_link_order_reloc *p;
 } reloc;
    } u;
};
struct bfd_link_order_reloc
{

  bfd_reloc_code_real_type reloc;

  union
    {



      asection *section;


      const char *name;
    } u;






  bfd_vma addend;
};


extern struct bfd_link_order *bfd_new_link_order (bfd *, asection *);
struct bfd_elf_version_expr
{

  struct bfd_elf_version_expr *next;

  const char *pattern;

  unsigned int literal : 1;

  unsigned int symver : 1;

  unsigned int script : 1;




  unsigned int mask : 3;
};

struct bfd_elf_version_expr_head
{

  struct bfd_elf_version_expr *list;

  void *htab;

  struct bfd_elf_version_expr *remaining;

  unsigned int mask;
};



struct bfd_elf_version_deps
{

  struct bfd_elf_version_deps *next;

  struct bfd_elf_version_tree *version_needed;
};



struct bfd_elf_version_tree
{

  struct bfd_elf_version_tree *next;

  const char *name;

  unsigned int vernum;

  struct bfd_elf_version_expr_head globals;

  struct bfd_elf_version_expr_head locals;

  struct bfd_elf_version_deps *deps;

  unsigned int name_indx;

  int used;

  struct bfd_elf_version_expr *(*match)
    (struct bfd_elf_version_expr_head *head,
     struct bfd_elf_version_expr *prev, const char *sym);
};

struct bfd_elf_dynamic_list
{
  struct bfd_elf_version_expr_head head;
  struct bfd_elf_version_expr *(*match)
    (struct bfd_elf_version_expr_head *head,
     struct bfd_elf_version_expr *prev, const char *sym);
};
typedef struct coff_tdata
{
  struct coff_symbol_struct *symbols;
  unsigned int *conversion_table;
  int conv_table_size;
  file_ptr sym_filepos;

  struct coff_ptr_struct *raw_syments;
  unsigned long raw_syment_count;


  unsigned long int relocbase;




  unsigned local_n_btmask;
  unsigned local_n_btshft;
  unsigned local_n_tmask;
  unsigned local_n_tshift;
  unsigned local_symesz;
  unsigned local_auxesz;
  unsigned local_linesz;



  void * external_syms;

  bfd_boolean keep_syms;



  char *strings;

  bfd_boolean keep_strings;

  bfd_boolean strings_written;


  int pe;

  struct coff_link_hash_entry **sym_hashes;


  int *local_toc_sym_map;

  struct bfd_link_info *link_info;


  void * line_info;


  void * dwarf2_find_line_info;


  long timestamp;



  flagword flags;



  char *go32stub;
} coff_data_type;


typedef struct pe_tdata
{
  coff_data_type coff;
  struct internal_extra_pe_aouthdr pe_opthdr;
  int dll;
  int has_reloc_section;
  int dont_strip_reloc;
  bfd_boolean insert_timestamp;
  bfd_boolean (*in_reloc_p) (bfd *, reloc_howto_type *);
  flagword real_flags;


  struct
  {
    bfd_boolean (*after_write_object_contents) (bfd *);
    const char *style;
    asection *sec;
  } build_id;
} pe_data_type;





struct xcoff_tdata
{

  coff_data_type coff;


  bfd_boolean xcoff64;


  bfd_boolean full_aouthdr;


  bfd_vma toc;


  int sntoc;


  int snentry;


  int text_align_power;


  int data_align_power;


  short modtype;


  short cputype;


  bfd_vma maxdata;


  bfd_vma maxstack;


  asection **csects;
  long *debug_indices;
  unsigned int *lineno_counts;
  unsigned int import_file_id;
};
struct coff_section_tdata
{

  struct internal_reloc *relocs;

  bfd_boolean keep_relocs;

  bfd_byte *contents;

  bfd_boolean keep_contents;

  bfd_vma offset;
  unsigned int i;
  const char *function;

  struct coff_comdat_info *comdat;
  int line_base;

  void * stab_info;

  void * tdata;
};







struct xcoff_section_tdata
{


  asection *enclosing;


  unsigned int lineno_count;

  unsigned long first_symndx;
  unsigned long last_symndx;
};







struct pei_section_tdata
{

  bfd_size_type virt_size;

  long pe_flags;
};







struct coff_link_hash_entry
{
  struct bfd_link_hash_entry root;



  long indx;


  unsigned short type;


  unsigned char symbol_class;


  char numaux;


  bfd *auxbfd;


  union internal_auxent *aux;


  unsigned short coff_link_hash_flags;


};



struct coff_link_hash_table
{
  struct bfd_link_hash_table root;

  struct stab_info stab_info;
};
extern const bfd_target *coff_object_p
  (bfd *);
extern struct bfd_section *coff_section_from_bfd_index
  (bfd *, int);
extern long coff_get_symtab_upper_bound
  (bfd *);
extern long coff_canonicalize_symtab
  (bfd *, asymbol **);
extern int coff_count_linenumbers
  (bfd *);
extern struct coff_symbol_struct *coff_symbol_from
  (bfd *, asymbol *);
extern bfd_boolean coff_renumber_symbols
  (bfd *, int *);
extern void coff_mangle_symbols
  (bfd *);
extern bfd_boolean coff_write_symbols
  (bfd *);
extern bfd_boolean coff_write_alien_symbol
  (bfd *, asymbol *, struct internal_syment *, bfd_vma *,
   bfd_size_type *, asection **, bfd_size_type *);
extern bfd_boolean coff_write_linenumbers
  (bfd *);
extern alent *coff_get_lineno
  (bfd *, asymbol *);
extern asymbol *coff_section_symbol
  (bfd *, char *);
extern bfd_boolean _bfd_coff_get_external_symbols
  (bfd *);
extern const char *_bfd_coff_read_string_table
  (bfd *);
extern bfd_boolean _bfd_coff_free_symbols
  (bfd *);
extern struct coff_ptr_struct *coff_get_normalized_symtab
  (bfd *);
extern long coff_get_reloc_upper_bound
  (bfd *, sec_ptr);
extern asymbol *coff_make_empty_symbol
  (bfd *);
extern void coff_print_symbol
  (bfd *, void * filep, asymbol *, bfd_print_symbol_type);
extern void coff_get_symbol_info
  (bfd *, asymbol *, symbol_info *ret);
extern bfd_boolean _bfd_coff_is_local_label_name
  (bfd *, const char *);
extern asymbol *coff_bfd_make_debug_symbol
  (bfd *, void *, unsigned long);
extern bfd_boolean coff_find_nearest_line
  (bfd *, asection *, asymbol **, bfd_vma, const char **,
   const char **, unsigned int *);
extern bfd_boolean coff_find_nearest_line_discriminator
  (bfd *, asection *, asymbol **, bfd_vma, const char **,
   const char **, unsigned int *, unsigned int *);
struct dwarf_debug_section;
extern bfd_boolean coff_find_nearest_line_with_names
  (bfd *, const struct dwarf_debug_section *, asection *, asymbol **,
   bfd_vma, const char **, const char **, unsigned int *);
extern bfd_boolean coff_find_inliner_info
  (bfd *, const char **, const char **, unsigned int *);
extern int coff_sizeof_headers
  (bfd *, struct bfd_link_info *);
extern bfd_boolean bfd_coff_reloc16_relax_section
  (bfd *, asection *, struct bfd_link_info *, bfd_boolean *);
extern bfd_byte *bfd_coff_reloc16_get_relocated_section_contents
  (bfd *, struct bfd_link_info *, struct bfd_link_order *,
   bfd_byte *, bfd_boolean, asymbol **);
extern bfd_vma bfd_coff_reloc16_get_value
  (arelent *, struct bfd_link_info *, asection *);
extern void bfd_perform_slip
  (bfd *, unsigned int, asection *, bfd_vma);
struct coff_debug_merge_element
{

  struct coff_debug_merge_element *next;


  const char *name;


  unsigned int type;


  long tagndx;
};



struct coff_debug_merge_type
{

  struct coff_debug_merge_type *next;


  int type_class;


  long indx;


  struct coff_debug_merge_element *elements;
};



struct coff_debug_merge_hash_entry
{
  struct bfd_hash_entry root;


  struct coff_debug_merge_type *types;
};



struct coff_debug_merge_hash_table
{
  struct bfd_hash_table root;
};
struct coff_link_section_info
{

  struct internal_reloc *relocs;


  struct coff_link_hash_entry **rel_hashes;
};



struct coff_final_link_info
{

  struct bfd_link_info *info;

  bfd *output_bfd;

  bfd_boolean failed;



  bfd_boolean global_to_static;

  struct bfd_strtab_hash *strtab;


  struct coff_link_section_info *section_info;

  long last_file_index;

  struct internal_syment last_file;


  long last_bf_index;

  union internal_auxent last_bf;

  struct coff_debug_merge_hash_table debug_merge;

  struct internal_syment *internal_syms;

  asection **sec_ptrs;


  long *sym_indices;

  bfd_byte *outsyms;


  bfd_byte *linenos;

  bfd_byte *contents;

  bfd_byte *external_relocs;

  struct internal_reloc *internal_relocs;
};





struct coff_section_alignment_entry
{

  const char *name;




  unsigned int comparison_length;
  unsigned int default_alignment_min;




  unsigned int default_alignment_max;




  unsigned int alignment_power;
};

extern struct bfd_hash_entry *_bfd_coff_link_hash_newfunc
  (struct bfd_hash_entry *, struct bfd_hash_table *, const char *);
extern bfd_boolean _bfd_coff_link_hash_table_init
  (struct coff_link_hash_table *, bfd *,
   struct bfd_hash_entry *(*) (struct bfd_hash_entry *,
          struct bfd_hash_table *,
          const char *),
   unsigned int);
extern struct bfd_link_hash_table *_bfd_coff_link_hash_table_create
  (bfd *);
extern const char *_bfd_coff_internal_syment_name
  (bfd *, const struct internal_syment *, char *);
extern bfd_boolean _bfd_coff_section_already_linked
  (bfd *, asection *, struct bfd_link_info *);
extern bfd_boolean _bfd_coff_link_add_symbols
  (bfd *, struct bfd_link_info *);
extern bfd_boolean _bfd_coff_final_link
  (bfd *, struct bfd_link_info *);
extern struct internal_reloc *_bfd_coff_read_internal_relocs
  (bfd *, asection *, bfd_boolean, bfd_byte *, bfd_boolean,
   struct internal_reloc *);
extern bfd_boolean _bfd_coff_generic_relocate_section
  (bfd *, struct bfd_link_info *, bfd *, asection *, bfd_byte *,
   struct internal_reloc *, struct internal_syment *, asection **);
extern struct bfd_hash_entry *_bfd_coff_debug_merge_hash_newfunc
  (struct bfd_hash_entry *, struct bfd_hash_table *, const char *);
extern bfd_boolean _bfd_coff_write_global_sym
  (struct bfd_hash_entry *, void *);
extern bfd_boolean _bfd_coff_write_task_globals
  (struct coff_link_hash_entry *, void *);
extern bfd_boolean _bfd_coff_link_input_bfd
  (struct coff_final_link_info *, bfd *);
extern bfd_boolean _bfd_coff_reloc_link_order
  (bfd *, struct coff_final_link_info *, asection *,
   struct bfd_link_order *);







extern long _bfd_xcoff_get_dynamic_symtab_upper_bound
  (bfd *);
extern long _bfd_xcoff_canonicalize_dynamic_symtab
  (bfd *, asymbol **);
extern long _bfd_xcoff_get_dynamic_reloc_upper_bound
  (bfd *);
extern long _bfd_xcoff_canonicalize_dynamic_reloc
  (bfd *, arelent **, asymbol **);
extern struct bfd_link_hash_table *_bfd_xcoff_bfd_link_hash_table_create
  (bfd *);
extern void _bfd_xcoff_bfd_link_hash_table_free
  (struct bfd_link_hash_table *);
extern bfd_boolean _bfd_xcoff_bfd_link_add_symbols
  (bfd *, struct bfd_link_info *);
extern bfd_boolean _bfd_xcoff_bfd_final_link
  (bfd *, struct bfd_link_info *);
extern bfd_boolean _bfd_xcoff_define_common_symbol
  (bfd *, struct bfd_link_info *, struct bfd_link_hash_entry *);
extern bfd_boolean _bfd_ppc_xcoff_relocate_section
  (bfd *, struct bfd_link_info *, bfd *, asection *, bfd_byte *,
   struct internal_reloc *, struct internal_syment *, asection **);




extern bfd_boolean ppc_allocate_toc_section
  (struct bfd_link_info *);
extern bfd_boolean ppc_process_before_allocation
  (bfd *, struct bfd_link_info *);

typedef struct coff_ptr_struct
{


  unsigned int offset;



  unsigned int fix_value : 1;



  unsigned int fix_tag : 1;



  unsigned int fix_end : 1;



  unsigned int fix_scnlen : 1;



  unsigned int fix_line : 1;



  union
  {
    union internal_auxent auxent;
    struct internal_syment syment;
  } u;
} combined_entry_type;




typedef struct coff_symbol_struct
{

  asymbol symbol;


  combined_entry_type *native;


  struct lineno_cache_entry *lineno;


  bfd_boolean done_lineno;
} coff_symbol_type;


enum coff_symbol_classification
{

  COFF_SYMBOL_GLOBAL,

  COFF_SYMBOL_COMMON,

  COFF_SYMBOL_UNDEFINED,

  COFF_SYMBOL_LOCAL,

  COFF_SYMBOL_PE_SECTION
};

typedef struct
{
  void (*_bfd_coff_swap_aux_in)
    (bfd *, void *, int, int, int, int, void *);

  void (*_bfd_coff_swap_sym_in)
    (bfd *, void *, void *);

  void (*_bfd_coff_swap_lineno_in)
    (bfd *, void *, void *);

  unsigned int (*_bfd_coff_swap_aux_out)
    (bfd *, void *, int, int, int, int, void *);

  unsigned int (*_bfd_coff_swap_sym_out)
    (bfd *, void *, void *);

  unsigned int (*_bfd_coff_swap_lineno_out)
    (bfd *, void *, void *);

  unsigned int (*_bfd_coff_swap_reloc_out)
    (bfd *, void *, void *);

  unsigned int (*_bfd_coff_swap_filehdr_out)
    (bfd *, void *, void *);

  unsigned int (*_bfd_coff_swap_aouthdr_out)
    (bfd *, void *, void *);

  unsigned int (*_bfd_coff_swap_scnhdr_out)
    (bfd *, void *, void *);

  unsigned int _bfd_filhsz;
  unsigned int _bfd_aoutsz;
  unsigned int _bfd_scnhsz;
  unsigned int _bfd_symesz;
  unsigned int _bfd_auxesz;
  unsigned int _bfd_relsz;
  unsigned int _bfd_linesz;
  unsigned int _bfd_filnmlen;
  bfd_boolean _bfd_coff_long_filenames;

  bfd_boolean _bfd_coff_long_section_names;
  bfd_boolean (*_bfd_coff_set_long_section_names)
    (bfd *, int);

  unsigned int _bfd_coff_default_section_alignment_power;
  bfd_boolean _bfd_coff_force_symnames_in_strings;
  unsigned int _bfd_coff_debug_string_prefix_length;
  unsigned int _bfd_coff_max_nscns;

  void (*_bfd_coff_swap_filehdr_in)
    (bfd *, void *, void *);

  void (*_bfd_coff_swap_aouthdr_in)
    (bfd *, void *, void *);

  void (*_bfd_coff_swap_scnhdr_in)
    (bfd *, void *, void *);

  void (*_bfd_coff_swap_reloc_in)
    (bfd *abfd, void *, void *);

  bfd_boolean (*_bfd_coff_bad_format_hook)
    (bfd *, void *);

  bfd_boolean (*_bfd_coff_set_arch_mach_hook)
    (bfd *, void *);

  void * (*_bfd_coff_mkobject_hook)
    (bfd *, void *, void *);

  bfd_boolean (*_bfd_styp_to_sec_flags_hook)
    (bfd *, void *, const char *, asection *, flagword *);

  void (*_bfd_set_alignment_hook)
    (bfd *, asection *, void *);

  bfd_boolean (*_bfd_coff_slurp_symbol_table)
    (bfd *);

  bfd_boolean (*_bfd_coff_symname_in_debug)
    (bfd *, struct internal_syment *);

  bfd_boolean (*_bfd_coff_pointerize_aux_hook)
    (bfd *, combined_entry_type *, combined_entry_type *,
            unsigned int, combined_entry_type *);

  bfd_boolean (*_bfd_coff_print_aux)
    (bfd *, FILE *, combined_entry_type *, combined_entry_type *,
            combined_entry_type *, unsigned int);

  void (*_bfd_coff_reloc16_extra_cases)
    (bfd *, struct bfd_link_info *, struct bfd_link_order *, arelent *,
           bfd_byte *, unsigned int *, unsigned int *);

  int (*_bfd_coff_reloc16_estimate)
    (bfd *, asection *, arelent *, unsigned int,
            struct bfd_link_info *);

  enum coff_symbol_classification (*_bfd_coff_classify_symbol)
    (bfd *, struct internal_syment *);

  bfd_boolean (*_bfd_coff_compute_section_file_positions)
    (bfd *);

  bfd_boolean (*_bfd_coff_start_final_link)
    (bfd *, struct bfd_link_info *);

  bfd_boolean (*_bfd_coff_relocate_section)
    (bfd *, struct bfd_link_info *, bfd *, asection *, bfd_byte *,
            struct internal_reloc *, struct internal_syment *, asection **);

  reloc_howto_type *(*_bfd_coff_rtype_to_howto)
    (bfd *, asection *, struct internal_reloc *,
            struct coff_link_hash_entry *, struct internal_syment *,
            bfd_vma *);

  bfd_boolean (*_bfd_coff_adjust_symndx)
    (bfd *, struct bfd_link_info *, bfd *, asection *,
            struct internal_reloc *, bfd_boolean *);

  bfd_boolean (*_bfd_coff_link_add_one_symbol)
    (struct bfd_link_info *, bfd *, const char *, flagword,
            asection *, bfd_vma, const char *, bfd_boolean, bfd_boolean,
            struct bfd_link_hash_entry **);

  bfd_boolean (*_bfd_coff_link_output_has_begun)
    (bfd *, struct coff_final_link_info *);

  bfd_boolean (*_bfd_coff_final_link_postscript)
    (bfd *, struct coff_final_link_info *);

  bfd_boolean (*_bfd_coff_print_pdata)
    (bfd *, void *);

} bfd_coff_backend_data;
typedef struct {
  unsigned char e_ident[16];
  unsigned char e_type[2];
  unsigned char e_machine[2];
  unsigned char e_version[4];
  unsigned char e_entry[4];
  unsigned char e_phoff[4];
  unsigned char e_shoff[4];
  unsigned char e_flags[4];
  unsigned char e_ehsize[2];
  unsigned char e_phentsize[2];
  unsigned char e_phnum[2];
  unsigned char e_shentsize[2];
  unsigned char e_shnum[2];
  unsigned char e_shstrndx[2];
} Elf32_External_Ehdr;

typedef struct {
  unsigned char e_ident[16];
  unsigned char e_type[2];
  unsigned char e_machine[2];
  unsigned char e_version[4];
  unsigned char e_entry[8];
  unsigned char e_phoff[8];
  unsigned char e_shoff[8];
  unsigned char e_flags[4];
  unsigned char e_ehsize[2];
  unsigned char e_phentsize[2];
  unsigned char e_phnum[2];
  unsigned char e_shentsize[2];
  unsigned char e_shnum[2];
  unsigned char e_shstrndx[2];
} Elf64_External_Ehdr;



typedef struct {
  unsigned char p_type[4];
  unsigned char p_offset[4];
  unsigned char p_vaddr[4];
  unsigned char p_paddr[4];
  unsigned char p_filesz[4];
  unsigned char p_memsz[4];
  unsigned char p_flags[4];
  unsigned char p_align[4];
} Elf32_External_Phdr;

typedef struct {
  unsigned char p_type[4];
  unsigned char p_flags[4];
  unsigned char p_offset[8];
  unsigned char p_vaddr[8];
  unsigned char p_paddr[8];
  unsigned char p_filesz[8];
  unsigned char p_memsz[8];
  unsigned char p_align[8];
} Elf64_External_Phdr;



typedef struct {
  unsigned char sh_name[4];
  unsigned char sh_type[4];
  unsigned char sh_flags[4];
  unsigned char sh_addr[4];
  unsigned char sh_offset[4];
  unsigned char sh_size[4];
  unsigned char sh_link[4];
  unsigned char sh_info[4];
  unsigned char sh_addralign[4];
  unsigned char sh_entsize[4];
} Elf32_External_Shdr;

typedef struct {
  unsigned char sh_name[4];
  unsigned char sh_type[4];
  unsigned char sh_flags[8];
  unsigned char sh_addr[8];
  unsigned char sh_offset[8];
  unsigned char sh_size[8];
  unsigned char sh_link[4];
  unsigned char sh_info[4];
  unsigned char sh_addralign[8];
  unsigned char sh_entsize[8];
} Elf64_External_Shdr;



typedef struct {
  unsigned char st_name[4];
  unsigned char st_value[4];
  unsigned char st_size[4];
  unsigned char st_info[1];
  unsigned char st_other[1];
  unsigned char st_shndx[2];
} Elf32_External_Sym;

typedef struct {
  unsigned char st_name[4];
  unsigned char st_info[1];
  unsigned char st_other[1];
  unsigned char st_shndx[2];
  unsigned char st_value[8];
  unsigned char st_size[8];
} Elf64_External_Sym;

typedef struct {
  unsigned char est_shndx[4];
} Elf_External_Sym_Shndx;



typedef struct {
  unsigned char namesz[4];
  unsigned char descsz[4];
  unsigned char type[4];
  char name[1];
} Elf_External_Note;


typedef struct {
  unsigned char r_offset[4];
  unsigned char r_info[4];
} Elf32_External_Rel;

typedef struct {
  unsigned char r_offset[4];
  unsigned char r_info[4];
  unsigned char r_addend[4];
} Elf32_External_Rela;

typedef struct {
  unsigned char r_offset[8];
  unsigned char r_info[8];
} Elf64_External_Rel;

typedef struct {
  unsigned char r_offset[8];
  unsigned char r_info[8];
  unsigned char r_addend[8];
} Elf64_External_Rela;



typedef struct {
  unsigned char d_tag[4];
  union {
    unsigned char d_val[4];
    unsigned char d_ptr[4];
  } d_un;
} Elf32_External_Dyn;

typedef struct {
  unsigned char d_tag[8];
  union {
    unsigned char d_val[8];
    unsigned char d_ptr[8];
  } d_un;
} Elf64_External_Dyn;







typedef struct {
  unsigned char vd_version[2];
  unsigned char vd_flags[2];
  unsigned char vd_ndx[2];
  unsigned char vd_cnt[2];
  unsigned char vd_hash[4];
  unsigned char vd_aux[4];
  unsigned char vd_next[4];
} Elf_External_Verdef;



typedef struct {
  unsigned char vda_name[4];
  unsigned char vda_next[4];
} Elf_External_Verdaux;



typedef struct {
  unsigned char vn_version[2];
  unsigned char vn_cnt[2];
  unsigned char vn_file[4];
  unsigned char vn_aux[4];
  unsigned char vn_next[4];
} Elf_External_Verneed;



typedef struct {
  unsigned char vna_hash[4];
  unsigned char vna_flags[2];
  unsigned char vna_other[2];
  unsigned char vna_name[4];
  unsigned char vna_next[4];
} Elf_External_Vernaux;




typedef struct {
  unsigned char vs_vers[2];
} __attribute__ ((packed)) Elf_External_Versym;


typedef struct
{
  unsigned char si_boundto[2];
  unsigned char si_flags[2];
} Elf_External_Syminfo;



typedef struct
{
  unsigned char a_type[4];
  unsigned char a_val[4];
} Elf32_External_Auxv;

typedef struct
{
  unsigned char a_type[8];
  unsigned char a_val[8];
} Elf64_External_Auxv;
typedef struct elf_internal_ehdr {
  unsigned char e_ident[16];
  bfd_vma e_entry;
  bfd_size_type e_phoff;
  bfd_size_type e_shoff;
  unsigned long e_version;
  unsigned long e_flags;
  unsigned short e_type;
  unsigned short e_machine;
  unsigned int e_ehsize;
  unsigned int e_phentsize;
  unsigned int e_phnum;
  unsigned int e_shentsize;
  unsigned int e_shnum;
  unsigned int e_shstrndx;
} Elf_Internal_Ehdr;



struct elf_internal_phdr {
  unsigned long p_type;
  unsigned long p_flags;
  bfd_vma p_offset;
  bfd_vma p_vaddr;
  bfd_vma p_paddr;
  bfd_vma p_filesz;
  bfd_vma p_memsz;
  bfd_vma p_align;
};

typedef struct elf_internal_phdr Elf_Internal_Phdr;



typedef struct elf_internal_shdr {
  unsigned int sh_name;
  unsigned int sh_type;
  bfd_vma sh_flags;
  bfd_vma sh_addr;
  file_ptr sh_offset;
  bfd_size_type sh_size;
  unsigned int sh_link;
  unsigned int sh_info;
  bfd_vma sh_addralign;
  bfd_size_type sh_entsize;


  asection * bfd_section;
  unsigned char *contents;
} Elf_Internal_Shdr;



struct elf_internal_sym {
  bfd_vma st_value;
  bfd_vma st_size;
  unsigned long st_name;
  unsigned char st_info;
  unsigned char st_other;
  unsigned char st_target_internal;
  unsigned int st_shndx;
};

typedef struct elf_internal_sym Elf_Internal_Sym;



typedef struct elf_internal_note {
  unsigned long namesz;
  unsigned long descsz;
  unsigned long type;
  char * namedata;
  char * descdata;
  bfd_vma descpos;
} Elf_Internal_Note;



typedef struct elf_internal_rela {
  bfd_vma r_offset;
  bfd_vma r_info;
  bfd_vma r_addend;
} Elf_Internal_Rela;



typedef struct elf_internal_dyn {

  bfd_vma d_tag;
  union {

    bfd_vma d_val;
    bfd_vma d_ptr;
  } d_un;
} Elf_Internal_Dyn;



typedef struct elf_internal_verdef {
  unsigned short vd_version;
  unsigned short vd_flags;
  unsigned short vd_ndx;
  unsigned short vd_cnt;
  unsigned long vd_hash;
  unsigned long vd_aux;
  unsigned long vd_next;



  bfd *vd_bfd;
  const char *vd_nodename;
  struct elf_internal_verdef *vd_nextdef;
  struct elf_internal_verdaux *vd_auxptr;
  unsigned int vd_exp_refno;
} Elf_Internal_Verdef;



typedef struct elf_internal_verdaux {
  unsigned long vda_name;
  unsigned long vda_next;



  const char *vda_nodename;
  struct elf_internal_verdaux *vda_nextptr;
} Elf_Internal_Verdaux;



typedef struct elf_internal_verneed {
  unsigned short vn_version;
  unsigned short vn_cnt;
  unsigned long vn_file;
  unsigned long vn_aux;
  unsigned long vn_next;



  bfd *vn_bfd;
  const char *vn_filename;
  struct elf_internal_vernaux *vn_auxptr;
  struct elf_internal_verneed *vn_nextref;
} Elf_Internal_Verneed;



typedef struct elf_internal_vernaux {
  unsigned long vna_hash;
  unsigned short vna_flags;
  unsigned short vna_other;
  unsigned long vna_name;
  unsigned long vna_next;



  const char *vna_nodename;
  struct elf_internal_vernaux *vna_nextptr;
} Elf_Internal_Vernaux;




typedef struct elf_internal_versym {
  unsigned short vs_vers;
} Elf_Internal_Versym;


typedef struct
{
  unsigned short int si_boundto;
  unsigned short int si_flags;
} Elf_Internal_Syminfo;


typedef struct
{
  bfd_vma a_type;
  bfd_vma a_val;
} Elf_Internal_Auxv;





struct elf_segment_map
{

  struct elf_segment_map *next;

  unsigned long p_type;

  unsigned long p_flags;

  bfd_vma p_paddr;

  bfd_vma p_vaddr_offset;

  bfd_vma p_align;

  bfd_vma p_size;

  bfd_vma header_size;


  unsigned int p_flags_valid : 1;


  unsigned int p_paddr_valid : 1;


  unsigned int p_align_valid : 1;


  unsigned int p_size_valid : 1;

  unsigned int includes_filehdr : 1;

  unsigned int includes_phdrs : 1;

  unsigned int count;

  asection *sections[1];
};
typedef struct
{

  asymbol symbol;

  Elf_Internal_Sym internal_elf_sym;

  union
    {
      unsigned int hppa_arg_reloc;
      void *mips_extr;
      void *any;
    }
  tc_data;




  unsigned short version;

} elf_symbol_type;

struct elf_strtab_hash;
struct got_entry;
struct plt_entry;

union gotplt_union
  {
    bfd_signed_vma refcount;
    bfd_vma offset;
    struct got_entry *glist;
    struct plt_entry *plist;
  };

struct elf_link_virtual_table_entry
  {




    size_t size;
    bfd_boolean *used;


    struct elf_link_hash_entry *parent;
  };



struct elf_link_hash_entry
{
  struct bfd_link_hash_entry root;



  long indx;
  long dynindx;
  union gotplt_union got;


  union gotplt_union plt;


  bfd_size_type size;


  unsigned int type : 8;


  unsigned int other : 8;


  unsigned int target_internal : 8;



  unsigned int ref_regular : 1;

  unsigned int def_regular : 1;

  unsigned int ref_dynamic : 1;

  unsigned int def_dynamic : 1;


  unsigned int ref_regular_nonweak : 1;

  unsigned int dynamic_adjusted : 1;

  unsigned int needs_copy : 1;

  unsigned int needs_plt : 1;

  unsigned int non_elf : 1;

  unsigned int hidden : 1;

  unsigned int forced_local : 1;

  unsigned int dynamic : 1;

  unsigned int mark : 1;


  unsigned int non_got_ref : 1;



  unsigned int dynamic_def : 1;

  unsigned int ref_dynamic_nonweak : 1;


  unsigned int pointer_equality_needed : 1;

  unsigned int unique_global : 1;


  unsigned long dynstr_index;

  union
  {



    struct elf_link_hash_entry *weakdef;




    unsigned long elf_hash_value;
  } u;


  union
  {



    Elf_Internal_Verdef *verdef;



    struct bfd_elf_version_tree *vertree;
  } verinfo;

  struct elf_link_virtual_table_entry *vtable;
};
struct elf_link_local_dynamic_entry
{
  struct elf_link_local_dynamic_entry *next;


  bfd *input_bfd;


  long input_indx;


  long dynindx;


  Elf_Internal_Sym isym;
};

struct elf_link_loaded_list
{
  struct elf_link_loaded_list *next;
  bfd *abfd;
};


struct eh_cie_fde
{
  union {
    struct {






      struct eh_cie_fde *cie_inf;
      struct eh_cie_fde *next_for_section;
    } fde;
    struct {
      union {
 struct cie *full_cie;
  struct eh_cie_fde *merged_with;
  asection *sec;
      } u;



      unsigned int personality_offset : 8;


      unsigned int gc_mark : 1;



      unsigned int make_lsda_relative : 1;



      unsigned int make_per_encoding_relative : 1;




      unsigned int per_encoding_relative : 1;



      unsigned int add_fde_encoding : 1;


      unsigned int merged : 1;


      unsigned int pad1 : 18;
    } cie;
  } u;
  unsigned int reloc_index;
  unsigned int size;
  unsigned int offset;
  unsigned int new_offset;
  unsigned int fde_encoding : 8;
  unsigned int lsda_encoding : 8;
  unsigned int lsda_offset : 8;


  unsigned int cie : 1;


  unsigned int removed : 1;



  unsigned int add_augmentation_size : 1;




  unsigned int make_relative : 1;


  unsigned int pad1 : 4;

  unsigned int *set_loc;
};

struct eh_frame_sec_info
{
  unsigned int count;
  struct cie *cies;
  struct eh_cie_fde entry[1];
};

struct eh_frame_array_ent
{
  bfd_vma initial_loc;
  bfd_vma fde;
};

struct htab;

struct eh_frame_hdr_info
{
  struct htab *cies;
  asection *hdr_sec;
  unsigned int fde_count, array_count;
  struct eh_frame_array_ent *array;

  bfd_boolean merge_cies;

  bfd_boolean parsed_eh_frames;



  bfd_boolean table;
};






enum elf_target_id
{
  AARCH64_ELF_DATA = 1,
  ALPHA_ELF_DATA,
  ARM_ELF_DATA,
  AVR_ELF_DATA,
  BFIN_ELF_DATA,
  CRIS_ELF_DATA,
  FRV_ELF_DATA,
  HPPA32_ELF_DATA,
  HPPA64_ELF_DATA,
  I386_ELF_DATA,
  IA64_ELF_DATA,
  LM32_ELF_DATA,
  M32R_ELF_DATA,
  M68HC11_ELF_DATA,
  M68K_ELF_DATA,
  METAG_ELF_DATA,
  MICROBLAZE_ELF_DATA,
  MIPS_ELF_DATA,
  MN10300_ELF_DATA,
  NDS32_ELF_DATA,
  NIOS2_ELF_DATA,
  OR1K_ELF_DATA,
  PPC32_ELF_DATA,
  PPC64_ELF_DATA,
  S390_ELF_DATA,
  SH_ELF_DATA,
  SPARC_ELF_DATA,
  SPU_ELF_DATA,
  TIC6X_ELF_DATA,
  X86_64_ELF_DATA,
  XTENSA_ELF_DATA,
  XGATE_ELF_DATA,
  TILEGX_ELF_DATA,
  TILEPRO_ELF_DATA,
  GENERIC_ELF_DATA
};



struct elf_link_hash_table
{
  struct bfd_link_hash_table root;



  enum elf_target_id hash_table_id;



  bfd_boolean dynamic_sections_created;



  bfd_boolean is_relocatable_executable;




  bfd *dynobj;





  union gotplt_union init_got_refcount;
  union gotplt_union init_plt_refcount;



  union gotplt_union init_got_offset;
  union gotplt_union init_plt_offset;



  bfd_size_type dynsymcount;



  struct elf_strtab_hash *dynstr;



  bfd_size_type bucketcount;



  struct bfd_link_needed_list *needed;




  asection *text_index_section;
  asection *data_index_section;


  struct elf_link_hash_entry *hgot;


  struct elf_link_hash_entry *hplt;


  struct elf_link_hash_entry *hdynamic;


  void *merge_info;


  struct stab_info stab_info;


  struct eh_frame_hdr_info eh_info;


  struct elf_link_local_dynamic_entry *dynlocal;



  struct bfd_link_needed_list *runpath;


  asection *tls_sec;
  bfd_size_type tls_size;


  struct elf_link_loaded_list *loaded;


  asection *sgot;
  asection *sgotplt;
  asection *srelgot;
  asection *splt;
  asection *srelplt;
  asection *igotplt;
  asection *iplt;
  asection *irelplt;
  asection *irelifunc;
};
struct sym_cache
{
  bfd *abfd;
  unsigned long indx[32];
  Elf_Internal_Sym sym[32];
};



struct elf_size_info {
  unsigned char sizeof_ehdr, sizeof_phdr, sizeof_shdr;
  unsigned char sizeof_rel, sizeof_rela, sizeof_sym, sizeof_dyn, sizeof_note;


  unsigned char sizeof_hash_entry;



  unsigned char int_rels_per_ext_rel;




  unsigned char arch_size, log_file_align;
  unsigned char elfclass, ev_current;
  int (*write_out_phdrs)
    (bfd *, const Elf_Internal_Phdr *, unsigned int);
  bfd_boolean
    (*write_shdrs_and_ehdr) (bfd *);
  bfd_boolean (*checksum_contents)
    (bfd * , void (*) (const void *, size_t, void *), void *);
  void (*write_relocs)
    (bfd *, asection *, void *);
  bfd_boolean (*swap_symbol_in)
    (bfd *, const void *, const void *, Elf_Internal_Sym *);
  void (*swap_symbol_out)
    (bfd *, const Elf_Internal_Sym *, void *, void *);
  bfd_boolean (*slurp_reloc_table)
    (bfd *, asection *, asymbol **, bfd_boolean);
  long (*slurp_symbol_table)
    (bfd *, asymbol **, bfd_boolean);
  void (*swap_dyn_in)
    (bfd *, const void *, Elf_Internal_Dyn *);
  void (*swap_dyn_out)
    (bfd *, const Elf_Internal_Dyn *, void *);




  void (*swap_reloc_in)
    (bfd *, const bfd_byte *, Elf_Internal_Rela *);


  void (*swap_reloc_out)
    (bfd *, const Elf_Internal_Rela *, bfd_byte *);




  void (*swap_reloca_in)
    (bfd *, const bfd_byte *, Elf_Internal_Rela *);


  void (*swap_reloca_out)
    (bfd *, const Elf_Internal_Rela *, bfd_byte *);
};







enum elf_reloc_type_class {
  reloc_class_normal,
  reloc_class_relative,
  reloc_class_plt,
  reloc_class_copy,
  reloc_class_ifunc
};

struct elf_reloc_cookie
{
  Elf_Internal_Rela *rels, *rel, *relend;
  Elf_Internal_Sym *locsyms;
  bfd *abfd;
  size_t locsymcount;
  size_t extsymoff;
  struct elf_link_hash_entry **sym_hashes;
  int r_sym_shift;
  bfd_boolean bad_symtab;
};



typedef enum {
  ict_none,
  ict_irix5,
  ict_irix6
} irix_compat_t;


struct bfd_elf_special_section
{
  const char *prefix;
  int prefix_length;






  int suffix_length;
  int type;
  bfd_vma attr;
};

enum action_discarded
  {
    COMPLAIN = 1,
    PRETEND = 2
  };

typedef asection * (*elf_gc_mark_hook_fn)
  (asection *, struct bfd_link_info *, Elf_Internal_Rela *,
   struct elf_link_hash_entry *, Elf_Internal_Sym *);

struct elf_backend_data
{

  enum bfd_architecture arch;



  enum elf_target_id target_id;


  int elf_machine_code;


  int elf_osabi;


  bfd_vma maxpagesize;




  bfd_vma minpagesize;


  bfd_vma commonpagesize;


  flagword dynamic_sec_flags;



  const void *arch_data;



  void (*elf_info_to_howto)
    (bfd *, arelent *, Elf_Internal_Rela *);



  void (*elf_info_to_howto_rel)
    (bfd *, arelent *, Elf_Internal_Rela *);






  bfd_boolean (*elf_backend_sym_is_global)
    (bfd *, asymbol *);
  bfd_boolean (*elf_backend_object_p)
    (bfd *);




  void (*elf_backend_symbol_processing)
    (bfd *, asymbol *);



  bfd_boolean (*elf_backend_symbol_table_processing)
    (bfd *, elf_symbol_type *, unsigned int);



  int (*elf_backend_get_symbol_type)
    (Elf_Internal_Sym *, int);



  struct elf_link_hash_entry * (*elf_backend_archive_symbol_lookup)
    (bfd *, struct bfd_link_info *, const char *);



  bfd_boolean (*elf_backend_name_local_section_symbols)
    (bfd *);





  bfd_boolean (*elf_backend_section_processing)
    (bfd *, Elf_Internal_Shdr *);



  bfd_boolean (*elf_backend_section_from_shdr)
    (bfd *, Elf_Internal_Shdr *, const char *, int);



  bfd_boolean (*elf_backend_section_flags)
    (flagword *, const Elf_Internal_Shdr *);



  const struct bfd_elf_special_section * (*get_sec_type_attr)
    (bfd *, asection *);



  bfd_boolean (*elf_backend_section_from_phdr)
    (bfd *, Elf_Internal_Phdr *, int, const char *);




  bfd_boolean (*elf_backend_fake_sections)
    (bfd *, Elf_Internal_Shdr *, asection *);





  bfd_boolean (*elf_backend_section_from_bfd_section)
    (bfd *, asection *, int *retval);
  bfd_boolean (*elf_add_symbol_hook)
    (bfd *abfd, struct bfd_link_info *info, Elf_Internal_Sym *,
     const char **name, flagword *flags, asection **sec, bfd_vma *value);





  int (*elf_backend_link_output_symbol_hook)
    (struct bfd_link_info *info, const char *, Elf_Internal_Sym *,
     asection *, struct elf_link_hash_entry *);
  bfd_boolean (*elf_backend_create_dynamic_sections)
    (bfd *abfd, struct bfd_link_info *info);



  bfd_boolean (*elf_backend_omit_section_dynsym)
    (bfd *output_bfd, struct bfd_link_info *info, asection *osec);



  bfd_boolean (*relocs_compatible) (const bfd_target *, const bfd_target *);
  bfd_boolean (*check_relocs)
    (bfd *abfd, struct bfd_link_info *info, asection *o,
     const Elf_Internal_Rela *relocs);





  bfd_boolean (*check_directives)
    (bfd *abfd, struct bfd_link_info *info);





  bfd_boolean (*notice_as_needed)
    (bfd *abfd, struct bfd_link_info *info, enum notice_asneeded_action act);
  bfd_boolean (*elf_backend_adjust_dynamic_symbol)
    (struct bfd_link_info *info, struct elf_link_hash_entry *h);





  bfd_boolean (*elf_backend_always_size_sections)
    (bfd *output_bfd, struct bfd_link_info *info);
  bfd_boolean (*elf_backend_size_dynamic_sections)
    (bfd *output_bfd, struct bfd_link_info *info);



  void (*elf_backend_init_index_section)
    (bfd *output_bfd, struct bfd_link_info *info);
  int (*elf_backend_relocate_section)
    (bfd *output_bfd, struct bfd_link_info *info, bfd *input_bfd,
     asection *input_section, bfd_byte *contents, Elf_Internal_Rela *relocs,
     Elf_Internal_Sym *local_syms, asection **local_sections);
  bfd_boolean (*elf_backend_finish_dynamic_symbol)
    (bfd *output_bfd, struct bfd_link_info *info,
     struct elf_link_hash_entry *h, Elf_Internal_Sym *sym);





  bfd_boolean (*elf_backend_finish_dynamic_sections)
    (bfd *output_bfd, struct bfd_link_info *info);



  void (*elf_backend_begin_write_processing)
    (bfd *, struct bfd_link_info *);




  void (*elf_backend_final_write_processing)
    (bfd *, bfd_boolean linker);




  int (*elf_backend_additional_program_headers)
    (bfd *, struct bfd_link_info *);



  bfd_boolean (*elf_backend_modify_segment_map)
    (bfd *, struct bfd_link_info *);



  bfd_boolean (*elf_backend_modify_program_headers)
    (bfd *, struct bfd_link_info *);



  void (*gc_keep)
    (struct bfd_link_info *);



  bfd_boolean (*gc_mark_dynamic_ref)
    (struct elf_link_hash_entry *, void *);



  elf_gc_mark_hook_fn gc_mark_hook;



  bfd_boolean (*gc_mark_extra_sections)
    (struct bfd_link_info *, elf_gc_mark_hook_fn);




  bfd_boolean (*gc_sweep_hook)
    (bfd *, struct bfd_link_info *, asection *, const Elf_Internal_Rela *);




  void (*elf_backend_post_process_headers)
    (bfd *, struct bfd_link_info *);




  const char *(*elf_backend_print_symbol_all)
    (bfd *, void *, asymbol *);





  bfd_boolean (*elf_backend_output_arch_local_syms)
    (bfd *, struct bfd_link_info *, void *,
     bfd_boolean (*) (void *, const char *, Elf_Internal_Sym *, asection *,
        struct elf_link_hash_entry *));




  bfd_boolean (*elf_backend_output_arch_syms)
    (bfd *, struct bfd_link_info *, void *,
     bfd_boolean (*) (void *, const char *, Elf_Internal_Sym *, asection *,
        struct elf_link_hash_entry *));






  void (*elf_backend_copy_indirect_symbol)
    (struct bfd_link_info *, struct elf_link_hash_entry *,
     struct elf_link_hash_entry *);



  void (*elf_backend_hide_symbol)
    (struct bfd_link_info *, struct elf_link_hash_entry *, bfd_boolean);



  bfd_boolean (*elf_backend_fixup_symbol)
    (struct bfd_link_info *, struct elf_link_hash_entry *);


  void (*elf_backend_merge_symbol_attribute)
    (struct elf_link_hash_entry *, const Elf_Internal_Sym *, bfd_boolean,
     bfd_boolean);



  char *(*elf_backend_get_target_dtag)
    (bfd_vma);



  bfd_boolean (*elf_backend_ignore_undef_symbol)
    (struct elf_link_hash_entry *);



  bfd_boolean (*elf_backend_emit_relocs)
    (bfd *, asection *, Elf_Internal_Shdr *, Elf_Internal_Rela *,
     struct elf_link_hash_entry **);



  unsigned int (*elf_backend_count_relocs)
    (struct bfd_link_info *, asection *);



  bfd_boolean (*elf_backend_grok_prstatus)
    (bfd *, Elf_Internal_Note *);



  bfd_boolean (*elf_backend_grok_psinfo)
    (bfd *, Elf_Internal_Note *);


  char *(*elf_backend_write_core_note)
    (bfd *abfd, char *buf, int *bufsiz, int note_type, ...);



  flagword (*elf_backend_lookup_section_flags_hook)
    (char *);


  enum elf_reloc_type_class (*elf_backend_reloc_type_class)
  (const struct bfd_link_info *, const asection *, const Elf_Internal_Rela *);



  bfd_boolean (*elf_backend_discard_info)
    (bfd *, struct elf_reloc_cookie *, struct bfd_link_info *);



  bfd_boolean (*elf_backend_ignore_discarded_relocs)
    (asection *);



  unsigned int (*action_discarded)
    (asection *);




  unsigned int (*elf_backend_eh_frame_address_size)
    (bfd *, asection *);




  bfd_boolean (*elf_backend_can_make_relative_eh_frame)
     (bfd *, struct bfd_link_info *, asection *);
  bfd_boolean (*elf_backend_can_make_lsda_relative_eh_frame)
     (bfd *, struct bfd_link_info *, asection *);





  bfd_byte (*elf_backend_encode_eh_address)
     (bfd *abfd, struct bfd_link_info *info,
      asection *osec, bfd_vma offset,
      asection *loc_sec, bfd_vma loc_offset,
      bfd_vma *encoded);



  bfd_boolean (*elf_backend_write_section)
    (bfd *, struct bfd_link_info *, asection *, bfd_byte *);



  irix_compat_t (*elf_backend_mips_irix_compat)
    (bfd *);

  reloc_howto_type *(*elf_backend_mips_rtype_to_howto)
    (unsigned int, bfd_boolean);



  const struct ecoff_debug_swap *elf_backend_ecoff_debug_swap;



  bfd *(*elf_backend_bfd_from_remote_memory)
    (bfd *templ, bfd_vma ehdr_vma, bfd_size_type size, bfd_vma *loadbasep,
     int (*target_read_memory) (bfd_vma vma, bfd_byte *myaddr,
    bfd_size_type len));



  bfd_vma (*plt_sym_val) (bfd_vma, const asection *, const arelent *);


  bfd_boolean (*common_definition) (Elf_Internal_Sym *);


  unsigned int (*common_section_index) (asection *);


  asection *(*common_section) (asection *);


  bfd_boolean (*merge_symbol) (struct elf_link_hash_entry *,
          const Elf_Internal_Sym *, asection **,
          bfd_boolean, bfd_boolean,
          bfd *, const asection *);


  bfd_boolean (*elf_hash_symbol) (struct elf_link_hash_entry *);


  bfd_boolean (*is_function_type) (unsigned int type);




  bfd_size_type (*maybe_function_sym) (const asymbol *sym, asection *sec,
           bfd_vma *code_off);


  bfd_error_handler_type link_order_error_handler;


  const char *relplt_name;


  int elf_machine_alt1;
  int elf_machine_alt2;

  const struct elf_size_info *s;


  const struct bfd_elf_special_section *special_sections;



  bfd_vma got_header_size;



  bfd_vma (*got_elt_size) (bfd *, struct bfd_link_info *,
      struct elf_link_hash_entry *h,
      bfd *ibfd, unsigned long symndx);


  const char *obj_attrs_vendor;


  const char *obj_attrs_section;



  int (*obj_attrs_arg_type) (int);


  unsigned int obj_attrs_section_type;






  int (*obj_attrs_order) (int);



  bfd_boolean (*obj_attrs_handle_unknown) (bfd *, int);


  unsigned static_tls_alignment;


  unsigned stack_align;





  unsigned collect : 1;





  unsigned type_change_ok : 1;




  unsigned may_use_rel_p : 1;




  unsigned may_use_rela_p : 1;






  unsigned default_use_rela_p : 1;


  unsigned rela_plts_and_copies_p : 1;




  unsigned rela_normal : 1;



  unsigned sign_extend_vma : 1;

  unsigned want_got_plt : 1;
  unsigned plt_readonly : 1;
  unsigned want_plt_sym : 1;
  unsigned plt_not_loaded : 1;
  unsigned plt_alignment : 4;
  unsigned can_gc_sections : 1;
  unsigned can_refcount : 1;
  unsigned want_got_sym : 1;
  unsigned want_dynbss : 1;




  unsigned want_p_paddr_set_to_zero : 1;





  unsigned default_execstack : 1;




  unsigned caches_rawsize : 1;
};



struct bfd_elf_section_reloc_data
{


  Elf_Internal_Shdr *hdr;

  unsigned int count;


  int idx;


  struct elf_link_hash_entry **hashes;
};




struct bfd_elf_section_data
{

  Elf_Internal_Shdr this_hdr;


  struct flag_info *section_flag_info;



  struct bfd_elf_section_reloc_data rel, rela;


  int this_idx;





  int dynindx;


  asection *linked_to;




  Elf_Internal_Rela *relocs;



  void *local_dynrel;


  asection *sreloc;

  union {

    const char *name;


    struct bfd_symbol *id;
  } group;



  asection *sec_group;



  asection *next_in_group;



  struct eh_cie_fde *fde_list;


  void *sec_info;
};
typedef struct obj_attribute
{
  int type;
  unsigned int i;
  char *s;
} obj_attribute;

typedef struct obj_attribute_list
{
  struct obj_attribute_list *next;
  int tag;
  obj_attribute attr;
} obj_attribute_list;
enum
{
  Tag_NULL = 0,
  Tag_File = 1,
  Tag_Section = 2,
  Tag_Symbol = 3,
  Tag_compatibility = 32
};



struct sdt_note
{
  struct sdt_note *next;
  bfd_size_type size;
  bfd_byte data[1];
};


struct elf_build_id
{
  size_t size;
  bfd_byte data[1];
};


struct core_elf_obj_tdata
{
  int signal;
  int pid;
  int lwpid;
  char* program;
  char* command;
};


struct output_elf_obj_tdata
{
  struct elf_segment_map *seg_map;
  struct elf_strtab_hash *strtab_ptr;


  asymbol **section_syms;



  asection *eh_frame_hdr;


  struct
  {
    bfd_boolean (*after_write_object_contents) (bfd *);
    const char *style;
    asection *sec;
  } build_id;


  bfd_size_type program_header_size;


  file_ptr next_file_pos;

  int num_section_syms;
  unsigned int shstrtab_section, strtab_section;


  unsigned int stack_flags;



  bfd_boolean linker;


  bfd_boolean flags_init;
};




struct elf_obj_tdata
{
  Elf_Internal_Ehdr elf_header[1];
  Elf_Internal_Shdr **elf_sect_ptr;
  Elf_Internal_Phdr *phdr;
  Elf_Internal_Shdr symtab_hdr;
  Elf_Internal_Shdr shstrtab_hdr;
  Elf_Internal_Shdr strtab_hdr;
  Elf_Internal_Shdr dynsymtab_hdr;
  Elf_Internal_Shdr dynstrtab_hdr;
  Elf_Internal_Shdr dynversym_hdr;
  Elf_Internal_Shdr dynverref_hdr;
  Elf_Internal_Shdr dynverdef_hdr;
  Elf_Internal_Shdr symtab_shndx_hdr;
  bfd_vma gp;
  unsigned int gp_size;
  unsigned int num_elf_sections;




  struct elf_link_hash_entry **sym_hashes;




  union
    {
      bfd_signed_vma *refcounts;
      bfd_vma *offsets;
      struct got_entry **ents;
    } local_got;
  const char *dt_name;



  const char *dt_audit;


  void *line_info;


  struct dwarf1_debug *dwarf1_find_line_info;


  void *dwarf2_find_line_info;


  void *elf_find_function_cache;


  unsigned int cverdefs;


  unsigned int cverrefs;


  Elf_Internal_Verdef *verdef;


  Elf_Internal_Verneed *verref;


  asection *eh_frame_section;


  void *symbuf;

  obj_attribute known_obj_attributes[2][71];
  obj_attribute_list *other_obj_attributes[2];


  struct elf_build_id *build_id;




  struct sdt_note *sdt_note_head;

  Elf_Internal_Shdr **group_sect_ptr;
  int num_group;

  unsigned int symtab_section, symtab_shndx_section, dynsymtab_section;
  unsigned int dynversym_section, dynverdef_section, dynverref_section;



  enum elf_target_id object_id;




  enum dynamic_lib_link_class dyn_lib_class;






  bfd_boolean bad_symtab;




  bfd_boolean has_gnu_symbols;


  struct core_elf_obj_tdata *core;


  struct output_elf_obj_tdata *o;
};
extern void _bfd_elf_swap_verdef_in
  (bfd *, const Elf_External_Verdef *, Elf_Internal_Verdef *);
extern void _bfd_elf_swap_verdef_out
  (bfd *, const Elf_Internal_Verdef *, Elf_External_Verdef *);
extern void _bfd_elf_swap_verdaux_in
  (bfd *, const Elf_External_Verdaux *, Elf_Internal_Verdaux *);
extern void _bfd_elf_swap_verdaux_out
  (bfd *, const Elf_Internal_Verdaux *, Elf_External_Verdaux *);
extern void _bfd_elf_swap_verneed_in
  (bfd *, const Elf_External_Verneed *, Elf_Internal_Verneed *);
extern void _bfd_elf_swap_verneed_out
  (bfd *, const Elf_Internal_Verneed *, Elf_External_Verneed *);
extern void _bfd_elf_swap_vernaux_in
  (bfd *, const Elf_External_Vernaux *, Elf_Internal_Vernaux *);
extern void _bfd_elf_swap_vernaux_out
  (bfd *, const Elf_Internal_Vernaux *, Elf_External_Vernaux *);
extern void _bfd_elf_swap_versym_in
  (bfd *, const Elf_External_Versym *, Elf_Internal_Versym *);
extern void _bfd_elf_swap_versym_out
  (bfd *, const Elf_Internal_Versym *, Elf_External_Versym *);

extern unsigned int _bfd_elf_section_from_bfd_section
  (bfd *, asection *);
extern char *bfd_elf_string_from_elf_section
  (bfd *, unsigned, unsigned);
extern Elf_Internal_Sym *bfd_elf_get_elf_syms
  (bfd *, Elf_Internal_Shdr *, size_t, size_t, Elf_Internal_Sym *, void *,
   Elf_External_Sym_Shndx *);
extern const char *bfd_elf_sym_name
  (bfd *, Elf_Internal_Shdr *, Elf_Internal_Sym *, asection *);

extern bfd_boolean _bfd_elf_copy_private_bfd_data
  (bfd *, bfd *);
extern bfd_boolean _bfd_elf_print_private_bfd_data
  (bfd *, void *);
extern void bfd_elf_print_symbol
  (bfd *, void *, asymbol *, bfd_print_symbol_type);

extern unsigned int _bfd_elf_eh_frame_address_size
  (bfd *, asection *);
extern bfd_byte _bfd_elf_encode_eh_address
  (bfd *abfd, struct bfd_link_info *info, asection *osec, bfd_vma offset,
   asection *loc_sec, bfd_vma loc_offset, bfd_vma *encoded);
extern bfd_boolean _bfd_elf_can_make_relative
  (bfd *input_bfd, struct bfd_link_info *info, asection *eh_frame_section);

extern enum elf_reloc_type_class _bfd_elf_reloc_type_class
  (const struct bfd_link_info *, const asection *,
   const Elf_Internal_Rela *);
extern bfd_vma _bfd_elf_rela_local_sym
  (bfd *, Elf_Internal_Sym *, asection **, Elf_Internal_Rela *);
extern bfd_vma _bfd_elf_rel_local_sym
  (bfd *, Elf_Internal_Sym *, asection **, bfd_vma);
extern bfd_vma _bfd_elf_section_offset
  (bfd *, struct bfd_link_info *, asection *, bfd_vma);

extern unsigned long bfd_elf_hash
  (const char *);
extern unsigned long bfd_elf_gnu_hash
  (const char *);

extern bfd_reloc_status_type bfd_elf_generic_reloc
  (bfd *, arelent *, asymbol *, void *, asection *, bfd *, char **);
extern bfd_boolean bfd_elf_allocate_object
  (bfd *, size_t, enum elf_target_id);
extern bfd_boolean bfd_elf_make_object
  (bfd *);
extern bfd_boolean bfd_elf_mkcorefile
  (bfd *);
extern bfd_boolean _bfd_elf_make_section_from_shdr
  (bfd *, Elf_Internal_Shdr *, const char *, int);
extern bfd_boolean _bfd_elf_make_section_from_phdr
  (bfd *, Elf_Internal_Phdr *, int, const char *);
extern struct bfd_hash_entry *_bfd_elf_link_hash_newfunc
  (struct bfd_hash_entry *, struct bfd_hash_table *, const char *);
extern struct bfd_link_hash_table *_bfd_elf_link_hash_table_create
  (bfd *);
extern void _bfd_elf_link_hash_table_free
  (struct bfd_link_hash_table *);
extern void _bfd_elf_link_hash_copy_indirect
  (struct bfd_link_info *, struct elf_link_hash_entry *,
   struct elf_link_hash_entry *);
extern void _bfd_elf_link_hash_hide_symbol
  (struct bfd_link_info *, struct elf_link_hash_entry *, bfd_boolean);
extern bfd_boolean _bfd_elf_link_hash_fixup_symbol
  (struct bfd_link_info *, struct elf_link_hash_entry *);
extern bfd_boolean _bfd_elf_link_hash_table_init
  (struct elf_link_hash_table *, bfd *,
   struct bfd_hash_entry *(*)
     (struct bfd_hash_entry *, struct bfd_hash_table *, const char *),
   unsigned int, enum elf_target_id);
extern bfd_boolean _bfd_elf_slurp_version_tables
  (bfd *, bfd_boolean);
extern bfd_boolean _bfd_elf_merge_sections
  (bfd *, struct bfd_link_info *);
extern bfd_boolean _bfd_elf_match_sections_by_type
  (bfd *, const asection *, bfd *, const asection *);
extern bfd_boolean bfd_elf_is_group_section
  (bfd *, const struct bfd_section *);
extern bfd_boolean _bfd_elf_section_already_linked
  (bfd *, asection *, struct bfd_link_info *);
extern void bfd_elf_set_group_contents
  (bfd *, asection *, void *);
extern asection *_bfd_elf_check_kept_section
  (asection *, struct bfd_link_info *);

extern void _bfd_elf_copy_link_hash_symbol_type
  (bfd *, struct bfd_link_hash_entry *, struct bfd_link_hash_entry *);
extern bfd_boolean _bfd_elf_size_group_sections
  (struct bfd_link_info *);
extern bfd_boolean _bfd_elf_fixup_group_sections
(bfd *, asection *);
extern bfd_boolean _bfd_elf_copy_private_header_data
  (bfd *, bfd *);
extern bfd_boolean _bfd_elf_copy_private_symbol_data
  (bfd *, asymbol *, bfd *, asymbol *);


extern bfd_boolean _bfd_elf_init_private_section_data
  (bfd *, asection *, bfd *, asection *, struct bfd_link_info *);
extern bfd_boolean _bfd_elf_copy_private_section_data
  (bfd *, asection *, bfd *, asection *);
extern bfd_boolean _bfd_elf_write_object_contents
  (bfd *);
extern bfd_boolean _bfd_elf_write_corefile_contents
  (bfd *);
extern bfd_boolean _bfd_elf_set_section_contents
  (bfd *, sec_ptr, const void *, file_ptr, bfd_size_type);
extern long _bfd_elf_get_symtab_upper_bound
  (bfd *);
extern long _bfd_elf_canonicalize_symtab
  (bfd *, asymbol **);
extern long _bfd_elf_get_dynamic_symtab_upper_bound
  (bfd *);
extern long _bfd_elf_canonicalize_dynamic_symtab
  (bfd *, asymbol **);
extern long _bfd_elf_get_synthetic_symtab
  (bfd *, long, asymbol **, long, asymbol **, asymbol **);
extern long _bfd_elf_get_reloc_upper_bound
  (bfd *, sec_ptr);
extern long _bfd_elf_canonicalize_reloc
  (bfd *, sec_ptr, arelent **, asymbol **);
extern asection * _bfd_elf_get_dynamic_reloc_section
  (bfd *, asection *, bfd_boolean);
extern asection * _bfd_elf_make_dynamic_reloc_section
  (asection *, bfd *, unsigned int, bfd *, bfd_boolean);
extern long _bfd_elf_get_dynamic_reloc_upper_bound
  (bfd *);
extern long _bfd_elf_canonicalize_dynamic_reloc
  (bfd *, arelent **, asymbol **);
extern asymbol *_bfd_elf_make_empty_symbol
  (bfd *);
extern void _bfd_elf_get_symbol_info
  (bfd *, asymbol *, symbol_info *);
extern bfd_boolean _bfd_elf_is_local_label_name
  (bfd *, const char *);
extern alent *_bfd_elf_get_lineno
  (bfd *, asymbol *);
extern bfd_boolean _bfd_elf_set_arch_mach
  (bfd *, enum bfd_architecture, unsigned long);
extern bfd_boolean _bfd_elf_find_nearest_line
  (bfd *, asection *, asymbol **, bfd_vma, const char **, const char **,
   unsigned int *);
extern bfd_boolean _bfd_elf_find_nearest_line_discriminator
  (bfd *, asection *, asymbol **, bfd_vma, const char **, const char **,
   unsigned int *, unsigned int *);
extern bfd_boolean _bfd_elf_find_line
  (bfd *, asymbol **, asymbol *, const char **, unsigned int *);
extern bfd_boolean _bfd_elf_find_line_discriminator
  (bfd *, asymbol **, asymbol *, const char **, unsigned int *, unsigned int *);



extern bfd_boolean _bfd_elf_find_inliner_info
  (bfd *, const char **, const char **, unsigned int *);


extern int _bfd_elf_sizeof_headers
  (bfd *, struct bfd_link_info *);
extern bfd_boolean _bfd_elf_new_section_hook
  (bfd *, asection *);
extern const struct bfd_elf_special_section *_bfd_elf_get_special_section
  (const char *, const struct bfd_elf_special_section *, unsigned int);
extern const struct bfd_elf_special_section *_bfd_elf_get_sec_type_attr
  (bfd *, asection *);


extern void _bfd_elf_no_info_to_howto
  (bfd *, arelent *, Elf_Internal_Rela *);

extern bfd_boolean bfd_section_from_shdr
  (bfd *, unsigned int shindex);
extern bfd_boolean bfd_section_from_phdr
  (bfd *, Elf_Internal_Phdr *, int);

extern int _bfd_elf_symbol_from_bfd_symbol
  (bfd *, asymbol **);

extern Elf_Internal_Sym *bfd_sym_from_r_symndx
  (struct sym_cache *, bfd *, unsigned long);
extern asection *bfd_section_from_elf_index
  (bfd *, unsigned int);
extern struct bfd_strtab_hash *_bfd_elf_stringtab_init
  (void);

extern struct elf_strtab_hash * _bfd_elf_strtab_init
  (void);
extern void _bfd_elf_strtab_free
  (struct elf_strtab_hash *);
extern bfd_size_type _bfd_elf_strtab_add
  (struct elf_strtab_hash *, const char *, bfd_boolean);
extern void _bfd_elf_strtab_addref
  (struct elf_strtab_hash *, bfd_size_type);
extern void _bfd_elf_strtab_delref
  (struct elf_strtab_hash *, bfd_size_type);
extern unsigned int _bfd_elf_strtab_refcount
  (struct elf_strtab_hash *, bfd_size_type);
extern void _bfd_elf_strtab_clear_all_refs
  (struct elf_strtab_hash *tab);
extern void _bfd_elf_strtab_restore_size
  (struct elf_strtab_hash *, bfd_size_type);
extern bfd_size_type _bfd_elf_strtab_size
  (struct elf_strtab_hash *);
extern bfd_size_type _bfd_elf_strtab_offset
  (struct elf_strtab_hash *, bfd_size_type);
extern bfd_boolean _bfd_elf_strtab_emit
  (bfd *, struct elf_strtab_hash *);
extern void _bfd_elf_strtab_finalize
  (struct elf_strtab_hash *);

extern void _bfd_elf_begin_eh_frame_parsing
  (struct bfd_link_info *info);
extern void _bfd_elf_parse_eh_frame
  (bfd *, struct bfd_link_info *, asection *, struct elf_reloc_cookie *);
extern void _bfd_elf_end_eh_frame_parsing
  (struct bfd_link_info *info);

extern bfd_boolean _bfd_elf_discard_section_eh_frame
  (bfd *, struct bfd_link_info *, asection *,
   bfd_boolean (*) (bfd_vma, void *), struct elf_reloc_cookie *);
extern bfd_boolean _bfd_elf_discard_section_eh_frame_hdr
  (bfd *, struct bfd_link_info *);
extern bfd_vma _bfd_elf_eh_frame_section_offset
  (bfd *, struct bfd_link_info *, asection *, bfd_vma);
extern bfd_boolean _bfd_elf_write_section_eh_frame
  (bfd *, struct bfd_link_info *, asection *, bfd_byte *);
extern bfd_boolean _bfd_elf_write_section_eh_frame_hdr
  (bfd *, struct bfd_link_info *);
extern bfd_boolean _bfd_elf_eh_frame_present
  (struct bfd_link_info *);
extern bfd_boolean _bfd_elf_maybe_strip_eh_frame_hdr
  (struct bfd_link_info *);

extern bfd_boolean _bfd_elf_hash_symbol (struct elf_link_hash_entry *);

extern long _bfd_elf_link_lookup_local_dynindx
  (struct bfd_link_info *, bfd *, long);
extern bfd_boolean _bfd_elf_compute_section_file_positions
  (bfd *, struct bfd_link_info *);
extern void _bfd_elf_assign_file_positions_for_relocs
  (bfd *);
extern file_ptr _bfd_elf_assign_file_position_for_section
  (Elf_Internal_Shdr *, file_ptr, bfd_boolean);

extern bfd_boolean _bfd_elf_validate_reloc
  (bfd *, arelent *);

extern bfd_boolean _bfd_elf_link_create_dynamic_sections
  (bfd *, struct bfd_link_info *);
extern bfd_boolean _bfd_elf_link_omit_section_dynsym
  (bfd *, struct bfd_link_info *, asection *);
extern bfd_boolean _bfd_elf_create_dynamic_sections
  (bfd *, struct bfd_link_info *);
extern bfd_boolean _bfd_elf_create_got_section
  (bfd *, struct bfd_link_info *);
extern struct elf_link_hash_entry *_bfd_elf_define_linkage_sym
  (bfd *, struct bfd_link_info *, asection *, const char *);
extern void _bfd_elf_init_1_index_section
  (bfd *, struct bfd_link_info *);
extern void _bfd_elf_init_2_index_sections
  (bfd *, struct bfd_link_info *);

extern bfd_boolean _bfd_elfcore_make_pseudosection
  (bfd *, char *, size_t, ufile_ptr);
extern char *_bfd_elfcore_strndup
  (bfd *, char *, size_t);

extern Elf_Internal_Rela *_bfd_elf_link_read_relocs
  (bfd *, asection *, void *, Elf_Internal_Rela *, bfd_boolean);

extern bfd_boolean _bfd_elf_link_output_relocs
  (bfd *, asection *, Elf_Internal_Shdr *, Elf_Internal_Rela *,
   struct elf_link_hash_entry **);

extern bfd_boolean _bfd_elf_adjust_dynamic_copy
  (struct elf_link_hash_entry *, asection *);

extern bfd_boolean _bfd_elf_dynamic_symbol_p
  (struct elf_link_hash_entry *, struct bfd_link_info *, bfd_boolean);

extern bfd_boolean _bfd_elf_symbol_refs_local_p
  (struct elf_link_hash_entry *, struct bfd_link_info *, bfd_boolean);

extern bfd_reloc_status_type bfd_elf_perform_complex_relocation
  (bfd *, asection *, bfd_byte *, Elf_Internal_Rela *, bfd_vma);

extern bfd_boolean _bfd_elf_setup_sections
  (bfd *);

extern void _bfd_elf_post_process_headers (bfd * , struct bfd_link_info *);

extern const bfd_target *bfd_elf32_object_p
  (bfd *);
extern const bfd_target *bfd_elf32_core_file_p
  (bfd *);
extern char *bfd_elf32_core_file_failing_command
  (bfd *);
extern int bfd_elf32_core_file_failing_signal
  (bfd *);
extern bfd_boolean bfd_elf32_core_file_matches_executable_p
  (bfd *, bfd *);
extern int bfd_elf32_core_file_pid
  (bfd *);

extern bfd_boolean bfd_elf32_swap_symbol_in
  (bfd *, const void *, const void *, Elf_Internal_Sym *);
extern void bfd_elf32_swap_symbol_out
  (bfd *, const Elf_Internal_Sym *, void *, void *);
extern void bfd_elf32_swap_reloc_in
  (bfd *, const bfd_byte *, Elf_Internal_Rela *);
extern void bfd_elf32_swap_reloc_out
  (bfd *, const Elf_Internal_Rela *, bfd_byte *);
extern void bfd_elf32_swap_reloca_in
  (bfd *, const bfd_byte *, Elf_Internal_Rela *);
extern void bfd_elf32_swap_reloca_out
  (bfd *, const Elf_Internal_Rela *, bfd_byte *);
extern void bfd_elf32_swap_phdr_in
  (bfd *, const Elf32_External_Phdr *, Elf_Internal_Phdr *);
extern void bfd_elf32_swap_phdr_out
  (bfd *, const Elf_Internal_Phdr *, Elf32_External_Phdr *);
extern void bfd_elf32_swap_dyn_in
  (bfd *, const void *, Elf_Internal_Dyn *);
extern void bfd_elf32_swap_dyn_out
  (bfd *, const Elf_Internal_Dyn *, void *);
extern long bfd_elf32_slurp_symbol_table
  (bfd *, asymbol **, bfd_boolean);
extern bfd_boolean bfd_elf32_write_shdrs_and_ehdr
  (bfd *);
extern int bfd_elf32_write_out_phdrs
  (bfd *, const Elf_Internal_Phdr *, unsigned int);
extern bfd_boolean bfd_elf32_checksum_contents
  (bfd * , void (*) (const void *, size_t, void *), void *);
extern void bfd_elf32_write_relocs
  (bfd *, asection *, void *);
extern bfd_boolean bfd_elf32_slurp_reloc_table
  (bfd *, asection *, asymbol **, bfd_boolean);

extern const bfd_target *bfd_elf64_object_p
  (bfd *);
extern const bfd_target *bfd_elf64_core_file_p
  (bfd *);
extern char *bfd_elf64_core_file_failing_command
  (bfd *);
extern int bfd_elf64_core_file_failing_signal
  (bfd *);
extern bfd_boolean bfd_elf64_core_file_matches_executable_p
  (bfd *, bfd *);
extern int bfd_elf64_core_file_pid
  (bfd *);

extern bfd_boolean bfd_elf64_swap_symbol_in
  (bfd *, const void *, const void *, Elf_Internal_Sym *);
extern void bfd_elf64_swap_symbol_out
  (bfd *, const Elf_Internal_Sym *, void *, void *);
extern void bfd_elf64_swap_reloc_in
  (bfd *, const bfd_byte *, Elf_Internal_Rela *);
extern void bfd_elf64_swap_reloc_out
  (bfd *, const Elf_Internal_Rela *, bfd_byte *);
extern void bfd_elf64_swap_reloca_in
  (bfd *, const bfd_byte *, Elf_Internal_Rela *);
extern void bfd_elf64_swap_reloca_out
  (bfd *, const Elf_Internal_Rela *, bfd_byte *);
extern void bfd_elf64_swap_phdr_in
  (bfd *, const Elf64_External_Phdr *, Elf_Internal_Phdr *);
extern void bfd_elf64_swap_phdr_out
  (bfd *, const Elf_Internal_Phdr *, Elf64_External_Phdr *);
extern void bfd_elf64_swap_dyn_in
  (bfd *, const void *, Elf_Internal_Dyn *);
extern void bfd_elf64_swap_dyn_out
  (bfd *, const Elf_Internal_Dyn *, void *);
extern long bfd_elf64_slurp_symbol_table
  (bfd *, asymbol **, bfd_boolean);
extern bfd_boolean bfd_elf64_write_shdrs_and_ehdr
  (bfd *);
extern int bfd_elf64_write_out_phdrs
  (bfd *, const Elf_Internal_Phdr *, unsigned int);
extern bfd_boolean bfd_elf64_checksum_contents
  (bfd * , void (*) (const void *, size_t, void *), void *);
extern void bfd_elf64_write_relocs
  (bfd *, asection *, void *);
extern bfd_boolean bfd_elf64_slurp_reloc_table
  (bfd *, asection *, asymbol **, bfd_boolean);

extern bfd_boolean _bfd_elf_default_relocs_compatible
  (const bfd_target *, const bfd_target *);

extern bfd_boolean _bfd_elf_relocs_compatible
  (const bfd_target *, const bfd_target *);
extern bfd_boolean _bfd_elf_notice_as_needed
  (bfd *, struct bfd_link_info *, enum notice_asneeded_action);

extern struct elf_link_hash_entry *_bfd_elf_archive_symbol_lookup
  (bfd *, struct bfd_link_info *, const char *);
extern bfd_boolean bfd_elf_link_add_symbols
  (bfd *, struct bfd_link_info *);
extern bfd_boolean _bfd_elf_add_dynamic_entry
  (struct bfd_link_info *, bfd_vma, bfd_vma);

extern bfd_boolean bfd_elf_link_record_dynamic_symbol
  (struct bfd_link_info *, struct elf_link_hash_entry *);

extern int bfd_elf_link_record_local_dynamic_symbol
  (struct bfd_link_info *, bfd *, long);

extern bfd_boolean _bfd_elf_close_and_cleanup
  (bfd *);

extern bfd_boolean _bfd_elf_common_definition
  (Elf_Internal_Sym *);

extern unsigned int _bfd_elf_common_section_index
  (asection *);

extern asection *_bfd_elf_common_section
  (asection *);

extern bfd_vma _bfd_elf_default_got_elt_size
(bfd *, struct bfd_link_info *, struct elf_link_hash_entry *, bfd *,
 unsigned long);

extern bfd_reloc_status_type _bfd_elf_rel_vtable_reloc_fn
  (bfd *, arelent *, struct bfd_symbol *, void *,
   asection *, bfd *, char **);

extern bfd_boolean bfd_elf_final_link
  (bfd *, struct bfd_link_info *);

extern void _bfd_elf_gc_keep
  (struct bfd_link_info *info);

extern bfd_boolean bfd_elf_gc_mark_dynamic_ref_symbol
  (struct elf_link_hash_entry *h, void *inf);

extern bfd_boolean bfd_elf_gc_sections
  (bfd *, struct bfd_link_info *);

extern bfd_boolean bfd_elf_gc_record_vtinherit
  (bfd *, asection *, struct elf_link_hash_entry *, bfd_vma);

extern bfd_boolean bfd_elf_gc_record_vtentry
  (bfd *, asection *, struct elf_link_hash_entry *, bfd_vma);

extern asection *_bfd_elf_gc_mark_hook
  (asection *, struct bfd_link_info *, Elf_Internal_Rela *,
   struct elf_link_hash_entry *, Elf_Internal_Sym *);

extern asection *_bfd_elf_gc_mark_rsec
  (struct bfd_link_info *, asection *, elf_gc_mark_hook_fn,
   struct elf_reloc_cookie *);

extern bfd_boolean _bfd_elf_gc_mark_reloc
  (struct bfd_link_info *, asection *, elf_gc_mark_hook_fn,
   struct elf_reloc_cookie *);

extern bfd_boolean _bfd_elf_gc_mark_fdes
  (struct bfd_link_info *, asection *, asection *, elf_gc_mark_hook_fn,
   struct elf_reloc_cookie *);

extern bfd_boolean _bfd_elf_gc_mark
  (struct bfd_link_info *, asection *, elf_gc_mark_hook_fn);

extern bfd_boolean _bfd_elf_gc_mark_extra_sections
  (struct bfd_link_info *, elf_gc_mark_hook_fn);

extern bfd_boolean bfd_elf_gc_common_finalize_got_offsets
  (bfd *, struct bfd_link_info *);

extern bfd_boolean bfd_elf_gc_common_final_link
  (bfd *, struct bfd_link_info *);

extern bfd_boolean bfd_elf_reloc_symbol_deleted_p
  (bfd_vma, void *);

extern struct elf_segment_map * _bfd_elf_make_dynamic_segment
  (bfd *, asection *);

extern bfd_boolean _bfd_elf_map_sections_to_segments
  (bfd *, struct bfd_link_info *);

extern bfd_boolean _bfd_elf_is_function_type (unsigned int);

extern bfd_size_type _bfd_elf_maybe_function_sym (const asymbol *, asection *,
        bfd_vma *);

extern int bfd_elf_get_default_section_type (flagword);

extern bfd_boolean bfd_elf_lookup_section_flags
  (struct bfd_link_info *, struct flag_info *, asection *);

extern Elf_Internal_Phdr * _bfd_elf_find_segment_containing_section
  (bfd * abfd, asection * section);


extern char *elfcore_write_note
  (bfd *, char *, int *, const char *, int, const void *, int);
extern char *elfcore_write_prpsinfo
  (bfd *, char *, int *, const char *, const char *);
extern char *elfcore_write_prstatus
  (bfd *, char *, int *, long, int, const void *);
extern char * elfcore_write_pstatus
  (bfd *, char *, int *, long, int, const void *);
extern char *elfcore_write_prfpreg
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_prxfpreg
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_xstatereg
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_ppc_vmx
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_ppc_vsx
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_s390_timer
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_s390_todcmp
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_s390_todpreg
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_s390_ctrs
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_s390_prefix
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_s390_last_break
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_s390_system_call
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_s390_tdb
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_arm_vfp
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_aarch_tls
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_aarch_hw_break
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_aarch_hw_watch
  (bfd *, char *, int *, const void *, int);
extern char *elfcore_write_lwpstatus
  (bfd *, char *, int *, long, int, const void *);
extern char *elfcore_write_register_note
  (bfd *, char *, int *, const char *, const void *, int);
struct elf_internal_linux_prpsinfo
  {
    char pr_state;
    char pr_sname;
    char pr_zomb;
    char pr_nice;
    unsigned long pr_flag;
    unsigned int pr_uid;
    unsigned int pr_gid;
    int pr_pid, pr_ppid, pr_pgrp, pr_sid;
    char pr_fname[16 + 1];
    char pr_psargs[80 + 1];
  };


extern char *elfcore_write_linux_prpsinfo32
  (bfd *, char *, int *, const struct elf_internal_linux_prpsinfo *);


extern char *elfcore_write_linux_prpsinfo64
  (bfd *, char *, int *, const struct elf_internal_linux_prpsinfo *);


extern char *elfcore_write_ppc_linux_prpsinfo32
  (bfd *, char *, int *, const struct elf_internal_linux_prpsinfo *);

extern bfd *_bfd_elf32_bfd_from_remote_memory
  (bfd *templ, bfd_vma ehdr_vma, bfd_size_type size, bfd_vma *loadbasep,
   int (*target_read_memory) (bfd_vma, bfd_byte *, bfd_size_type));
extern bfd *_bfd_elf64_bfd_from_remote_memory
  (bfd *templ, bfd_vma ehdr_vma, bfd_size_type size, bfd_vma *loadbasep,
   int (*target_read_memory) (bfd_vma, bfd_byte *, bfd_size_type));

extern bfd_vma bfd_elf_obj_attr_size (bfd *);
extern void bfd_elf_set_obj_attr_contents (bfd *, bfd_byte *, bfd_vma);
extern int bfd_elf_get_obj_attr_int (bfd *, int, int);
extern void bfd_elf_add_obj_attr_int (bfd *, int, int, unsigned int);


extern void bfd_elf_add_obj_attr_string (bfd *, int, int, const char *);


extern void bfd_elf_add_obj_attr_int_string (bfd *, int, int, unsigned int,
          const char *);




extern char *_bfd_elf_attr_strdup (bfd *, const char *);
extern void _bfd_elf_copy_obj_attributes (bfd *, bfd *);
extern int _bfd_elf_obj_attrs_arg_type (bfd *, int, int);
extern void _bfd_elf_parse_attributes (bfd *, Elf_Internal_Shdr *);
extern bfd_boolean _bfd_elf_merge_object_attributes (bfd *, bfd *);
extern bfd_boolean _bfd_elf_merge_unknown_attribute_low (bfd *, bfd *, int);
extern bfd_boolean _bfd_elf_merge_unknown_attribute_list (bfd *, bfd *);
extern Elf_Internal_Shdr *_bfd_elf_single_rel_hdr (asection *sec);







struct elf_dyn_relocs
{
  struct elf_dyn_relocs *next;


  asection *sec;


  bfd_size_type count;


  bfd_size_type pc_count;
};

extern bfd_boolean _bfd_elf_create_ifunc_sections
  (bfd *, struct bfd_link_info *);
extern bfd_boolean _bfd_elf_allocate_ifunc_dyn_relocs
  (struct bfd_link_info *, struct elf_link_hash_entry *,
   struct elf_dyn_relocs **, unsigned int, unsigned int, unsigned int);

extern void elf_append_rela (bfd *, asection *, Elf_Internal_Rela *);
extern void elf_append_rel (bfd *, asection *, Elf_Internal_Rela *);

extern bfd_vma elf64_r_info (bfd_vma, bfd_vma);
extern bfd_vma elf64_r_sym (bfd_vma);
extern bfd_vma elf32_r_info (bfd_vma, bfd_vma);
extern bfd_vma elf32_r_sym (bfd_vma);


extern asection _bfd_elf_large_com_section;

enum elf_arm_reloc_type {

  R_ARM_NONE = 0,
  R_ARM_PC24 = 1,
  R_ARM_ABS32 = 2,
  R_ARM_REL32 = 3,
  R_ARM_LDR_PC_G0 = 4,
  R_ARM_ABS16 = 5,
  R_ARM_ABS12 = 6,
  R_ARM_THM_ABS5 = 7,
  R_ARM_ABS8 = 8,
  R_ARM_SBREL32 = 9,
  R_ARM_THM_CALL = 10,
  R_ARM_THM_PC8 = 11,
  R_ARM_BREL_ADJ = 12,
  R_ARM_TLS_DESC = 13,
  R_ARM_THM_SWI8 = 14,
  R_ARM_XPC25 = 15,
  R_ARM_THM_XPC22 = 16,
  R_ARM_TLS_DTPMOD32 = 17,
  R_ARM_TLS_DTPOFF32 = 18,
  R_ARM_TLS_TPOFF32 = 19,
  R_ARM_COPY = 20,
  R_ARM_GLOB_DAT = 21,
  R_ARM_JUMP_SLOT = 22,
  R_ARM_RELATIVE = 23,
  R_ARM_GOTOFF32 = 24,
  R_ARM_BASE_PREL = 25,
  R_ARM_GOT_BREL = 26,
  R_ARM_PLT32 = 27,
  R_ARM_CALL = 28,
  R_ARM_JUMP24 = 29,
  R_ARM_THM_JUMP24 = 30,
  R_ARM_BASE_ABS = 31,
  R_ARM_ALU_PCREL7_0 = 32,
  R_ARM_ALU_PCREL15_8 = 33,
  R_ARM_ALU_PCREL23_15 = 34,
  R_ARM_LDR_SBREL_11_0 = 35,
  R_ARM_ALU_SBREL_19_12 = 36,
  R_ARM_ALU_SBREL_27_20 = 37,
  R_ARM_TARGET1 = 38,
  R_ARM_SBREL31 = 39,
  R_ARM_V4BX = 40,
  R_ARM_TARGET2 = 41,
  R_ARM_PREL31 = 42,
  R_ARM_MOVW_ABS_NC = 43,
  R_ARM_MOVT_ABS = 44,
  R_ARM_MOVW_PREL_NC = 45,
  R_ARM_MOVT_PREL = 46,
  R_ARM_THM_MOVW_ABS_NC = 47,
  R_ARM_THM_MOVT_ABS = 48,
  R_ARM_THM_MOVW_PREL_NC = 49,
  R_ARM_THM_MOVT_PREL = 50,
  R_ARM_THM_JUMP19 = 51,
  R_ARM_THM_JUMP6 = 52,
  R_ARM_THM_ALU_PREL_11_0 = 53,
  R_ARM_THM_PC12 = 54,
  R_ARM_ABS32_NOI = 55,
  R_ARM_REL32_NOI = 56,
  R_ARM_ALU_PC_G0_NC = 57,
  R_ARM_ALU_PC_G0 = 58,
  R_ARM_ALU_PC_G1_NC = 59,
  R_ARM_ALU_PC_G1 = 60,
  R_ARM_ALU_PC_G2 = 61,
  R_ARM_LDR_PC_G1 = 62,
  R_ARM_LDR_PC_G2 = 63,
  R_ARM_LDRS_PC_G0 = 64,
  R_ARM_LDRS_PC_G1 = 65,
  R_ARM_LDRS_PC_G2 = 66,
  R_ARM_LDC_PC_G0 = 67,
  R_ARM_LDC_PC_G1 = 68,
  R_ARM_LDC_PC_G2 = 69,
  R_ARM_ALU_SB_G0_NC = 70,
  R_ARM_ALU_SB_G0 = 71,
  R_ARM_ALU_SB_G1_NC = 72,
  R_ARM_ALU_SB_G1 = 73,
  R_ARM_ALU_SB_G2 = 74,
  R_ARM_LDR_SB_G0 = 75,
  R_ARM_LDR_SB_G1 = 76,
  R_ARM_LDR_SB_G2 = 77,
  R_ARM_LDRS_SB_G0 = 78,
  R_ARM_LDRS_SB_G1 = 79,
  R_ARM_LDRS_SB_G2 = 80,
  R_ARM_LDC_SB_G0 = 81,
  R_ARM_LDC_SB_G1 = 82,
  R_ARM_LDC_SB_G2 = 83,
  R_ARM_MOVW_BREL_NC = 84,
  R_ARM_MOVT_BREL = 85,
  R_ARM_MOVW_BREL = 86,
  R_ARM_THM_MOVW_BREL_NC = 87,
  R_ARM_THM_MOVT_BREL = 88,
  R_ARM_THM_MOVW_BREL = 89,
  R_ARM_TLS_GOTDESC = 90,
  R_ARM_TLS_CALL = 91,
  R_ARM_TLS_DESCSEQ = 92,
  R_ARM_THM_TLS_CALL = 93,
  R_ARM_PLT32_ABS = 94,
  R_ARM_GOT_ABS = 95,
  R_ARM_GOT_PREL = 96,
  R_ARM_GOT_BREL12 = 97,
  R_ARM_GOTOFF12 = 98,
  R_ARM_GOTRELAX = 99,
  R_ARM_GNU_VTENTRY = 100,
  R_ARM_GNU_VTINHERIT = 101,
  R_ARM_THM_JUMP11 = 102,
  R_ARM_THM_JUMP8 = 103,
  R_ARM_TLS_GD32 = 104,
  R_ARM_TLS_LDM32 = 105,
  R_ARM_TLS_LDO32 = 106,
  R_ARM_TLS_IE32 = 107,
  R_ARM_TLS_LE32 = 108,
  R_ARM_TLS_LDO12 = 109,
  R_ARM_TLS_LE12 = 110,
  R_ARM_TLS_IE12GP = 111,

  R_ARM_ME_TOO = 128,
  R_ARM_THM_TLS_DESCSEQ = 129,

  R_ARM_IRELATIVE = 160,


  R_ARM_RXPC25 = 249,
  R_ARM_RSBREL32 = 250,
  R_ARM_THM_RPC22 = 251,
  R_ARM_RREL32 = 252,
  R_ARM_RABS32 = 253,
  R_ARM_RPC24 = 254,
  R_ARM_RBASE = 255,


  R_ARM_GOTOFF = R_ARM_GOTOFF32,
  R_ARM_THM_PC22 = R_ARM_THM_CALL,
  R_ARM_THM_PC11 = R_ARM_THM_JUMP11,
  R_ARM_THM_PC9 = R_ARM_THM_JUMP8,



  R_ARM_GOTPC = R_ARM_BASE_PREL,
  R_ARM_GOT32 = R_ARM_GOT_BREL,
  R_ARM_ROSEGREL32 = R_ARM_SBREL31,
  R_ARM_AMP_VCALL9 = R_ARM_BREL_ADJ,

R_ARM_max = 256 };




enum
{

  Tag_CPU_raw_name = 4,
  Tag_CPU_name,
  Tag_CPU_arch,
  Tag_CPU_arch_profile,
  Tag_ARM_ISA_use,
  Tag_THUMB_ISA_use,
  Tag_FP_arch,
  Tag_WMMX_arch,
  Tag_Advanced_SIMD_arch,
  Tag_PCS_config,
  Tag_ABI_PCS_R9_use,
  Tag_ABI_PCS_RW_data,
  Tag_ABI_PCS_RO_data,
  Tag_ABI_PCS_GOT_use,
  Tag_ABI_PCS_wchar_t,
  Tag_ABI_FP_rounding,
  Tag_ABI_FP_denormal,
  Tag_ABI_FP_exceptions,
  Tag_ABI_FP_user_exceptions,
  Tag_ABI_FP_number_model,
  Tag_ABI_align_needed,
  Tag_ABI_align_preserved,
  Tag_ABI_enum_size,
  Tag_ABI_HardFP_use,
  Tag_ABI_VFP_args,
  Tag_ABI_WMMX_args,
  Tag_ABI_optimization_goals,
  Tag_ABI_FP_optimization_goals,

  Tag_undefined33 = 33,
  Tag_CPU_unaligned_access,
  Tag_undefined35,
  Tag_FP_HP_extension,
  Tag_undefined37,
  Tag_ABI_FP_16bit_format,
  Tag_undefined39,
  Tag_undefined40,
  Tag_undefined41,
  Tag_MPextension_use,
  Tag_undefined_43,
  Tag_DIV_use,
  Tag_nodefaults = 64,
  Tag_also_compatible_with,
  Tag_T2EE_use,
  Tag_conformance,
  Tag_Virtualization_use,
  Tag_undefined69,
  Tag_MPextension_use_legacy,


  Tag_VFP_arch = Tag_FP_arch,
  Tag_ABI_align8_needed = Tag_ABI_align_needed,
  Tag_ABI_align8_preserved = Tag_ABI_align_preserved,
  Tag_VFP_HP_extension = Tag_FP_HP_extension
};
enum arm_st_branch_type {
  ST_BRANCH_TO_ARM,
  ST_BRANCH_TO_THUMB,
  ST_BRANCH_LONG,
  ST_BRANCH_UNKNOWN
};
enum map_type
{
  MAP_ARM,
  MAP_THUMB,
  MAP_DATA
};

struct arm_private_data
{

  arm_feature_set features;



  int has_mapping_symbols;


  enum map_type last_type;


  int last_mapping_sym;
  bfd_vma last_mapping_addr;
};

struct opcode32
{
  unsigned long arch;
  unsigned long value;
  unsigned long mask;
  const char * assembler;
};

struct opcode16
{
  unsigned long arch;
  unsigned short value, mask;
  const char *assembler;
};
enum opcode_sentinel_enum
{
  SENTINEL_IWMMXT_START = 1,
  SENTINEL_IWMMXT_END,
  SENTINEL_GENERIC_START
} opcode_sentinels;






static const struct opcode32 coprocessor_opcodes[] =
{

  {0x00000001, 0x0e200010, 0x0fff0ff0, "mia%c\tacc0, %0-3r, %12-15r"},
  {0x00000001, 0x0e280010, 0x0fff0ff0, "miaph%c\tacc0, %0-3r, %12-15r"},
  {0x00000001, 0x0e2c0010, 0x0ffc0ff0, "mia%17'T%17`B%16'T%16`B%c\tacc0, %0-3r, %12-15r"},
  {0x00000001, 0x0c400000, 0x0ff00fff, "mar%c\tacc0, %12-15r, %16-19r"},
  {0x00000001, 0x0c500000, 0x0ff00fff, "mra%c\t%12-15r, %16-19r, acc0"},


  { 0, SENTINEL_IWMMXT_START, 0, "" },
  {0x00000004, 0x0e130130, 0x0f3f0fff, "tandc%22-23w%c\t%12-15r"},
  {0x00000001, 0x0e400010, 0x0ff00f3f, "tbcst%6-7w%c\t%16-19g, %12-15r"},
  {0x00000001, 0x0e130170, 0x0f3f0ff8, "textrc%22-23w%c\t%12-15r, #%0-2d"},
  {0x00000001, 0x0e100070, 0x0f300ff0, "textrm%3?su%22-23w%c\t%12-15r, %16-19g, #%0-2d"},
  {0x00000001, 0x0e600010, 0x0ff00f38, "tinsr%6-7w%c\t%16-19g, %12-15r, #%0-2d"},
  {0x00000001, 0x0e000110, 0x0ff00fff, "tmcr%c\t%16-19G, %12-15r"},
  {0x00000001, 0x0c400000, 0x0ff00ff0, "tmcrr%c\t%0-3g, %12-15r, %16-19r"},
  {0x00000001, 0x0e2c0010, 0x0ffc0e10, "tmia%17?tb%16?tb%c\t%5-8g, %0-3r, %12-15r"},
  {0x00000001, 0x0e200010, 0x0fff0e10, "tmia%c\t%5-8g, %0-3r, %12-15r"},
  {0x00000001, 0x0e280010, 0x0fff0e10, "tmiaph%c\t%5-8g, %0-3r, %12-15r"},
  {0x00000001, 0x0e100030, 0x0f300fff, "tmovmsk%22-23w%c\t%12-15r, %16-19g"},
  {0x00000001, 0x0e100110, 0x0ff00ff0, "tmrc%c\t%12-15r, %16-19G"},
  {0x00000001, 0x0c500000, 0x0ff00ff0, "tmrrc%c\t%12-15r, %16-19r, %0-3g"},
  {0x00000001, 0x0e130150, 0x0f3f0fff, "torc%22-23w%c\t%12-15r"},
  {0x00000001, 0x0e120190, 0x0f3f0fff, "torvsc%22-23w%c\t%12-15r"},
  {0x00000001, 0x0e2001c0, 0x0f300fff, "wabs%22-23w%c\t%12-15g, %16-19g"},
  {0x00000001, 0x0e0001c0, 0x0f300fff, "wacc%22-23w%c\t%12-15g, %16-19g"},
  {0x00000001, 0x0e000180, 0x0f000ff0, "wadd%20-23w%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e2001a0, 0x0fb00ff0, "waddbhus%22?ml%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0ea001a0, 0x0ff00ff0, "waddsubhx%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e000020, 0x0f800ff0, "waligni%c\t%12-15g, %16-19g, %0-3g, #%20-22d"},
  {0x00000001, 0x0e800020, 0x0fc00ff0, "walignr%20-21d%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e200000, 0x0fe00ff0, "wand%20'n%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e800000, 0x0fa00ff0, "wavg2%22?hb%20'r%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e400000, 0x0fe00ff0, "wavg4%20'r%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e000060, 0x0f300ff0, "wcmpeq%22-23w%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e100060, 0x0f100ff0, "wcmpgt%21?su%22-23w%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0xfc500100, 0xfe500f00, "wldrd\t%12-15g, %r"},
  {0x00000001, 0xfc100100, 0xfe500f00, "wldrw\t%12-15G, %A"},
  {0x00000001, 0x0c100000, 0x0e100e00, "wldr%L%c\t%12-15g, %l"},
  {0x00000001, 0x0e400100, 0x0fc00ff0, "wmac%21?su%20'z%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e800100, 0x0fc00ff0, "wmadd%21?su%20'x%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0ec00100, 0x0fd00ff0, "wmadd%21?sun%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e000160, 0x0f100ff0, "wmax%21?su%22-23w%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e000080, 0x0f100fe0, "wmerge%c\t%12-15g, %16-19g, %0-3g, #%21-23d"},
  {0x00000001, 0x0e0000a0, 0x0f800ff0, "wmia%21?tb%20?tb%22'n%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e800120, 0x0f800ff0, "wmiaw%21?tb%20?tb%22'n%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e100160, 0x0f100ff0, "wmin%21?su%22-23w%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e000100, 0x0fc00ff0, "wmul%21?su%20?ml%23'r%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0ed00100, 0x0fd00ff0, "wmul%21?sumr%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0ee000c0, 0x0fe00ff0, "wmulwsm%20`r%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0ec000c0, 0x0fe00ff0, "wmulwum%20`r%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0eb000c0, 0x0ff00ff0, "wmulwl%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e8000a0, 0x0f800ff0, "wqmia%21?tb%20?tb%22'n%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e100080, 0x0fd00ff0, "wqmulm%21'r%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0ec000e0, 0x0fd00ff0, "wqmulwm%21'r%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e000000, 0x0ff00ff0, "wor%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e000080, 0x0f000ff0, "wpack%20-23w%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0xfe300040, 0xff300ef0, "wror%22-23w\t%12-15g, %16-19g, #%i"},
  {0x00000001, 0x0e300040, 0x0f300ff0, "wror%22-23w%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e300140, 0x0f300ff0, "wror%22-23wg%c\t%12-15g, %16-19g, %0-3G"},
  {0x00000001, 0x0e000120, 0x0fa00ff0, "wsad%22?hb%20'z%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e0001e0, 0x0f000ff0, "wshufh%c\t%12-15g, %16-19g, #%Z"},
  {0x00000001, 0xfe100040, 0xff300ef0, "wsll%22-23w\t%12-15g, %16-19g, #%i"},
  {0x00000001, 0x0e100040, 0x0f300ff0, "wsll%22-23w%8'g%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e100148, 0x0f300ffc, "wsll%22-23w%8'g%c\t%12-15g, %16-19g, %0-3G"},
  {0x00000001, 0xfe000040, 0xff300ef0, "wsra%22-23w\t%12-15g, %16-19g, #%i"},
  {0x00000001, 0x0e000040, 0x0f300ff0, "wsra%22-23w%8'g%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e000148, 0x0f300ffc, "wsra%22-23w%8'g%c\t%12-15g, %16-19g, %0-3G"},
  {0x00000001, 0xfe200040, 0xff300ef0, "wsrl%22-23w\t%12-15g, %16-19g, #%i"},
  {0x00000001, 0x0e200040, 0x0f300ff0, "wsrl%22-23w%8'g%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e200148, 0x0f300ffc, "wsrl%22-23w%8'g%c\t%12-15g, %16-19g, %0-3G"},
  {0x00000001, 0xfc400100, 0xfe500f00, "wstrd\t%12-15g, %r"},
  {0x00000001, 0xfc000100, 0xfe500f00, "wstrw\t%12-15G, %A"},
  {0x00000001, 0x0c000000, 0x0e100e00, "wstr%L%c\t%12-15g, %l"},
  {0x00000001, 0x0e0001a0, 0x0f000ff0, "wsub%20-23w%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0ed001c0, 0x0ff00ff0, "wsubaddhx%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e1001c0, 0x0f300ff0, "wabsdiff%22-23w%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e0000c0, 0x0fd00fff, "wunpckeh%21?sub%c\t%12-15g, %16-19g"},
  {0x00000001, 0x0e4000c0, 0x0fd00fff, "wunpckeh%21?suh%c\t%12-15g, %16-19g"},
  {0x00000001, 0x0e8000c0, 0x0fd00fff, "wunpckeh%21?suw%c\t%12-15g, %16-19g"},
  {0x00000001, 0x0e0000e0, 0x0f100fff, "wunpckel%21?su%22-23w%c\t%12-15g, %16-19g"},
  {0x00000001, 0x0e1000c0, 0x0f300ff0, "wunpckih%22-23w%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e1000e0, 0x0f300ff0, "wunpckil%22-23w%c\t%12-15g, %16-19g, %0-3g"},
  {0x00000001, 0x0e100000, 0x0ff00ff0, "wxor%c\t%12-15g, %16-19g, %0-3g"},
  { 0, SENTINEL_IWMMXT_END, 0, "" },


  {0x40000000, 0x0e000100, 0x0ff08f10, "adf%c%P%R\t%12-14f, %16-18f, %0-3f"},
  {0x40000000, 0x0e100100, 0x0ff08f10, "muf%c%P%R\t%12-14f, %16-18f, %0-3f"},
  {0x40000000, 0x0e200100, 0x0ff08f10, "suf%c%P%R\t%12-14f, %16-18f, %0-3f"},
  {0x40000000, 0x0e300100, 0x0ff08f10, "rsf%c%P%R\t%12-14f, %16-18f, %0-3f"},
  {0x40000000, 0x0e400100, 0x0ff08f10, "dvf%c%P%R\t%12-14f, %16-18f, %0-3f"},
  {0x40000000, 0x0e500100, 0x0ff08f10, "rdf%c%P%R\t%12-14f, %16-18f, %0-3f"},
  {0x40000000, 0x0e600100, 0x0ff08f10, "pow%c%P%R\t%12-14f, %16-18f, %0-3f"},
  {0x40000000, 0x0e700100, 0x0ff08f10, "rpw%c%P%R\t%12-14f, %16-18f, %0-3f"},
  {0x40000000, 0x0e800100, 0x0ff08f10, "rmf%c%P%R\t%12-14f, %16-18f, %0-3f"},
  {0x40000000, 0x0e900100, 0x0ff08f10, "fml%c%P%R\t%12-14f, %16-18f, %0-3f"},
  {0x40000000, 0x0ea00100, 0x0ff08f10, "fdv%c%P%R\t%12-14f, %16-18f, %0-3f"},
  {0x40000000, 0x0eb00100, 0x0ff08f10, "frd%c%P%R\t%12-14f, %16-18f, %0-3f"},
  {0x40000000, 0x0ec00100, 0x0ff08f10, "pol%c%P%R\t%12-14f, %16-18f, %0-3f"},
  {0x40000000, 0x0e008100, 0x0ff08f10, "mvf%c%P%R\t%12-14f, %0-3f"},
  {0x40000000, 0x0e108100, 0x0ff08f10, "mnf%c%P%R\t%12-14f, %0-3f"},
  {0x40000000, 0x0e208100, 0x0ff08f10, "abs%c%P%R\t%12-14f, %0-3f"},
  {0x40000000, 0x0e308100, 0x0ff08f10, "rnd%c%P%R\t%12-14f, %0-3f"},
  {0x40000000, 0x0e408100, 0x0ff08f10, "sqt%c%P%R\t%12-14f, %0-3f"},
  {0x40000000, 0x0e508100, 0x0ff08f10, "log%c%P%R\t%12-14f, %0-3f"},
  {0x40000000, 0x0e608100, 0x0ff08f10, "lgn%c%P%R\t%12-14f, %0-3f"},
  {0x40000000, 0x0e708100, 0x0ff08f10, "exp%c%P%R\t%12-14f, %0-3f"},
  {0x40000000, 0x0e808100, 0x0ff08f10, "sin%c%P%R\t%12-14f, %0-3f"},
  {0x40000000, 0x0e908100, 0x0ff08f10, "cos%c%P%R\t%12-14f, %0-3f"},
  {0x40000000, 0x0ea08100, 0x0ff08f10, "tan%c%P%R\t%12-14f, %0-3f"},
  {0x40000000, 0x0eb08100, 0x0ff08f10, "asn%c%P%R\t%12-14f, %0-3f"},
  {0x40000000, 0x0ec08100, 0x0ff08f10, "acs%c%P%R\t%12-14f, %0-3f"},
  {0x40000000, 0x0ed08100, 0x0ff08f10, "atn%c%P%R\t%12-14f, %0-3f"},
  {0x40000000, 0x0ee08100, 0x0ff08f10, "urd%c%P%R\t%12-14f, %0-3f"},
  {0x40000000, 0x0ef08100, 0x0ff08f10, "nrm%c%P%R\t%12-14f, %0-3f"},
  {0x40000000, 0x0e000110, 0x0ff00f1f, "flt%c%P%R\t%16-18f, %12-15r"},
  {0x40000000, 0x0e100110, 0x0fff0f98, "fix%c%R\t%12-15r, %0-2f"},
  {0x40000000, 0x0e200110, 0x0fff0fff, "wfs%c\t%12-15r"},
  {0x40000000, 0x0e300110, 0x0fff0fff, "rfs%c\t%12-15r"},
  {0x40000000, 0x0e400110, 0x0fff0fff, "wfc%c\t%12-15r"},
  {0x40000000, 0x0e500110, 0x0fff0fff, "rfc%c\t%12-15r"},
  {0x40000000, 0x0e90f110, 0x0ff8fff0, "cmf%c\t%16-18f, %0-3f"},
  {0x40000000, 0x0eb0f110, 0x0ff8fff0, "cnf%c\t%16-18f, %0-3f"},
  {0x40000000, 0x0ed0f110, 0x0ff8fff0, "cmfe%c\t%16-18f, %0-3f"},
  {0x40000000, 0x0ef0f110, 0x0ff8fff0, "cnfe%c\t%16-18f, %0-3f"},
  {0x40000000, 0x0c000100, 0x0e100f00, "stf%c%Q\t%12-14f, %A"},
  {0x40000000, 0x0c100100, 0x0e100f00, "ldf%c%Q\t%12-14f, %A"},
  {0x20000000, 0x0c000200, 0x0e100f00, "sfm%c\t%12-14f, %F, %A"},
  {0x20000000, 0x0c100200, 0x0e100f00, "lfm%c\t%12-14f, %F, %A"},


  {0x08000000 | 0x00400000, 0x0d2d0b00, 0x0fbf0f01, "vpush%c\t%B"},
  {0x08000000 | 0x00400000, 0x0d200b00, 0x0fb00f01, "vstmdb%c\t%16-19r!, %B"},
  {0x08000000 | 0x00400000, 0x0d300b00, 0x0fb00f01, "vldmdb%c\t%16-19r!, %B"},
  {0x08000000 | 0x00400000, 0x0c800b00, 0x0f900f01, "vstmia%c\t%16-19r%21'!, %B"},
  {0x08000000 | 0x00400000, 0x0cbd0b00, 0x0fbf0f01, "vpop%c\t%B"},
  {0x08000000 | 0x00400000, 0x0c900b00, 0x0f900f01, "vldmia%c\t%16-19r%21'!, %B"},
  {0x08000000 | 0x00400000, 0x0d000b00, 0x0f300f00, "vstr%c\t%12-15,22D, %A"},
  {0x08000000 | 0x00400000, 0x0d100b00, 0x0f300f00, "vldr%c\t%12-15,22D, %A"},
  {0x08000000, 0x0d2d0a00, 0x0fbf0f00, "vpush%c\t%y3"},
  {0x08000000, 0x0d200a00, 0x0fb00f00, "vstmdb%c\t%16-19r!, %y3"},
  {0x08000000, 0x0d300a00, 0x0fb00f00, "vldmdb%c\t%16-19r!, %y3"},
  {0x08000000, 0x0c800a00, 0x0f900f00, "vstmia%c\t%16-19r%21'!, %y3"},
  {0x08000000, 0x0cbd0a00, 0x0fbf0f00, "vpop%c\t%y3"},
  {0x08000000, 0x0c900a00, 0x0f900f00, "vldmia%c\t%16-19r%21'!, %y3"},
  {0x08000000, 0x0d000a00, 0x0f300f00, "vstr%c\t%y1, %A"},
  {0x08000000, 0x0d100a00, 0x0f300f00, "vldr%c\t%y1, %A"},

  {0x08000000, 0x0d200b01, 0x0fb00f01, "fstmdbx%c\t%16-19r!, %z3\t;@ Deprecated"},
  {0x08000000, 0x0d300b01, 0x0fb00f01, "fldmdbx%c\t%16-19r!, %z3\t;@ Deprecated"},
  {0x08000000, 0x0c800b01, 0x0f900f01, "fstmiax%c\t%16-19r%21'!, %z3\t;@ Deprecated"},
  {0x08000000, 0x0c900b01, 0x0f900f01, "fldmiax%c\t%16-19r%21'!, %z3\t;@ Deprecated"},


  {0x00400000, 0x0e800b10, 0x0ff00f70, "vdup%c.32\t%16-19,7D, %12-15r"},
  {0x00400000, 0x0e800b30, 0x0ff00f70, "vdup%c.16\t%16-19,7D, %12-15r"},
  {0x00400000, 0x0ea00b10, 0x0ff00f70, "vdup%c.32\t%16-19,7Q, %12-15r"},
  {0x00400000, 0x0ea00b30, 0x0ff00f70, "vdup%c.16\t%16-19,7Q, %12-15r"},
  {0x00400000, 0x0ec00b10, 0x0ff00f70, "vdup%c.8\t%16-19,7D, %12-15r"},
  {0x00400000, 0x0ee00b10, 0x0ff00f70, "vdup%c.8\t%16-19,7Q, %12-15r"},
  {0x00400000, 0x0c400b10, 0x0ff00fd0, "vmov%c\t%0-3,5D, %12-15r, %16-19r"},
  {0x00400000, 0x0c500b10, 0x0ff00fd0, "vmov%c\t%12-15r, %16-19r, %0-3,5D"},
  {0x00400000, 0x0e000b10, 0x0fd00f70, "vmov%c.32\t%16-19,7D[%21d], %12-15r"},
  {0x00400000, 0x0e100b10, 0x0f500f70, "vmov%c.32\t%12-15r, %16-19,7D[%21d]"},
  {0x00400000, 0x0e000b30, 0x0fd00f30, "vmov%c.16\t%16-19,7D[%6,21d], %12-15r"},
  {0x00400000, 0x0e100b30, 0x0f500f30, "vmov%c.%23?us16\t%12-15r, %16-19,7D[%6,21d]"},
  {0x00400000, 0x0e400b10, 0x0fd00f10, "vmov%c.8\t%16-19,7D[%5,6,21d], %12-15r"},
  {0x00400000, 0x0e500b10, 0x0f500f10, "vmov%c.%23?us8\t%12-15r, %16-19,7D[%5,6,21d]"},

  {0x00020000, 0x0eb20b40, 0x0fbf0f50, "vcvt%7?tb%c.f64.f16\t%z1, %y0"},
  {0x00020000, 0x0eb30b40, 0x0fbf0f50, "vcvt%7?tb%c.f16.f64\t%y1, %z0"},
  {0x00100000, 0x0eb20a40, 0x0fbf0f50, "vcvt%7?tb%c.f32.f16\t%y1, %y0"},
  {0x00100000, 0x0eb30a40, 0x0fbf0f50, "vcvt%7?tb%c.f16.f32\t%y1, %y0"},


  {0x08000000, 0x0ee00a10, 0x0fff0fff, "vmsr%c\tfpsid, %12-15r"},
  {0x08000000, 0x0ee10a10, 0x0fff0fff, "vmsr%c\tfpscr, %12-15r"},
  {0x08000000, 0x0ee60a10, 0x0fff0fff, "vmsr%c\tmvfr1, %12-15r"},
  {0x08000000, 0x0ee70a10, 0x0fff0fff, "vmsr%c\tmvfr0, %12-15r"},
  {0x08000000, 0x0ee80a10, 0x0fff0fff, "vmsr%c\tfpexc, %12-15r"},
  {0x08000000, 0x0ee90a10, 0x0fff0fff, "vmsr%c\tfpinst, %12-15r\t@ Impl def"},
  {0x08000000, 0x0eea0a10, 0x0fff0fff, "vmsr%c\tfpinst2, %12-15r\t@ Impl def"},
  {0x08000000, 0x0ef00a10, 0x0fff0fff, "vmrs%c\t%12-15r, fpsid"},
  {0x08000000, 0x0ef1fa10, 0x0fffffff, "vmrs%c\tAPSR_nzcv, fpscr"},
  {0x08000000, 0x0ef10a10, 0x0fff0fff, "vmrs%c\t%12-15r, fpscr"},
  {0x08000000, 0x0ef60a10, 0x0fff0fff, "vmrs%c\t%12-15r, mvfr1"},
  {0x08000000, 0x0ef70a10, 0x0fff0fff, "vmrs%c\t%12-15r, mvfr0"},
  {0x08000000, 0x0ef80a10, 0x0fff0fff, "vmrs%c\t%12-15r, fpexc"},
  {0x08000000, 0x0ef90a10, 0x0fff0fff, "vmrs%c\t%12-15r, fpinst\t@ Impl def"},
  {0x08000000, 0x0efa0a10, 0x0fff0fff, "vmrs%c\t%12-15r, fpinst2\t@ Impl def"},
  {0x04000000, 0x0e000b10, 0x0fd00fff, "vmov%c.32\t%z2[%21d], %12-15r"},
  {0x04000000, 0x0e100b10, 0x0fd00fff, "vmov%c.32\t%12-15r, %z2[%21d]"},
  {0x08000000, 0x0ee00a10, 0x0ff00fff, "vmsr%c\t<impl def %16-19x>, %12-15r"},
  {0x08000000, 0x0ef00a10, 0x0ff00fff, "vmrs%c\t%12-15r, <impl def %16-19x>"},
  {0x08000000, 0x0e000a10, 0x0ff00f7f, "vmov%c\t%y2, %12-15r"},
  {0x08000000, 0x0e100a10, 0x0ff00f7f, "vmov%c\t%12-15r, %y2"},
  {0x08000000, 0x0eb50a40, 0x0fbf0f70, "vcmp%7'e%c.f32\t%y1, #0.0"},
  {0x04000000, 0x0eb50b40, 0x0fbf0f70, "vcmp%7'e%c.f64\t%z1, #0.0"},
  {0x08000000, 0x0eb00a40, 0x0fbf0fd0, "vmov%c.f32\t%y1, %y0"},
  {0x08000000, 0x0eb00ac0, 0x0fbf0fd0, "vabs%c.f32\t%y1, %y0"},
  {0x04000000, 0x0eb00b40, 0x0fbf0fd0, "vmov%c.f64\t%z1, %z0"},
  {0x04000000, 0x0eb00bc0, 0x0fbf0fd0, "vabs%c.f64\t%z1, %z0"},
  {0x08000000, 0x0eb10a40, 0x0fbf0fd0, "vneg%c.f32\t%y1, %y0"},
  {0x08000000, 0x0eb10ac0, 0x0fbf0fd0, "vsqrt%c.f32\t%y1, %y0"},
  {0x04000000, 0x0eb10b40, 0x0fbf0fd0, "vneg%c.f64\t%z1, %z0"},
  {0x04000000, 0x0eb10bc0, 0x0fbf0fd0, "vsqrt%c.f64\t%z1, %z0"},
  {0x04000000, 0x0eb70ac0, 0x0fbf0fd0, "vcvt%c.f64.f32\t%z1, %y0"},
  {0x04000000, 0x0eb70bc0, 0x0fbf0fd0, "vcvt%c.f32.f64\t%y1, %z0"},
  {0x08000000, 0x0eb80a40, 0x0fbf0f50, "vcvt%c.f32.%7?su32\t%y1, %y0"},
  {0x04000000, 0x0eb80b40, 0x0fbf0f50, "vcvt%c.f64.%7?su32\t%z1, %y0"},
  {0x08000000, 0x0eb40a40, 0x0fbf0f50, "vcmp%7'e%c.f32\t%y1, %y0"},
  {0x04000000, 0x0eb40b40, 0x0fbf0f50, "vcmp%7'e%c.f64\t%z1, %z0"},
  {0x01000000, 0x0eba0a40, 0x0fbe0f50, "vcvt%c.f32.%16?us%7?31%7?26\t%y1, %y1, #%5,0-3k"},
  {0x00800000, 0x0eba0b40, 0x0fbe0f50, "vcvt%c.f64.%16?us%7?31%7?26\t%z1, %z1, #%5,0-3k"},
  {0x08000000, 0x0ebc0a40, 0x0fbe0f50, "vcvt%7`r%c.%16?su32.f32\t%y1, %y0"},
  {0x04000000, 0x0ebc0b40, 0x0fbe0f50, "vcvt%7`r%c.%16?su32.f64\t%y1, %z0"},
  {0x01000000, 0x0ebe0a40, 0x0fbe0f50, "vcvt%c.%16?us%7?31%7?26.f32\t%y1, %y1, #%5,0-3k"},
  {0x00800000, 0x0ebe0b40, 0x0fbe0f50, "vcvt%c.%16?us%7?31%7?26.f64\t%z1, %z1, #%5,0-3k"},
  {0x04000000, 0x0c500b10, 0x0fb00ff0, "vmov%c\t%12-15r, %16-19r, %z0"},
  {0x01000000, 0x0eb00a00, 0x0fb00ff0, "vmov%c.f32\t%y1, #%0-3,16-19d"},
  {0x00800000, 0x0eb00b00, 0x0fb00ff0, "vmov%c.f64\t%z1, #%0-3,16-19d"},
  {0x02000000, 0x0c400a10, 0x0ff00fd0, "vmov%c\t%y4, %12-15r, %16-19r"},
  {0x02000000, 0x0c400b10, 0x0ff00fd0, "vmov%c\t%z0, %12-15r, %16-19r"},
  {0x02000000, 0x0c500a10, 0x0ff00fd0, "vmov%c\t%12-15r, %16-19r, %y4"},
  {0x08000000, 0x0e000a00, 0x0fb00f50, "vmla%c.f32\t%y1, %y2, %y0"},
  {0x08000000, 0x0e000a40, 0x0fb00f50, "vmls%c.f32\t%y1, %y2, %y0"},
  {0x04000000, 0x0e000b00, 0x0fb00f50, "vmla%c.f64\t%z1, %z2, %z0"},
  {0x04000000, 0x0e000b40, 0x0fb00f50, "vmls%c.f64\t%z1, %z2, %z0"},
  {0x08000000, 0x0e100a00, 0x0fb00f50, "vnmls%c.f32\t%y1, %y2, %y0"},
  {0x08000000, 0x0e100a40, 0x0fb00f50, "vnmla%c.f32\t%y1, %y2, %y0"},
  {0x04000000, 0x0e100b00, 0x0fb00f50, "vnmls%c.f64\t%z1, %z2, %z0"},
  {0x04000000, 0x0e100b40, 0x0fb00f50, "vnmla%c.f64\t%z1, %z2, %z0"},
  {0x08000000, 0x0e200a00, 0x0fb00f50, "vmul%c.f32\t%y1, %y2, %y0"},
  {0x08000000, 0x0e200a40, 0x0fb00f50, "vnmul%c.f32\t%y1, %y2, %y0"},
  {0x04000000, 0x0e200b00, 0x0fb00f50, "vmul%c.f64\t%z1, %z2, %z0"},
  {0x04000000, 0x0e200b40, 0x0fb00f50, "vnmul%c.f64\t%z1, %z2, %z0"},
  {0x08000000, 0x0e300a00, 0x0fb00f50, "vadd%c.f32\t%y1, %y2, %y0"},
  {0x08000000, 0x0e300a40, 0x0fb00f50, "vsub%c.f32\t%y1, %y2, %y0"},
  {0x04000000, 0x0e300b00, 0x0fb00f50, "vadd%c.f64\t%z1, %z2, %z0"},
  {0x04000000, 0x0e300b40, 0x0fb00f50, "vsub%c.f64\t%z1, %z2, %z0"},
  {0x08000000, 0x0e800a00, 0x0fb00f50, "vdiv%c.f32\t%y1, %y2, %y0"},
  {0x04000000, 0x0e800b00, 0x0fb00f50, "vdiv%c.f64\t%z1, %z2, %z0"},


  {0x00000002, 0x0d100400, 0x0f500f00, "cfldrs%c\tmvf%12-15d, %A"},
  {0x00000002, 0x0c100400, 0x0f500f00, "cfldrs%c\tmvf%12-15d, %A"},
  {0x00000002, 0x0d500400, 0x0f500f00, "cfldrd%c\tmvd%12-15d, %A"},
  {0x00000002, 0x0c500400, 0x0f500f00, "cfldrd%c\tmvd%12-15d, %A"},
  {0x00000002, 0x0d100500, 0x0f500f00, "cfldr32%c\tmvfx%12-15d, %A"},
  {0x00000002, 0x0c100500, 0x0f500f00, "cfldr32%c\tmvfx%12-15d, %A"},
  {0x00000002, 0x0d500500, 0x0f500f00, "cfldr64%c\tmvdx%12-15d, %A"},
  {0x00000002, 0x0c500500, 0x0f500f00, "cfldr64%c\tmvdx%12-15d, %A"},
  {0x00000002, 0x0d000400, 0x0f500f00, "cfstrs%c\tmvf%12-15d, %A"},
  {0x00000002, 0x0c000400, 0x0f500f00, "cfstrs%c\tmvf%12-15d, %A"},
  {0x00000002, 0x0d400400, 0x0f500f00, "cfstrd%c\tmvd%12-15d, %A"},
  {0x00000002, 0x0c400400, 0x0f500f00, "cfstrd%c\tmvd%12-15d, %A"},
  {0x00000002, 0x0d000500, 0x0f500f00, "cfstr32%c\tmvfx%12-15d, %A"},
  {0x00000002, 0x0c000500, 0x0f500f00, "cfstr32%c\tmvfx%12-15d, %A"},
  {0x00000002, 0x0d400500, 0x0f500f00, "cfstr64%c\tmvdx%12-15d, %A"},
  {0x00000002, 0x0c400500, 0x0f500f00, "cfstr64%c\tmvdx%12-15d, %A"},
  {0x00000002, 0x0e000450, 0x0ff00ff0, "cfmvsr%c\tmvf%16-19d, %12-15r"},
  {0x00000002, 0x0e100450, 0x0ff00ff0, "cfmvrs%c\t%12-15r, mvf%16-19d"},
  {0x00000002, 0x0e000410, 0x0ff00ff0, "cfmvdlr%c\tmvd%16-19d, %12-15r"},
  {0x00000002, 0x0e100410, 0x0ff00ff0, "cfmvrdl%c\t%12-15r, mvd%16-19d"},
  {0x00000002, 0x0e000430, 0x0ff00ff0, "cfmvdhr%c\tmvd%16-19d, %12-15r"},
  {0x00000002, 0x0e100430, 0x0ff00fff, "cfmvrdh%c\t%12-15r, mvd%16-19d"},
  {0x00000002, 0x0e000510, 0x0ff00fff, "cfmv64lr%c\tmvdx%16-19d, %12-15r"},
  {0x00000002, 0x0e100510, 0x0ff00fff, "cfmvr64l%c\t%12-15r, mvdx%16-19d"},
  {0x00000002, 0x0e000530, 0x0ff00fff, "cfmv64hr%c\tmvdx%16-19d, %12-15r"},
  {0x00000002, 0x0e100530, 0x0ff00fff, "cfmvr64h%c\t%12-15r, mvdx%16-19d"},
  {0x00000002, 0x0e200440, 0x0ff00fff, "cfmval32%c\tmvax%12-15d, mvfx%16-19d"},
  {0x00000002, 0x0e100440, 0x0ff00fff, "cfmv32al%c\tmvfx%12-15d, mvax%16-19d"},
  {0x00000002, 0x0e200460, 0x0ff00fff, "cfmvam32%c\tmvax%12-15d, mvfx%16-19d"},
  {0x00000002, 0x0e100460, 0x0ff00fff, "cfmv32am%c\tmvfx%12-15d, mvax%16-19d"},
  {0x00000002, 0x0e200480, 0x0ff00fff, "cfmvah32%c\tmvax%12-15d, mvfx%16-19d"},
  {0x00000002, 0x0e100480, 0x0ff00fff, "cfmv32ah%c\tmvfx%12-15d, mvax%16-19d"},
  {0x00000002, 0x0e2004a0, 0x0ff00fff, "cfmva32%c\tmvax%12-15d, mvfx%16-19d"},
  {0x00000002, 0x0e1004a0, 0x0ff00fff, "cfmv32a%c\tmvfx%12-15d, mvax%16-19d"},
  {0x00000002, 0x0e2004c0, 0x0ff00fff, "cfmva64%c\tmvax%12-15d, mvdx%16-19d"},
  {0x00000002, 0x0e1004c0, 0x0ff00fff, "cfmv64a%c\tmvdx%12-15d, mvax%16-19d"},
  {0x00000002, 0x0e2004e0, 0x0fff0fff, "cfmvsc32%c\tdspsc, mvdx%12-15d"},
  {0x00000002, 0x0e1004e0, 0x0fff0fff, "cfmv32sc%c\tmvdx%12-15d, dspsc"},
  {0x00000002, 0x0e000400, 0x0ff00fff, "cfcpys%c\tmvf%12-15d, mvf%16-19d"},
  {0x00000002, 0x0e000420, 0x0ff00fff, "cfcpyd%c\tmvd%12-15d, mvd%16-19d"},
  {0x00000002, 0x0e000460, 0x0ff00fff, "cfcvtsd%c\tmvd%12-15d, mvf%16-19d"},
  {0x00000002, 0x0e000440, 0x0ff00fff, "cfcvtds%c\tmvf%12-15d, mvd%16-19d"},
  {0x00000002, 0x0e000480, 0x0ff00fff, "cfcvt32s%c\tmvf%12-15d, mvfx%16-19d"},
  {0x00000002, 0x0e0004a0, 0x0ff00fff, "cfcvt32d%c\tmvd%12-15d, mvfx%16-19d"},
  {0x00000002, 0x0e0004c0, 0x0ff00fff, "cfcvt64s%c\tmvf%12-15d, mvdx%16-19d"},
  {0x00000002, 0x0e0004e0, 0x0ff00fff, "cfcvt64d%c\tmvd%12-15d, mvdx%16-19d"},
  {0x00000002, 0x0e100580, 0x0ff00fff, "cfcvts32%c\tmvfx%12-15d, mvf%16-19d"},
  {0x00000002, 0x0e1005a0, 0x0ff00fff, "cfcvtd32%c\tmvfx%12-15d, mvd%16-19d"},
  {0x00000002, 0x0e1005c0, 0x0ff00fff, "cftruncs32%c\tmvfx%12-15d, mvf%16-19d"},
  {0x00000002, 0x0e1005e0, 0x0ff00fff, "cftruncd32%c\tmvfx%12-15d, mvd%16-19d"},
  {0x00000002, 0x0e000550, 0x0ff00ff0, "cfrshl32%c\tmvfx%16-19d, mvfx%0-3d, %12-15r"},
  {0x00000002, 0x0e000570, 0x0ff00ff0, "cfrshl64%c\tmvdx%16-19d, mvdx%0-3d, %12-15r"},
  {0x00000002, 0x0e000500, 0x0ff00f10, "cfsh32%c\tmvfx%12-15d, mvfx%16-19d, #%I"},
  {0x00000002, 0x0e200500, 0x0ff00f10, "cfsh64%c\tmvdx%12-15d, mvdx%16-19d, #%I"},
  {0x00000002, 0x0e100490, 0x0ff00ff0, "cfcmps%c\t%12-15r, mvf%16-19d, mvf%0-3d"},
  {0x00000002, 0x0e1004b0, 0x0ff00ff0, "cfcmpd%c\t%12-15r, mvd%16-19d, mvd%0-3d"},
  {0x00000002, 0x0e100590, 0x0ff00ff0, "cfcmp32%c\t%12-15r, mvfx%16-19d, mvfx%0-3d"},
  {0x00000002, 0x0e1005b0, 0x0ff00ff0, "cfcmp64%c\t%12-15r, mvdx%16-19d, mvdx%0-3d"},
  {0x00000002, 0x0e300400, 0x0ff00fff, "cfabss%c\tmvf%12-15d, mvf%16-19d"},
  {0x00000002, 0x0e300420, 0x0ff00fff, "cfabsd%c\tmvd%12-15d, mvd%16-19d"},
  {0x00000002, 0x0e300440, 0x0ff00fff, "cfnegs%c\tmvf%12-15d, mvf%16-19d"},
  {0x00000002, 0x0e300460, 0x0ff00fff, "cfnegd%c\tmvd%12-15d, mvd%16-19d"},
  {0x00000002, 0x0e300480, 0x0ff00ff0, "cfadds%c\tmvf%12-15d, mvf%16-19d, mvf%0-3d"},
  {0x00000002, 0x0e3004a0, 0x0ff00ff0, "cfaddd%c\tmvd%12-15d, mvd%16-19d, mvd%0-3d"},
  {0x00000002, 0x0e3004c0, 0x0ff00ff0, "cfsubs%c\tmvf%12-15d, mvf%16-19d, mvf%0-3d"},
  {0x00000002, 0x0e3004e0, 0x0ff00ff0, "cfsubd%c\tmvd%12-15d, mvd%16-19d, mvd%0-3d"},
  {0x00000002, 0x0e100400, 0x0ff00ff0, "cfmuls%c\tmvf%12-15d, mvf%16-19d, mvf%0-3d"},
  {0x00000002, 0x0e100420, 0x0ff00ff0, "cfmuld%c\tmvd%12-15d, mvd%16-19d, mvd%0-3d"},
  {0x00000002, 0x0e300500, 0x0ff00fff, "cfabs32%c\tmvfx%12-15d, mvfx%16-19d"},
  {0x00000002, 0x0e300520, 0x0ff00fff, "cfabs64%c\tmvdx%12-15d, mvdx%16-19d"},
  {0x00000002, 0x0e300540, 0x0ff00fff, "cfneg32%c\tmvfx%12-15d, mvfx%16-19d"},
  {0x00000002, 0x0e300560, 0x0ff00fff, "cfneg64%c\tmvdx%12-15d, mvdx%16-19d"},
  {0x00000002, 0x0e300580, 0x0ff00ff0, "cfadd32%c\tmvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
  {0x00000002, 0x0e3005a0, 0x0ff00ff0, "cfadd64%c\tmvdx%12-15d, mvdx%16-19d, mvdx%0-3d"},
  {0x00000002, 0x0e3005c0, 0x0ff00ff0, "cfsub32%c\tmvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
  {0x00000002, 0x0e3005e0, 0x0ff00ff0, "cfsub64%c\tmvdx%12-15d, mvdx%16-19d, mvdx%0-3d"},
  {0x00000002, 0x0e100500, 0x0ff00ff0, "cfmul32%c\tmvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
  {0x00000002, 0x0e100520, 0x0ff00ff0, "cfmul64%c\tmvdx%12-15d, mvdx%16-19d, mvdx%0-3d"},
  {0x00000002, 0x0e100540, 0x0ff00ff0, "cfmac32%c\tmvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
  {0x00000002, 0x0e100560, 0x0ff00ff0, "cfmsc32%c\tmvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
  {0x00000002, 0x0e000600, 0x0ff00f10, "cfmadd32%c\tmvax%5-7d, mvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
  {0x00000002, 0x0e100600, 0x0ff00f10, "cfmsub32%c\tmvax%5-7d, mvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
  {0x00000002, 0x0e200600, 0x0ff00f10, "cfmadda32%c\tmvax%5-7d, mvax%12-15d, mvfx%16-19d, mvfx%0-3d"},
  {0x00000002, 0x0e300600, 0x0ff00f10, "cfmsuba32%c\tmvax%5-7d, mvax%12-15d, mvfx%16-19d, mvfx%0-3d"},


  {0x00040000, 0x0ea00a00, 0x0fb00f50, "vfma%c.f32\t%y1, %y2, %y0"},
  {0x00040000, 0x0ea00b00, 0x0fb00f50, "vfma%c.f64\t%z1, %z2, %z0"},
  {0x00040000, 0x0ea00a40, 0x0fb00f50, "vfms%c.f32\t%y1, %y2, %y0"},
  {0x00040000, 0x0ea00b40, 0x0fb00f50, "vfms%c.f64\t%z1, %z2, %z0"},
  {0x00040000, 0x0e900a40, 0x0fb00f50, "vfnma%c.f32\t%y1, %y2, %y0"},
  {0x00040000, 0x0e900b40, 0x0fb00f50, "vfnma%c.f64\t%z1, %z2, %z0"},
  {0x00040000, 0x0e900a00, 0x0fb00f50, "vfnms%c.f32\t%y1, %y2, %y0"},
  {0x00040000, 0x0e900b00, 0x0fb00f50, "vfnms%c.f64\t%z1, %z2, %z0"},


  {0x00020000, 0xfe000a00, 0xff800f00, "vsel%20-21c%u.f32\t%y1, %y2, %y0"},
  {0x00020000, 0xfe000b00, 0xff800f00, "vsel%20-21c%u.f64\t%z1, %z2, %z0"},
  {0x00020000, 0xfe800a00, 0xffb00f40, "vmaxnm%u.f32\t%y1, %y2, %y0"},
  {0x00020000, 0xfe800b00, 0xffb00f40, "vmaxnm%u.f64\t%z1, %z2, %z0"},
  {0x00020000, 0xfe800a40, 0xffb00f40, "vminnm%u.f32\t%y1, %y2, %y0"},
  {0x00020000, 0xfe800b40, 0xffb00f40, "vminnm%u.f64\t%z1, %z2, %z0"},
  {0x00020000, 0xfebc0a40, 0xffbc0f50, "vcvt%16-17?mpna%u.%7?su32.f32\t%y1, %y0"},
  {0x00020000, 0xfebc0b40, 0xffbc0f50, "vcvt%16-17?mpna%u.%7?su32.f64\t%y1, %z0"},
  {0x00020000, 0x0eb60a40, 0x0fbe0f50, "vrint%7,16??xzr%c.f32\t%y1, %y0"},
  {0x00020000, 0x0eb60b40, 0x0fbe0f50, "vrint%7,16??xzr%c.f64\t%z1, %z0"},
  {0x00020000, 0xfeb80a40, 0xffbc0f50, "vrint%16-17?mpna%u.f32\t%y1, %y0"},
  {0x00020000, 0xfeb80b40, 0xffbc0f50, "vrint%16-17?mpna%u.f64\t%z1, %z0"},


  { 0, SENTINEL_GENERIC_START, 0, "" },
  {0x00000400, 0x0c400000, 0x0ff00000, "mcrr%c\t%8-11d, %4-7d, %12-15R, %16-19r, cr%0-3d"},
  {0x00000400, 0x0c500000, 0x0ff00000, "mrrc%c\t%8-11d, %4-7d, %12-15Ru, %16-19Ru, cr%0-3d"},
  {0x00000002, 0x0e000000, 0x0f000010, "cdp%c\t%8-11d, %20-23d, cr%12-15d, cr%16-19d, cr%0-3d, {%5-7d}"},
  {0x00000002, 0x0e10f010, 0x0f10f010, "mrc%c\t%8-11d, %21-23d, APSR_nzcv, cr%16-19d, cr%0-3d, {%5-7d}"},
  {0x00000002, 0x0e100010, 0x0f100010, "mrc%c\t%8-11d, %21-23d, %12-15r, cr%16-19d, cr%0-3d, {%5-7d}"},
  {0x00000002, 0x0e000010, 0x0f100010, "mcr%c\t%8-11d, %21-23d, %12-15R, cr%16-19d, cr%0-3d, {%5-7d}"},
  {0x00000002, 0x0c000000, 0x0e100000, "stc%22'l%c\t%8-11d, cr%12-15d, %A"},
  {0x00000002, 0x0c100000, 0x0e100000, "ldc%22'l%c\t%8-11d, cr%12-15d, %A"},


  {0x00001000, 0xfc500000, 0xfff00000, "mrrc2%c\t%8-11d, %4-7d, %12-15Ru, %16-19Ru, cr%0-3d"},
  {0x00001000, 0xfc400000, 0xfff00000, "mcrr2%c\t%8-11d, %4-7d, %12-15R, %16-19R, cr%0-3d"},


  {0x00000080, 0xfc100000, 0xfe100000, "ldc2%22'l%c\t%8-11d, cr%12-15d, %A"},
  {0x00000080, 0xfc000000, 0xfe100000, "stc2%22'l%c\t%8-11d, cr%12-15d, %A"},
  {0x00000080, 0xfe000000, 0xff000010, "cdp2%c\t%8-11d, %20-23d, cr%12-15d, cr%16-19d, cr%0-3d, {%5-7d}"},
  {0x00000080, 0xfe000010, 0xff100010, "mcr2%c\t%8-11d, %21-23d, %12-15R, cr%16-19d, cr%0-3d, {%5-7d}"},
  {0x00000080, 0xfe100010, 0xff100010, "mrc2%c\t%8-11d, %21-23d, %12-15r, cr%16-19d, cr%0-3d, {%5-7d}"},

  {0, 0, 0, 0}
};
static const struct opcode32 neon_opcodes[] =
{

  {0x00400000, 0xf2b00840, 0xffb00850, "vext%c.8\t%12-15,22R, %16-19,7R, %0-3,5R, #%8-11d"},
  {0x00400000, 0xf2b00000, 0xffb00810, "vext%c.8\t%12-15,22R, %16-19,7R, %0-3,5R, #%8-11d"},


  {0x00400000, 0xf3b40c00, 0xffb70f90, "vdup%c.32\t%12-15,22R, %0-3,5D[%19d]"},
  {0x00400000, 0xf3b20c00, 0xffb30f90, "vdup%c.16\t%12-15,22R, %0-3,5D[%18-19d]"},
  {0x00400000, 0xf3b10c00, 0xffb10f90, "vdup%c.8\t%12-15,22R, %0-3,5D[%17-19d]"},


  {0x00400000, 0xf3b00800, 0xffb00c50, "vtbl%c.8\t%12-15,22D, %F, %0-3,5D"},
  {0x00400000, 0xf3b00840, 0xffb00c50, "vtbx%c.8\t%12-15,22D, %F, %0-3,5D"},


  {0x00100000, 0xf3b60600, 0xffbf0fd0, "vcvt%c.f16.f32\t%12-15,22D, %0-3,5Q"},
  {0x00100000, 0xf3b60700, 0xffbf0fd0, "vcvt%c.f32.f16\t%12-15,22Q, %0-3,5D"},


  {0x00080000, 0xf2000c10, 0xffa00f10, "vfma%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00080000, 0xf2200c10, 0xffa00f10, "vfms%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},


  {0x00010000, 0xf3ba0400, 0xffbf0c10, "vrint%7-9?p?m?zaxn%u.f32\t%12-15,22R, %0-3,5R"},
  {0x00010000, 0xf3bb0000, 0xffbf0c10, "vcvt%8-9?mpna%u.%7?us32.f32\t%12-15,22R, %0-3,5R"},
  {0x00008000, 0xf3b00300, 0xffbf0fd0, "aese%u.8\t%12-15,22Q, %0-3,5Q"},
  {0x00008000, 0xf3b00340, 0xffbf0fd0, "aesd%u.8\t%12-15,22Q, %0-3,5Q"},
  {0x00008000, 0xf3b00380, 0xffbf0fd0, "aesmc%u.8\t%12-15,22Q, %0-3,5Q"},
  {0x00008000, 0xf3b003c0, 0xffbf0fd0, "aesimc%u.8\t%12-15,22Q, %0-3,5Q"},
  {0x00008000, 0xf3b902c0, 0xffbf0fd0, "sha1h%u.32\t%12-15,22Q, %0-3,5Q"},
  {0x00008000, 0xf3ba0380, 0xffbf0fd0, "sha1su1%u.32\t%12-15,22Q, %0-3,5Q"},
  {0x00008000, 0xf3ba03c0, 0xffbf0fd0, "sha256su0%u.32\t%12-15,22Q, %0-3,5Q"},
  {0x00400000, 0xf2880a10, 0xfebf0fd0, "vmovl%c.%24?us8\t%12-15,22Q, %0-3,5D"},
  {0x00400000, 0xf2900a10, 0xfebf0fd0, "vmovl%c.%24?us16\t%12-15,22Q, %0-3,5D"},
  {0x00400000, 0xf2a00a10, 0xfebf0fd0, "vmovl%c.%24?us32\t%12-15,22Q, %0-3,5D"},
  {0x00400000, 0xf3b00500, 0xffbf0f90, "vcnt%c.8\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b00580, 0xffbf0f90, "vmvn%c\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b20000, 0xffbf0f90, "vswp%c\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b20200, 0xffb30fd0, "vmovn%c.i%18-19T2\t%12-15,22D, %0-3,5Q"},
  {0x00400000, 0xf3b20240, 0xffb30fd0, "vqmovun%c.s%18-19T2\t%12-15,22D, %0-3,5Q"},
  {0x00400000, 0xf3b20280, 0xffb30fd0, "vqmovn%c.s%18-19T2\t%12-15,22D, %0-3,5Q"},
  {0x00400000, 0xf3b202c0, 0xffb30fd0, "vqmovn%c.u%18-19T2\t%12-15,22D, %0-3,5Q"},
  {0x00400000, 0xf3b20300, 0xffb30fd0, "vshll%c.i%18-19S2\t%12-15,22Q, %0-3,5D, #%18-19S2"},
  {0x00400000, 0xf3bb0400, 0xffbf0e90, "vrecpe%c.%8?fu%18-19S2\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3bb0480, 0xffbf0e90, "vrsqrte%c.%8?fu%18-19S2\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b00000, 0xffb30f90, "vrev64%c.%18-19S2\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b00080, 0xffb30f90, "vrev32%c.%18-19S2\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b00100, 0xffb30f90, "vrev16%c.%18-19S2\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b00400, 0xffb30f90, "vcls%c.s%18-19S2\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b00480, 0xffb30f90, "vclz%c.i%18-19S2\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b00700, 0xffb30f90, "vqabs%c.s%18-19S2\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b00780, 0xffb30f90, "vqneg%c.s%18-19S2\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b20080, 0xffb30f90, "vtrn%c.%18-19S2\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b20100, 0xffb30f90, "vuzp%c.%18-19S2\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b20180, 0xffb30f90, "vzip%c.%18-19S2\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b10000, 0xffb30b90, "vcgt%c.%10?fs%18-19S2\t%12-15,22R, %0-3,5R, #0"},
  {0x00400000, 0xf3b10080, 0xffb30b90, "vcge%c.%10?fs%18-19S2\t%12-15,22R, %0-3,5R, #0"},
  {0x00400000, 0xf3b10100, 0xffb30b90, "vceq%c.%10?fi%18-19S2\t%12-15,22R, %0-3,5R, #0"},
  {0x00400000, 0xf3b10180, 0xffb30b90, "vcle%c.%10?fs%18-19S2\t%12-15,22R, %0-3,5R, #0"},
  {0x00400000, 0xf3b10200, 0xffb30b90, "vclt%c.%10?fs%18-19S2\t%12-15,22R, %0-3,5R, #0"},
  {0x00400000, 0xf3b10300, 0xffb30b90, "vabs%c.%10?fs%18-19S2\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b10380, 0xffb30b90, "vneg%c.%10?fs%18-19S2\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b00200, 0xffb30f10, "vpaddl%c.%7?us%18-19S2\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b00600, 0xffb30f10, "vpadal%c.%7?us%18-19S2\t%12-15,22R, %0-3,5R"},
  {0x00400000, 0xf3b30600, 0xffb30e10, "vcvt%c.%7-8?usff%18-19Sa.%7-8?ffus%18-19Sa\t%12-15,22R, %0-3,5R"},


  {0x00008000, 0xf2000c40, 0xffb00f50, "sha1c%u.32\t%12-15,22Q, %16-19,7Q, %0-3,5Q"},
  {0x00008000, 0xf2100c40, 0xffb00f50, "sha1p%u.32\t%12-15,22Q, %16-19,7Q, %0-3,5Q"},
  {0x00008000, 0xf2200c40, 0xffb00f50, "sha1m%u.32\t%12-15,22Q, %16-19,7Q, %0-3,5Q"},
  {0x00008000, 0xf2300c40, 0xffb00f50, "sha1su0%u.32\t%12-15,22Q, %16-19,7Q, %0-3,5Q"},
  {0x00008000, 0xf3000c40, 0xffb00f50, "sha256h%u.32\t%12-15,22Q, %16-19,7Q, %0-3,5Q"},
  {0x00008000, 0xf3100c40, 0xffb00f50, "sha256h2%u.32\t%12-15,22Q, %16-19,7Q, %0-3,5Q"},
  {0x00008000, 0xf3200c40, 0xffb00f50, "sha256su1%u.32\t%12-15,22Q, %16-19,7Q, %0-3,5Q"},
  {0x00010000, 0xf3000f10, 0xffa00f10, "vmaxnm%u.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00010000, 0xf3200f10, 0xffa00f10, "vminnm%u.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000110, 0xffb00f10, "vand%c\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2100110, 0xffb00f10, "vbic%c\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2200110, 0xffb00f10, "vorr%c\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2300110, 0xffb00f10, "vorn%c\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3000110, 0xffb00f10, "veor%c\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3100110, 0xffb00f10, "vbsl%c\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3200110, 0xffb00f10, "vbit%c\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3300110, 0xffb00f10, "vbif%c\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000d00, 0xffa00f10, "vadd%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000d10, 0xffa00f10, "vmla%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000e00, 0xffa00f10, "vceq%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000f00, 0xffa00f10, "vmax%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000f10, 0xffa00f10, "vrecps%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2200d00, 0xffa00f10, "vsub%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2200d10, 0xffa00f10, "vmls%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2200f00, 0xffa00f10, "vmin%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2200f10, 0xffa00f10, "vrsqrts%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3000d00, 0xffa00f10, "vpadd%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3000d10, 0xffa00f10, "vmul%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3000e00, 0xffa00f10, "vcge%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3000e10, 0xffa00f10, "vacge%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3000f00, 0xffa00f10, "vpmax%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3200d00, 0xffa00f10, "vabd%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3200e00, 0xffa00f10, "vcgt%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3200e10, 0xffa00f10, "vacgt%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3200f00, 0xffa00f10, "vpmin%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000800, 0xff800f10, "vadd%c.i%20-21S3\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000810, 0xff800f10, "vtst%c.%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000900, 0xff800f10, "vmla%c.i%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000b00, 0xff800f10, "vqdmulh%c.s%20-21S6\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000b10, 0xff800f10, "vpadd%c.i%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3000800, 0xff800f10, "vsub%c.i%20-21S3\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3000810, 0xff800f10, "vceq%c.i%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3000900, 0xff800f10, "vmls%c.i%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf3000b00, 0xff800f10, "vqrdmulh%c.s%20-21S6\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000000, 0xfe800f10, "vhadd%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000010, 0xfe800f10, "vqadd%c.%24?us%20-21S3\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000100, 0xfe800f10, "vrhadd%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000200, 0xfe800f10, "vhsub%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000210, 0xfe800f10, "vqsub%c.%24?us%20-21S3\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000300, 0xfe800f10, "vcgt%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000310, 0xfe800f10, "vcge%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000400, 0xfe800f10, "vshl%c.%24?us%20-21S3\t%12-15,22R, %0-3,5R, %16-19,7R"},
  {0x00400000, 0xf2000410, 0xfe800f10, "vqshl%c.%24?us%20-21S3\t%12-15,22R, %0-3,5R, %16-19,7R"},
  {0x00400000, 0xf2000500, 0xfe800f10, "vrshl%c.%24?us%20-21S3\t%12-15,22R, %0-3,5R, %16-19,7R"},
  {0x00400000, 0xf2000510, 0xfe800f10, "vqrshl%c.%24?us%20-21S3\t%12-15,22R, %0-3,5R, %16-19,7R"},
  {0x00400000, 0xf2000600, 0xfe800f10, "vmax%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000610, 0xfe800f10, "vmin%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000700, 0xfe800f10, "vabd%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000710, 0xfe800f10, "vaba%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000910, 0xfe800f10, "vmul%c.%24?pi%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000a00, 0xfe800f10, "vpmax%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
  {0x00400000, 0xf2000a10, 0xfe800f10, "vpmin%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},


  {0x00400000, 0xf2800e10, 0xfeb80fb0, "vmov%c.i8\t%12-15,22R, %E"},
  {0x00400000, 0xf2800e30, 0xfeb80fb0, "vmov%c.i64\t%12-15,22R, %E"},
  {0x00400000, 0xf2800f10, 0xfeb80fb0, "vmov%c.f32\t%12-15,22R, %E"},
  {0x00400000, 0xf2800810, 0xfeb80db0, "vmov%c.i16\t%12-15,22R, %E"},
  {0x00400000, 0xf2800830, 0xfeb80db0, "vmvn%c.i16\t%12-15,22R, %E"},
  {0x00400000, 0xf2800910, 0xfeb80db0, "vorr%c.i16\t%12-15,22R, %E"},
  {0x00400000, 0xf2800930, 0xfeb80db0, "vbic%c.i16\t%12-15,22R, %E"},
  {0x00400000, 0xf2800c10, 0xfeb80eb0, "vmov%c.i32\t%12-15,22R, %E"},
  {0x00400000, 0xf2800c30, 0xfeb80eb0, "vmvn%c.i32\t%12-15,22R, %E"},
  {0x00400000, 0xf2800110, 0xfeb809b0, "vorr%c.i32\t%12-15,22R, %E"},
  {0x00400000, 0xf2800130, 0xfeb809b0, "vbic%c.i32\t%12-15,22R, %E"},
  {0x00400000, 0xf2800010, 0xfeb808b0, "vmov%c.i32\t%12-15,22R, %E"},
  {0x00400000, 0xf2800030, 0xfeb808b0, "vmvn%c.i32\t%12-15,22R, %E"},


  {0x00400000, 0xf2880810, 0xffb80fd0, "vshrn%c.i16\t%12-15,22D, %0-3,5Q, #%16-18e"},
  {0x00400000, 0xf2880850, 0xffb80fd0, "vrshrn%c.i16\t%12-15,22D, %0-3,5Q, #%16-18e"},
  {0x00400000, 0xf2880810, 0xfeb80fd0, "vqshrun%c.s16\t%12-15,22D, %0-3,5Q, #%16-18e"},
  {0x00400000, 0xf2880850, 0xfeb80fd0, "vqrshrun%c.s16\t%12-15,22D, %0-3,5Q, #%16-18e"},
  {0x00400000, 0xf2880910, 0xfeb80fd0, "vqshrn%c.%24?us16\t%12-15,22D, %0-3,5Q, #%16-18e"},
  {0x00400000, 0xf2880950, 0xfeb80fd0, "vqrshrn%c.%24?us16\t%12-15,22D, %0-3,5Q, #%16-18e"},
  {0x00400000, 0xf2880a10, 0xfeb80fd0, "vshll%c.%24?us8\t%12-15,22Q, %0-3,5D, #%16-18d"},
  {0x00400000, 0xf2900810, 0xffb00fd0, "vshrn%c.i32\t%12-15,22D, %0-3,5Q, #%16-19e"},
  {0x00400000, 0xf2900850, 0xffb00fd0, "vrshrn%c.i32\t%12-15,22D, %0-3,5Q, #%16-19e"},
  {0x00400000, 0xf2880510, 0xffb80f90, "vshl%c.%24?us8\t%12-15,22R, %0-3,5R, #%16-18d"},
  {0x00400000, 0xf3880410, 0xffb80f90, "vsri%c.8\t%12-15,22R, %0-3,5R, #%16-18e"},
  {0x00400000, 0xf3880510, 0xffb80f90, "vsli%c.8\t%12-15,22R, %0-3,5R, #%16-18d"},
  {0x00400000, 0xf3880610, 0xffb80f90, "vqshlu%c.s8\t%12-15,22R, %0-3,5R, #%16-18d"},
  {0x00400000, 0xf2900810, 0xfeb00fd0, "vqshrun%c.s32\t%12-15,22D, %0-3,5Q, #%16-19e"},
  {0x00400000, 0xf2900850, 0xfeb00fd0, "vqrshrun%c.s32\t%12-15,22D, %0-3,5Q, #%16-19e"},
  {0x00400000, 0xf2900910, 0xfeb00fd0, "vqshrn%c.%24?us32\t%12-15,22D, %0-3,5Q, #%16-19e"},
  {0x00400000, 0xf2900950, 0xfeb00fd0, "vqrshrn%c.%24?us32\t%12-15,22D, %0-3,5Q, #%16-19e"},
  {0x00400000, 0xf2900a10, 0xfeb00fd0, "vshll%c.%24?us16\t%12-15,22Q, %0-3,5D, #%16-19d"},
  {0x00400000, 0xf2880010, 0xfeb80f90, "vshr%c.%24?us8\t%12-15,22R, %0-3,5R, #%16-18e"},
  {0x00400000, 0xf2880110, 0xfeb80f90, "vsra%c.%24?us8\t%12-15,22R, %0-3,5R, #%16-18e"},
  {0x00400000, 0xf2880210, 0xfeb80f90, "vrshr%c.%24?us8\t%12-15,22R, %0-3,5R, #%16-18e"},
  {0x00400000, 0xf2880310, 0xfeb80f90, "vrsra%c.%24?us8\t%12-15,22R, %0-3,5R, #%16-18e"},
  {0x00400000, 0xf2880710, 0xfeb80f90, "vqshl%c.%24?us8\t%12-15,22R, %0-3,5R, #%16-18d"},
  {0x00400000, 0xf2a00810, 0xffa00fd0, "vshrn%c.i64\t%12-15,22D, %0-3,5Q, #%16-20e"},
  {0x00400000, 0xf2a00850, 0xffa00fd0, "vrshrn%c.i64\t%12-15,22D, %0-3,5Q, #%16-20e"},
  {0x00400000, 0xf2900510, 0xffb00f90, "vshl%c.%24?us16\t%12-15,22R, %0-3,5R, #%16-19d"},
  {0x00400000, 0xf3900410, 0xffb00f90, "vsri%c.16\t%12-15,22R, %0-3,5R, #%16-19e"},
  {0x00400000, 0xf3900510, 0xffb00f90, "vsli%c.16\t%12-15,22R, %0-3,5R, #%16-19d"},
  {0x00400000, 0xf3900610, 0xffb00f90, "vqshlu%c.s16\t%12-15,22R, %0-3,5R, #%16-19d"},
  {0x00400000, 0xf2a00a10, 0xfea00fd0, "vshll%c.%24?us32\t%12-15,22Q, %0-3,5D, #%16-20d"},
  {0x00400000, 0xf2900010, 0xfeb00f90, "vshr%c.%24?us16\t%12-15,22R, %0-3,5R, #%16-19e"},
  {0x00400000, 0xf2900110, 0xfeb00f90, "vsra%c.%24?us16\t%12-15,22R, %0-3,5R, #%16-19e"},
  {0x00400000, 0xf2900210, 0xfeb00f90, "vrshr%c.%24?us16\t%12-15,22R, %0-3,5R, #%16-19e"},
  {0x00400000, 0xf2900310, 0xfeb00f90, "vrsra%c.%24?us16\t%12-15,22R, %0-3,5R, #%16-19e"},
  {0x00400000, 0xf2900710, 0xfeb00f90, "vqshl%c.%24?us16\t%12-15,22R, %0-3,5R, #%16-19d"},
  {0x00400000, 0xf2a00810, 0xfea00fd0, "vqshrun%c.s64\t%12-15,22D, %0-3,5Q, #%16-20e"},
  {0x00400000, 0xf2a00850, 0xfea00fd0, "vqrshrun%c.s64\t%12-15,22D, %0-3,5Q, #%16-20e"},
  {0x00400000, 0xf2a00910, 0xfea00fd0, "vqshrn%c.%24?us64\t%12-15,22D, %0-3,5Q, #%16-20e"},
  {0x00400000, 0xf2a00950, 0xfea00fd0, "vqrshrn%c.%24?us64\t%12-15,22D, %0-3,5Q, #%16-20e"},
  {0x00400000, 0xf2a00510, 0xffa00f90, "vshl%c.%24?us32\t%12-15,22R, %0-3,5R, #%16-20d"},
  {0x00400000, 0xf3a00410, 0xffa00f90, "vsri%c.32\t%12-15,22R, %0-3,5R, #%16-20e"},
  {0x00400000, 0xf3a00510, 0xffa00f90, "vsli%c.32\t%12-15,22R, %0-3,5R, #%16-20d"},
  {0x00400000, 0xf3a00610, 0xffa00f90, "vqshlu%c.s32\t%12-15,22R, %0-3,5R, #%16-20d"},
  {0x00400000, 0xf2a00010, 0xfea00f90, "vshr%c.%24?us32\t%12-15,22R, %0-3,5R, #%16-20e"},
  {0x00400000, 0xf2a00110, 0xfea00f90, "vsra%c.%24?us32\t%12-15,22R, %0-3,5R, #%16-20e"},
  {0x00400000, 0xf2a00210, 0xfea00f90, "vrshr%c.%24?us32\t%12-15,22R, %0-3,5R, #%16-20e"},
  {0x00400000, 0xf2a00310, 0xfea00f90, "vrsra%c.%24?us32\t%12-15,22R, %0-3,5R, #%16-20e"},
  {0x00400000, 0xf2a00710, 0xfea00f90, "vqshl%c.%24?us32\t%12-15,22R, %0-3,5R, #%16-20d"},
  {0x00400000, 0xf2800590, 0xff800f90, "vshl%c.%24?us64\t%12-15,22R, %0-3,5R, #%16-21d"},
  {0x00400000, 0xf3800490, 0xff800f90, "vsri%c.64\t%12-15,22R, %0-3,5R, #%16-21e"},
  {0x00400000, 0xf3800590, 0xff800f90, "vsli%c.64\t%12-15,22R, %0-3,5R, #%16-21d"},
  {0x00400000, 0xf3800690, 0xff800f90, "vqshlu%c.s64\t%12-15,22R, %0-3,5R, #%16-21d"},
  {0x00400000, 0xf2800090, 0xfe800f90, "vshr%c.%24?us64\t%12-15,22R, %0-3,5R, #%16-21e"},
  {0x00400000, 0xf2800190, 0xfe800f90, "vsra%c.%24?us64\t%12-15,22R, %0-3,5R, #%16-21e"},
  {0x00400000, 0xf2800290, 0xfe800f90, "vrshr%c.%24?us64\t%12-15,22R, %0-3,5R, #%16-21e"},
  {0x00400000, 0xf2800390, 0xfe800f90, "vrsra%c.%24?us64\t%12-15,22R, %0-3,5R, #%16-21e"},
  {0x00400000, 0xf2800790, 0xfe800f90, "vqshl%c.%24?us64\t%12-15,22R, %0-3,5R, #%16-21d"},
  {0x00400000, 0xf2a00e10, 0xfea00e90, "vcvt%c.%24,8?usff32.%24,8?ffus32\t%12-15,22R, %0-3,5R, #%16-20e"},


  {0x00008000, 0xf2a00e00, 0xfeb00f50, "vmull%c.p64\t%12-15,22Q, %16-19,7D, %0-3,5D"},
  {0x00400000, 0xf2800e00, 0xfea00f50, "vmull%c.p%20S0\t%12-15,22Q, %16-19,7D, %0-3,5D"},
  {0x00400000, 0xf2800400, 0xff800f50, "vaddhn%c.i%20-21T2\t%12-15,22D, %16-19,7Q, %0-3,5Q"},
  {0x00400000, 0xf2800600, 0xff800f50, "vsubhn%c.i%20-21T2\t%12-15,22D, %16-19,7Q, %0-3,5Q"},
  {0x00400000, 0xf2800900, 0xff800f50, "vqdmlal%c.s%20-21S6\t%12-15,22Q, %16-19,7D, %0-3,5D"},
  {0x00400000, 0xf2800b00, 0xff800f50, "vqdmlsl%c.s%20-21S6\t%12-15,22Q, %16-19,7D, %0-3,5D"},
  {0x00400000, 0xf2800d00, 0xff800f50, "vqdmull%c.s%20-21S6\t%12-15,22Q, %16-19,7D, %0-3,5D"},
  {0x00400000, 0xf3800400, 0xff800f50, "vraddhn%c.i%20-21T2\t%12-15,22D, %16-19,7Q, %0-3,5Q"},
  {0x00400000, 0xf3800600, 0xff800f50, "vrsubhn%c.i%20-21T2\t%12-15,22D, %16-19,7Q, %0-3,5Q"},
  {0x00400000, 0xf2800000, 0xfe800f50, "vaddl%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7D, %0-3,5D"},
  {0x00400000, 0xf2800100, 0xfe800f50, "vaddw%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7Q, %0-3,5D"},
  {0x00400000, 0xf2800200, 0xfe800f50, "vsubl%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7D, %0-3,5D"},
  {0x00400000, 0xf2800300, 0xfe800f50, "vsubw%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7Q, %0-3,5D"},
  {0x00400000, 0xf2800500, 0xfe800f50, "vabal%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7D, %0-3,5D"},
  {0x00400000, 0xf2800700, 0xfe800f50, "vabdl%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7D, %0-3,5D"},
  {0x00400000, 0xf2800800, 0xfe800f50, "vmlal%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7D, %0-3,5D"},
  {0x00400000, 0xf2800a00, 0xfe800f50, "vmlsl%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7D, %0-3,5D"},
  {0x00400000, 0xf2800c00, 0xfe800f50, "vmull%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7D, %0-3,5D"},


  {0x00400000, 0xf2800040, 0xff800f50, "vmla%c.i%20-21S6\t%12-15,22D, %16-19,7D, %D"},
  {0x00400000, 0xf2800140, 0xff800f50, "vmla%c.f%20-21Sa\t%12-15,22D, %16-19,7D, %D"},
  {0x00400000, 0xf2800340, 0xff800f50, "vqdmlal%c.s%20-21S6\t%12-15,22Q, %16-19,7D, %D"},
  {0x00400000, 0xf2800440, 0xff800f50, "vmls%c.i%20-21S6\t%12-15,22D, %16-19,7D, %D"},
  {0x00400000, 0xf2800540, 0xff800f50, "vmls%c.f%20-21S6\t%12-15,22D, %16-19,7D, %D"},
  {0x00400000, 0xf2800740, 0xff800f50, "vqdmlsl%c.s%20-21S6\t%12-15,22Q, %16-19,7D, %D"},
  {0x00400000, 0xf2800840, 0xff800f50, "vmul%c.i%20-21S6\t%12-15,22D, %16-19,7D, %D"},
  {0x00400000, 0xf2800940, 0xff800f50, "vmul%c.f%20-21Sa\t%12-15,22D, %16-19,7D, %D"},
  {0x00400000, 0xf2800b40, 0xff800f50, "vqdmull%c.s%20-21S6\t%12-15,22Q, %16-19,7D, %D"},
  {0x00400000, 0xf2800c40, 0xff800f50, "vqdmulh%c.s%20-21S6\t%12-15,22D, %16-19,7D, %D"},
  {0x00400000, 0xf2800d40, 0xff800f50, "vqrdmulh%c.s%20-21S6\t%12-15,22D, %16-19,7D, %D"},
  {0x00400000, 0xf3800040, 0xff800f50, "vmla%c.i%20-21S6\t%12-15,22Q, %16-19,7Q, %D"},
  {0x00400000, 0xf3800140, 0xff800f50, "vmla%c.f%20-21Sa\t%12-15,22Q, %16-19,7Q, %D"},
  {0x00400000, 0xf3800440, 0xff800f50, "vmls%c.i%20-21S6\t%12-15,22Q, %16-19,7Q, %D"},
  {0x00400000, 0xf3800540, 0xff800f50, "vmls%c.f%20-21Sa\t%12-15,22Q, %16-19,7Q, %D"},
  {0x00400000, 0xf3800840, 0xff800f50, "vmul%c.i%20-21S6\t%12-15,22Q, %16-19,7Q, %D"},
  {0x00400000, 0xf3800940, 0xff800f50, "vmul%c.f%20-21Sa\t%12-15,22Q, %16-19,7Q, %D"},
  {0x00400000, 0xf3800c40, 0xff800f50, "vqdmulh%c.s%20-21S6\t%12-15,22Q, %16-19,7Q, %D"},
  {0x00400000, 0xf3800d40, 0xff800f50, "vqrdmulh%c.s%20-21S6\t%12-15,22Q, %16-19,7Q, %D"},
  {0x00400000, 0xf2800240, 0xfe800f50, "vmlal%c.%24?us%20-21S6\t%12-15,22Q, %16-19,7D, %D"},
  {0x00400000, 0xf2800640, 0xfe800f50, "vmlsl%c.%24?us%20-21S6\t%12-15,22Q, %16-19,7D, %D"},
  {0x00400000, 0xf2800a40, 0xfe800f50, "vmull%c.%24?us%20-21S6\t%12-15,22Q, %16-19,7D, %D"},


  {0x00400000, 0xf4a00fc0, 0xffb00fc0, "vld4%c.32\t%C"},
  {0x00400000, 0xf4a00c00, 0xffb00f00, "vld1%c.%6-7S2\t%C"},
  {0x00400000, 0xf4a00d00, 0xffb00f00, "vld2%c.%6-7S2\t%C"},
  {0x00400000, 0xf4a00e00, 0xffb00f00, "vld3%c.%6-7S2\t%C"},
  {0x00400000, 0xf4a00f00, 0xffb00f00, "vld4%c.%6-7S2\t%C"},
  {0x00400000, 0xf4000200, 0xff900f00, "v%21?ls%21?dt1%c.%6-7S3\t%A"},
  {0x00400000, 0xf4000300, 0xff900f00, "v%21?ls%21?dt2%c.%6-7S2\t%A"},
  {0x00400000, 0xf4000400, 0xff900f00, "v%21?ls%21?dt3%c.%6-7S2\t%A"},
  {0x00400000, 0xf4000500, 0xff900f00, "v%21?ls%21?dt3%c.%6-7S2\t%A"},
  {0x00400000, 0xf4000600, 0xff900f00, "v%21?ls%21?dt1%c.%6-7S3\t%A"},
  {0x00400000, 0xf4000700, 0xff900f00, "v%21?ls%21?dt1%c.%6-7S3\t%A"},
  {0x00400000, 0xf4000800, 0xff900f00, "v%21?ls%21?dt2%c.%6-7S2\t%A"},
  {0x00400000, 0xf4000900, 0xff900f00, "v%21?ls%21?dt2%c.%6-7S2\t%A"},
  {0x00400000, 0xf4000a00, 0xff900f00, "v%21?ls%21?dt1%c.%6-7S3\t%A"},
  {0x00400000, 0xf4000000, 0xff900e00, "v%21?ls%21?dt4%c.%6-7S2\t%A"},
  {0x00400000, 0xf4800000, 0xff900300, "v%21?ls%21?dt1%c.%10-11S2\t%B"},
  {0x00400000, 0xf4800100, 0xff900300, "v%21?ls%21?dt2%c.%10-11S2\t%B"},
  {0x00400000, 0xf4800200, 0xff900300, "v%21?ls%21?dt3%c.%10-11S2\t%B"},
  {0x00400000, 0xf4800300, 0xff900300, "v%21?ls%21?dt4%c.%10-11S2\t%B"},

  {0,0 ,0, 0}
};
static const struct opcode32 arm_opcodes[] =
{

  {0x00000001, 0xe1a00000, 0xffffffff, "nop\t\t\t; (mov r0, r0)"},
  {0x00000001, 0xe7f000f0, 0xfff000f0, "udf\t#%e"},

  {0x00000040 | 0x00000080, 0x012FFF10, 0x0ffffff0, "bx%c\t%0-3r"},
  {0x00000002, 0x00000090, 0x0fe000f0, "mul%20's%c\t%16-19R, %0-3R, %8-11R"},
  {0x00000002, 0x00200090, 0x0fe000f0, "mla%20's%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
  {0x00000004, 0x01000090, 0x0fb00ff0, "swp%22'b%c\t%12-15RU, %0-3Ru, [%16-19RuU]"},
  {0x00000010, 0x00800090, 0x0fa000f0, "%22?sumull%20's%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
  {0x00000010, 0x00a00090, 0x0fa000f0, "%22?sumlal%20's%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},


  {0x00004000, 0x0320f005, 0x0fffffff, "sevl"},
  {0x00004000, 0xe1000070, 0xfff000f0, "hlt\t0x%16-19X%12-15X%8-11X%0-3X"},
  {0x00004000, 0x01800e90, 0x0ff00ff0, "stlex%c\t%12-15r, %0-3r, [%16-19R]"},
  {0x00004000, 0x01900e9f, 0x0ff00fff, "ldaex%c\t%12-15r, [%16-19R]"},
  {0x00004000, 0x01a00e90, 0x0ff00ff0, "stlexd%c\t%12-15r, %0-3r, %0-3T, [%16-19R]"},
  {0x00004000, 0x01b00e9f, 0x0ff00fff, "ldaexd%c\t%12-15r, %12-15T, [%16-19R]"},
  {0x00004000, 0x01c00e90, 0x0ff00ff0, "stlexb%c\t%12-15r, %0-3r, [%16-19R]"},
  {0x00004000, 0x01d00e9f, 0x0ff00fff, "ldaexb%c\t%12-15r, [%16-19R]"},
  {0x00004000, 0x01e00e90, 0x0ff00ff0, "stlexh%c\t%12-15r, %0-3r, [%16-19R]"},
  {0x00004000, 0x01f00e9f, 0x0ff00fff, "ldaexh%c\t%12-15r, [%16-19R]"},
  {0x00004000, 0x0180fc90, 0x0ff0fff0, "stl%c\t%0-3r, [%16-19R]"},
  {0x00004000, 0x01900c9f, 0x0ff00fff, "lda%c\t%12-15r, [%16-19R]"},
  {0x00004000, 0x01c0fc90, 0x0ff0fff0, "stlb%c\t%0-3r, [%16-19R]"},
  {0x00004000, 0x01d00c9f, 0x0ff00fff, "ldab%c\t%12-15r, [%16-19R]"},
  {0x00004000, 0x01e0fc90, 0x0ff0fff0, "stlh%c\t%0-3r, [%16-19R]"},
  {0x00004000, 0x01f00c9f, 0x0ff00fff, "ldaexh%c\t%12-15r, [%16-19R]"},

  {0x00004000, 0xe1000040, 0xfff00ff0, "crc32b\t%12-15R, %16-19R, %0-3R"},
  {0x00004000, 0xe1200040, 0xfff00ff0, "crc32h\t%12-15R, %16-19R, %0-3R"},
  {0x00004000, 0xe1400040, 0xfff00ff0, "crc32w\t%12-15R, %16-19R, %0-3R"},
  {0x00004000, 0xe1000240, 0xfff00ff0, "crc32cb\t%12-15R, %16-19R, %0-3R"},
  {0x00004000, 0xe1200240, 0xfff00ff0, "crc32ch\t%12-15R, %16-19R, %0-3R"},
  {0x00004000, 0xe1400240, 0xfff00ff0, "crc32cw\t%12-15R, %16-19R, %0-3R"},


  {0x80000000, 0x0160006e, 0x0fffffff, "eret%c"},
  {0x80000000, 0x01400070, 0x0ff000f0, "hvc%c\t%e"},


  {0x40000000, 0x0710f010, 0x0ff0f0f0, "sdiv%c\t%16-19r, %0-3r, %8-11r"},
  {0x40000000, 0x0730f010, 0x0ff0f0f0, "udiv%c\t%16-19r, %0-3r, %8-11r"},


  {0x08000000, 0xf410f000, 0xfc70f000, "pldw\t%a"},


  {0x00080000, 0xf450f000, 0xfd70f000, "pli\t%P"},
  {0x00080000, 0x0320f0f0, 0x0ffffff0, "dbg%c\t#%0-3d"},
  {0x00004000, 0xf57ff051, 0xfffffff3, "dmb\t%U"},
  {0x00004000, 0xf57ff041, 0xfffffff3, "dsb\t%U"},
  {0x00080000, 0xf57ff050, 0xfffffff0, "dmb\t%U"},
  {0x00080000, 0xf57ff040, 0xfffffff0, "dsb\t%U"},
  {0x00080000, 0xf57ff060, 0xfffffff0, "isb\t%U"},


  {0x00008000, 0x07c0001f, 0x0fe0007f, "bfc%c\t%12-15R, %E"},
  {0x00008000, 0x07c00010, 0x0fe00070, "bfi%c\t%12-15R, %0-3r, %E"},
  {0x00008000, 0x00600090, 0x0ff000f0, "mls%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
  {0x00008000, 0x002000b0, 0x0f3000f0, "strht%c\t%12-15R, %S"},

  {0x00008000, 0x00300090, 0x0f3000f0, "\t\t; <UNDEFINED> instruction: %0-31x" },
  {0x00008000, 0x00300090, 0x0f300090, "ldr%6's%5?hbt%c\t%12-15R, %S"},

  {0x00008000, 0x03000000, 0x0ff00000, "movw%c\t%12-15R, %V"},
  {0x00008000, 0x03400000, 0x0ff00000, "movt%c\t%12-15R, %V"},
  {0x00008000, 0x06ff0f30, 0x0fff0ff0, "rbit%c\t%12-15R, %0-3R"},
  {0x00008000, 0x07a00050, 0x0fa00070, "%22?usbfx%c\t%12-15r, %0-3r, #%7-11d, #%16-20W"},


  {0x10000000, 0x01600070, 0x0ff000f0, "smc%c\t%e"},


  {0x00002000, 0xf57ff01f, 0xffffffff, "clrex"},
  {0x00002000, 0x01d00f9f, 0x0ff00fff, "ldrexb%c\t%12-15R, [%16-19R]"},
  {0x00002000, 0x01b00f9f, 0x0ff00fff, "ldrexd%c\t%12-15r, [%16-19R]"},
  {0x00002000, 0x01f00f9f, 0x0ff00fff, "ldrexh%c\t%12-15R, [%16-19R]"},
  {0x00002000, 0x01c00f90, 0x0ff00ff0, "strexb%c\t%12-15R, %0-3R, [%16-19R]"},
  {0x00002000, 0x01a00f90, 0x0ff00ff0, "strexd%c\t%12-15R, %0-3r, [%16-19R]"},
  {0x00002000, 0x01e00f90, 0x0ff00ff0, "strexh%c\t%12-15R, %0-3R, [%16-19R]"},


  {0x00002000, 0x0320f001, 0x0fffffff, "yield%c"},
  {0x00002000, 0x0320f002, 0x0fffffff, "wfe%c"},
  {0x00002000, 0x0320f003, 0x0fffffff, "wfi%c"},
  {0x00002000, 0x0320f004, 0x0fffffff, "sev%c"},
  {0x00002000, 0x0320f000, 0x0fffff00, "nop%c\t{%0-7d}"},


  {0x00001000, 0xf1080000, 0xfffffe3f, "cpsie\t%8'a%7'i%6'f"},
  {0x00001000, 0xf10a0000, 0xfffffe20, "cpsie\t%8'a%7'i%6'f,#%0-4d"},
  {0x00001000, 0xf10C0000, 0xfffffe3f, "cpsid\t%8'a%7'i%6'f"},
  {0x00001000, 0xf10e0000, 0xfffffe20, "cpsid\t%8'a%7'i%6'f,#%0-4d"},
  {0x00001000, 0xf1000000, 0xfff1fe20, "cps\t#%0-4d"},
  {0x00001000, 0x06800010, 0x0ff00ff0, "pkhbt%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06800010, 0x0ff00070, "pkhbt%c\t%12-15R, %16-19R, %0-3R, lsl #%7-11d"},
  {0x00001000, 0x06800050, 0x0ff00ff0, "pkhtb%c\t%12-15R, %16-19R, %0-3R, asr #32"},
  {0x00001000, 0x06800050, 0x0ff00070, "pkhtb%c\t%12-15R, %16-19R, %0-3R, asr #%7-11d"},
  {0x00001000, 0x01900f9f, 0x0ff00fff, "ldrex%c\tr%12-15d, [%16-19R]"},
  {0x00001000, 0x06200f10, 0x0ff00ff0, "qadd16%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06200f90, 0x0ff00ff0, "qadd8%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06200f30, 0x0ff00ff0, "qasx%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06200f70, 0x0ff00ff0, "qsub16%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06200ff0, 0x0ff00ff0, "qsub8%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06200f50, 0x0ff00ff0, "qsax%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06100f10, 0x0ff00ff0, "sadd16%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06100f90, 0x0ff00ff0, "sadd8%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06100f30, 0x0ff00ff0, "sasx%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06300f10, 0x0ff00ff0, "shadd16%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06300f90, 0x0ff00ff0, "shadd8%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06300f30, 0x0ff00ff0, "shasx%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06300f70, 0x0ff00ff0, "shsub16%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06300ff0, 0x0ff00ff0, "shsub8%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06300f50, 0x0ff00ff0, "shsax%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06100f70, 0x0ff00ff0, "ssub16%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06100ff0, 0x0ff00ff0, "ssub8%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06100f50, 0x0ff00ff0, "ssax%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06500f10, 0x0ff00ff0, "uadd16%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06500f90, 0x0ff00ff0, "uadd8%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06500f30, 0x0ff00ff0, "uasx%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06700f10, 0x0ff00ff0, "uhadd16%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06700f90, 0x0ff00ff0, "uhadd8%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06700f30, 0x0ff00ff0, "uhasx%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06700f70, 0x0ff00ff0, "uhsub16%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06700ff0, 0x0ff00ff0, "uhsub8%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06700f50, 0x0ff00ff0, "uhsax%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06600f10, 0x0ff00ff0, "uqadd16%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06600f90, 0x0ff00ff0, "uqadd8%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06600f30, 0x0ff00ff0, "uqasx%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06600f70, 0x0ff00ff0, "uqsub16%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06600ff0, 0x0ff00ff0, "uqsub8%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06600f50, 0x0ff00ff0, "uqsax%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06500f70, 0x0ff00ff0, "usub16%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06500ff0, 0x0ff00ff0, "usub8%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06500f50, 0x0ff00ff0, "usax%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0x06bf0f30, 0x0fff0ff0, "rev%c\t%12-15R, %0-3R"},
  {0x00001000, 0x06bf0fb0, 0x0fff0ff0, "rev16%c\t%12-15R, %0-3R"},
  {0x00001000, 0x06ff0fb0, 0x0fff0ff0, "revsh%c\t%12-15R, %0-3R"},
  {0x00001000, 0xf8100a00, 0xfe50ffff, "rfe%23?id%24?ba\t%16-19r%21'!"},
  {0x00001000, 0x06bf0070, 0x0fff0ff0, "sxth%c\t%12-15R, %0-3R"},
  {0x00001000, 0x06bf0470, 0x0fff0ff0, "sxth%c\t%12-15R, %0-3R, ror #8"},
  {0x00001000, 0x06bf0870, 0x0fff0ff0, "sxth%c\t%12-15R, %0-3R, ror #16"},
  {0x00001000, 0x06bf0c70, 0x0fff0ff0, "sxth%c\t%12-15R, %0-3R, ror #24"},
  {0x00001000, 0x068f0070, 0x0fff0ff0, "sxtb16%c\t%12-15R, %0-3R"},
  {0x00001000, 0x068f0470, 0x0fff0ff0, "sxtb16%c\t%12-15R, %0-3R, ror #8"},
  {0x00001000, 0x068f0870, 0x0fff0ff0, "sxtb16%c\t%12-15R, %0-3R, ror #16"},
  {0x00001000, 0x068f0c70, 0x0fff0ff0, "sxtb16%c\t%12-15R, %0-3R, ror #24"},
  {0x00001000, 0x06af0070, 0x0fff0ff0, "sxtb%c\t%12-15R, %0-3R"},
  {0x00001000, 0x06af0470, 0x0fff0ff0, "sxtb%c\t%12-15R, %0-3R, ror #8"},
  {0x00001000, 0x06af0870, 0x0fff0ff0, "sxtb%c\t%12-15R, %0-3R, ror #16"},
  {0x00001000, 0x06af0c70, 0x0fff0ff0, "sxtb%c\t%12-15R, %0-3R, ror #24"},
  {0x00001000, 0x06ff0070, 0x0fff0ff0, "uxth%c\t%12-15R, %0-3R"},
  {0x00001000, 0x06ff0470, 0x0fff0ff0, "uxth%c\t%12-15R, %0-3R, ror #8"},
  {0x00001000, 0x06ff0870, 0x0fff0ff0, "uxth%c\t%12-15R, %0-3R, ror #16"},
  {0x00001000, 0x06ff0c70, 0x0fff0ff0, "uxth%c\t%12-15R, %0-3R, ror #24"},
  {0x00001000, 0x06cf0070, 0x0fff0ff0, "uxtb16%c\t%12-15R, %0-3R"},
  {0x00001000, 0x06cf0470, 0x0fff0ff0, "uxtb16%c\t%12-15R, %0-3R, ror #8"},
  {0x00001000, 0x06cf0870, 0x0fff0ff0, "uxtb16%c\t%12-15R, %0-3R, ror #16"},
  {0x00001000, 0x06cf0c70, 0x0fff0ff0, "uxtb16%c\t%12-15R, %0-3R, ror #24"},
  {0x00001000, 0x06ef0070, 0x0fff0ff0, "uxtb%c\t%12-15R, %0-3R"},
  {0x00001000, 0x06ef0470, 0x0fff0ff0, "uxtb%c\t%12-15R, %0-3R, ror #8"},
  {0x00001000, 0x06ef0870, 0x0fff0ff0, "uxtb%c\t%12-15R, %0-3R, ror #16"},
  {0x00001000, 0x06ef0c70, 0x0fff0ff0, "uxtb%c\t%12-15R, %0-3R, ror #24"},
  {0x00001000, 0x06b00070, 0x0ff00ff0, "sxtah%c\t%12-15R, %16-19r, %0-3R"},
  {0x00001000, 0x06b00470, 0x0ff00ff0, "sxtah%c\t%12-15R, %16-19r, %0-3R, ror #8"},
  {0x00001000, 0x06b00870, 0x0ff00ff0, "sxtah%c\t%12-15R, %16-19r, %0-3R, ror #16"},
  {0x00001000, 0x06b00c70, 0x0ff00ff0, "sxtah%c\t%12-15R, %16-19r, %0-3R, ror #24"},
  {0x00001000, 0x06800070, 0x0ff00ff0, "sxtab16%c\t%12-15R, %16-19r, %0-3R"},
  {0x00001000, 0x06800470, 0x0ff00ff0, "sxtab16%c\t%12-15R, %16-19r, %0-3R, ror #8"},
  {0x00001000, 0x06800870, 0x0ff00ff0, "sxtab16%c\t%12-15R, %16-19r, %0-3R, ror #16"},
  {0x00001000, 0x06800c70, 0x0ff00ff0, "sxtab16%c\t%12-15R, %16-19r, %0-3R, ror #24"},
  {0x00001000, 0x06a00070, 0x0ff00ff0, "sxtab%c\t%12-15R, %16-19r, %0-3R"},
  {0x00001000, 0x06a00470, 0x0ff00ff0, "sxtab%c\t%12-15R, %16-19r, %0-3R, ror #8"},
  {0x00001000, 0x06a00870, 0x0ff00ff0, "sxtab%c\t%12-15R, %16-19r, %0-3R, ror #16"},
  {0x00001000, 0x06a00c70, 0x0ff00ff0, "sxtab%c\t%12-15R, %16-19r, %0-3R, ror #24"},
  {0x00001000, 0x06f00070, 0x0ff00ff0, "uxtah%c\t%12-15R, %16-19r, %0-3R"},
  {0x00001000, 0x06f00470, 0x0ff00ff0, "uxtah%c\t%12-15R, %16-19r, %0-3R, ror #8"},
  {0x00001000, 0x06f00870, 0x0ff00ff0, "uxtah%c\t%12-15R, %16-19r, %0-3R, ror #16"},
  {0x00001000, 0x06f00c70, 0x0ff00ff0, "uxtah%c\t%12-15R, %16-19r, %0-3R, ror #24"},
  {0x00001000, 0x06c00070, 0x0ff00ff0, "uxtab16%c\t%12-15R, %16-19r, %0-3R"},
  {0x00001000, 0x06c00470, 0x0ff00ff0, "uxtab16%c\t%12-15R, %16-19r, %0-3R, ror #8"},
  {0x00001000, 0x06c00870, 0x0ff00ff0, "uxtab16%c\t%12-15R, %16-19r, %0-3R, ror #16"},
  {0x00001000, 0x06c00c70, 0x0ff00ff0, "uxtab16%c\t%12-15R, %16-19r, %0-3R, ROR #24"},
  {0x00001000, 0x06e00070, 0x0ff00ff0, "uxtab%c\t%12-15R, %16-19r, %0-3R"},
  {0x00001000, 0x06e00470, 0x0ff00ff0, "uxtab%c\t%12-15R, %16-19r, %0-3R, ror #8"},
  {0x00001000, 0x06e00870, 0x0ff00ff0, "uxtab%c\t%12-15R, %16-19r, %0-3R, ror #16"},
  {0x00001000, 0x06e00c70, 0x0ff00ff0, "uxtab%c\t%12-15R, %16-19r, %0-3R, ror #24"},
  {0x00001000, 0x06800fb0, 0x0ff00ff0, "sel%c\t%12-15R, %16-19R, %0-3R"},
  {0x00001000, 0xf1010000, 0xfffffc00, "setend\t%9?ble"},
  {0x00001000, 0x0700f010, 0x0ff0f0d0, "smuad%5'x%c\t%16-19R, %0-3R, %8-11R"},
  {0x00001000, 0x0700f050, 0x0ff0f0d0, "smusd%5'x%c\t%16-19R, %0-3R, %8-11R"},
  {0x00001000, 0x07000010, 0x0ff000d0, "smlad%5'x%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
  {0x00001000, 0x07400010, 0x0ff000d0, "smlald%5'x%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
  {0x00001000, 0x07000050, 0x0ff000d0, "smlsd%5'x%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
  {0x00001000, 0x07400050, 0x0ff000d0, "smlsld%5'x%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
  {0x00001000, 0x0750f010, 0x0ff0f0d0, "smmul%5'r%c\t%16-19R, %0-3R, %8-11R"},
  {0x00001000, 0x07500010, 0x0ff000d0, "smmla%5'r%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
  {0x00001000, 0x075000d0, 0x0ff000d0, "smmls%5'r%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
  {0x00001000, 0xf84d0500, 0xfe5fffe0, "srs%23?id%24?ba\t%16-19r%21'!, #%0-4d"},
  {0x00001000, 0x06a00010, 0x0fe00ff0, "ssat%c\t%12-15R, #%16-20W, %0-3R"},
  {0x00001000, 0x06a00010, 0x0fe00070, "ssat%c\t%12-15R, #%16-20W, %0-3R, lsl #%7-11d"},
  {0x00001000, 0x06a00050, 0x0fe00070, "ssat%c\t%12-15R, #%16-20W, %0-3R, asr #%7-11d"},
  {0x00001000, 0x06a00f30, 0x0ff00ff0, "ssat16%c\t%12-15r, #%16-19W, %0-3r"},
  {0x00001000, 0x01800f90, 0x0ff00ff0, "strex%c\t%12-15R, %0-3R, [%16-19R]"},
  {0x00001000, 0x00400090, 0x0ff000f0, "umaal%c\t%12-15R, %16-19R, %0-3R, %8-11R"},
  {0x00001000, 0x0780f010, 0x0ff0f0f0, "usad8%c\t%16-19R, %0-3R, %8-11R"},
  {0x00001000, 0x07800010, 0x0ff000f0, "usada8%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
  {0x00001000, 0x06e00010, 0x0fe00ff0, "usat%c\t%12-15R, #%16-20d, %0-3R"},
  {0x00001000, 0x06e00010, 0x0fe00070, "usat%c\t%12-15R, #%16-20d, %0-3R, lsl #%7-11d"},
  {0x00001000, 0x06e00050, 0x0fe00070, "usat%c\t%12-15R, #%16-20d, %0-3R, asr #%7-11d"},
  {0x00001000, 0x06e00f30, 0x0ff00ff0, "usat16%c\t%12-15R, #%16-19d, %0-3R"},


  {0x00000800, 0x012fff20, 0x0ffffff0, "bxj%c\t%0-3R"},


  {0x00000080, 0xe1200070, 0xfff000f0, "bkpt\t0x%16-19X%12-15X%8-11X%0-3X"},
  {0x00000080, 0xfa000000, 0xfe000000, "blx\t%B"},
  {0x00000080, 0x012fff30, 0x0ffffff0, "blx%c\t%0-3R"},
  {0x00000080, 0x016f0f10, 0x0fff0ff0, "clz%c\t%12-15R, %0-3R"},


  {0x00000400, 0x000000d0, 0x0e1000f0, "ldrd%c\t%12-15r, %s"},
  {0x00000400, 0x000000f0, 0x0e1000f0, "strd%c\t%12-15r, %s"},
  {0x00000400, 0xf450f000, 0xfc70f000, "pld\t%a"},
  {0x00000200, 0x01000080, 0x0ff000f0, "smlabb%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
  {0x00000200, 0x010000a0, 0x0ff000f0, "smlatb%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
  {0x00000200, 0x010000c0, 0x0ff000f0, "smlabt%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
  {0x00000200, 0x010000e0, 0x0ff000f0, "smlatt%c\t%16-19r, %0-3r, %8-11R, %12-15R"},

  {0x00000200, 0x01200080, 0x0ff000f0, "smlawb%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
  {0x00000200, 0x012000c0, 0x0ff000f0, "smlawt%c\t%16-19R, %0-3r, %8-11R, %12-15R"},

  {0x00000200, 0x01400080, 0x0ff000f0, "smlalbb%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
  {0x00000200, 0x014000a0, 0x0ff000f0, "smlaltb%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
  {0x00000200, 0x014000c0, 0x0ff000f0, "smlalbt%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
  {0x00000200, 0x014000e0, 0x0ff000f0, "smlaltt%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},

  {0x00000200, 0x01600080, 0x0ff0f0f0, "smulbb%c\t%16-19R, %0-3R, %8-11R"},
  {0x00000200, 0x016000a0, 0x0ff0f0f0, "smultb%c\t%16-19R, %0-3R, %8-11R"},
  {0x00000200, 0x016000c0, 0x0ff0f0f0, "smulbt%c\t%16-19R, %0-3R, %8-11R"},
  {0x00000200, 0x016000e0, 0x0ff0f0f0, "smultt%c\t%16-19R, %0-3R, %8-11R"},

  {0x00000200, 0x012000a0, 0x0ff0f0f0, "smulwb%c\t%16-19R, %0-3R, %8-11R"},
  {0x00000200, 0x012000e0, 0x0ff0f0f0, "smulwt%c\t%16-19R, %0-3R, %8-11R"},

  {0x00000200, 0x01000050, 0x0ff00ff0, "qadd%c\t%12-15R, %0-3R, %16-19R"},
  {0x00000200, 0x01400050, 0x0ff00ff0, "qdadd%c\t%12-15R, %0-3R, %16-19R"},
  {0x00000200, 0x01200050, 0x0ff00ff0, "qsub%c\t%12-15R, %0-3R, %16-19R"},
  {0x00000200, 0x01600050, 0x0ff00ff0, "qdsub%c\t%12-15R, %0-3R, %16-19R"},


  {0x00000001, 0x052d0004, 0x0fff0fff, "push%c\t{%12-15r}\t\t; (str%c %12-15r, %a)"},

  {0x00000001, 0x04400000, 0x0e500000, "strb%t%c\t%12-15R, %a"},
  {0x00000001, 0x04000000, 0x0e500000, "str%t%c\t%12-15r, %a"},
  {0x00000001, 0x06400000, 0x0e500ff0, "strb%t%c\t%12-15R, %a"},
  {0x00000001, 0x06000000, 0x0e500ff0, "str%t%c\t%12-15r, %a"},
  {0x00000001, 0x04400000, 0x0c500010, "strb%t%c\t%12-15R, %a"},
  {0x00000001, 0x04000000, 0x0c500010, "str%t%c\t%12-15r, %a"},

  {0x00000001, 0x04400000, 0x0e500000, "strb%c\t%12-15R, %a"},
  {0x00000001, 0x06400000, 0x0e500010, "strb%c\t%12-15R, %a"},
  {0x00000001, 0x004000b0, 0x0e5000f0, "strh%c\t%12-15R, %s"},
  {0x00000001, 0x000000b0, 0x0e500ff0, "strh%c\t%12-15R, %s"},

  {0x00000001, 0x00500090, 0x0e5000f0, "\t\t; <UNDEFINED> instruction: %0-31x"},
  {0x00000001, 0x00500090, 0x0e500090, "ldr%6's%5?hb%c\t%12-15R, %s"},
  {0x00000001, 0x00100090, 0x0e500ff0, "\t\t; <UNDEFINED> instruction: %0-31x"},
  {0x00000001, 0x00100090, 0x0e500f90, "ldr%6's%5?hb%c\t%12-15R, %s"},

  {0x00000001, 0x02000000, 0x0fe00000, "and%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x00000000, 0x0fe00010, "and%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x00000010, 0x0fe00090, "and%20's%c\t%12-15R, %16-19R, %o"},

  {0x00000001, 0x02200000, 0x0fe00000, "eor%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x00200000, 0x0fe00010, "eor%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x00200010, 0x0fe00090, "eor%20's%c\t%12-15R, %16-19R, %o"},

  {0x00000001, 0x02400000, 0x0fe00000, "sub%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x00400000, 0x0fe00010, "sub%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x00400010, 0x0fe00090, "sub%20's%c\t%12-15R, %16-19R, %o"},

  {0x00000001, 0x02600000, 0x0fe00000, "rsb%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x00600000, 0x0fe00010, "rsb%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x00600010, 0x0fe00090, "rsb%20's%c\t%12-15R, %16-19R, %o"},

  {0x00000001, 0x02800000, 0x0fe00000, "add%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x00800000, 0x0fe00010, "add%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x00800010, 0x0fe00090, "add%20's%c\t%12-15R, %16-19R, %o"},

  {0x00000001, 0x02a00000, 0x0fe00000, "adc%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x00a00000, 0x0fe00010, "adc%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x00a00010, 0x0fe00090, "adc%20's%c\t%12-15R, %16-19R, %o"},

  {0x00000001, 0x02c00000, 0x0fe00000, "sbc%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x00c00000, 0x0fe00010, "sbc%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x00c00010, 0x0fe00090, "sbc%20's%c\t%12-15R, %16-19R, %o"},

  {0x00000001, 0x02e00000, 0x0fe00000, "rsc%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x00e00000, 0x0fe00010, "rsc%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x00e00010, 0x0fe00090, "rsc%20's%c\t%12-15R, %16-19R, %o"},

  {0x80000000, 0x0120f200, 0x0fb0f200, "msr%c\t%C, %0-3r"},
  {0x00000008, 0x0120f000, 0x0db0f000, "msr%c\t%C, %o"},
  {0x00000008, 0x01000000, 0x0fb00cff, "mrs%c\t%12-15R, %R"},

  {0x00000001, 0x03000000, 0x0fe00000, "tst%p%c\t%16-19r, %o"},
  {0x00000001, 0x01000000, 0x0fe00010, "tst%p%c\t%16-19r, %o"},
  {0x00000001, 0x01000010, 0x0fe00090, "tst%p%c\t%16-19R, %o"},

  {0x00000001, 0x03200000, 0x0fe00000, "teq%p%c\t%16-19r, %o"},
  {0x00000001, 0x01200000, 0x0fe00010, "teq%p%c\t%16-19r, %o"},
  {0x00000001, 0x01200010, 0x0fe00090, "teq%p%c\t%16-19R, %o"},

  {0x00000001, 0x03400000, 0x0fe00000, "cmp%p%c\t%16-19r, %o"},
  {0x00000001, 0x01400000, 0x0fe00010, "cmp%p%c\t%16-19r, %o"},
  {0x00000001, 0x01400010, 0x0fe00090, "cmp%p%c\t%16-19R, %o"},

  {0x00000001, 0x03600000, 0x0fe00000, "cmn%p%c\t%16-19r, %o"},
  {0x00000001, 0x01600000, 0x0fe00010, "cmn%p%c\t%16-19r, %o"},
  {0x00000001, 0x01600010, 0x0fe00090, "cmn%p%c\t%16-19R, %o"},

  {0x00000001, 0x03800000, 0x0fe00000, "orr%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x01800000, 0x0fe00010, "orr%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x01800010, 0x0fe00090, "orr%20's%c\t%12-15R, %16-19R, %o"},

  {0x00000001, 0x03a00000, 0x0fef0000, "mov%20's%c\t%12-15r, %o"},
  {0x00000001, 0x01a00000, 0x0def0ff0, "mov%20's%c\t%12-15r, %0-3r"},
  {0x00000001, 0x01a00000, 0x0def0060, "lsl%20's%c\t%12-15R, %q"},
  {0x00000001, 0x01a00020, 0x0def0060, "lsr%20's%c\t%12-15R, %q"},
  {0x00000001, 0x01a00040, 0x0def0060, "asr%20's%c\t%12-15R, %q"},
  {0x00000001, 0x01a00060, 0x0def0ff0, "rrx%20's%c\t%12-15r, %0-3r"},
  {0x00000001, 0x01a00060, 0x0def0060, "ror%20's%c\t%12-15R, %q"},

  {0x00000001, 0x03c00000, 0x0fe00000, "bic%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x01c00000, 0x0fe00010, "bic%20's%c\t%12-15r, %16-19r, %o"},
  {0x00000001, 0x01c00010, 0x0fe00090, "bic%20's%c\t%12-15R, %16-19R, %o"},

  {0x00000001, 0x03e00000, 0x0fe00000, "mvn%20's%c\t%12-15r, %o"},
  {0x00000001, 0x01e00000, 0x0fe00010, "mvn%20's%c\t%12-15r, %o"},
  {0x00000001, 0x01e00010, 0x0fe00090, "mvn%20's%c\t%12-15R, %o"},

  {0x00000001, 0x06000010, 0x0e000010, "\t\t; <UNDEFINED> instruction: %0-31x"},
  {0x00000001, 0x049d0004, 0x0fff0fff, "pop%c\t{%12-15r}\t\t; (ldr%c %12-15r, %a)"},

  {0x00000001, 0x04500000, 0x0c500000, "ldrb%t%c\t%12-15R, %a"},

  {0x00000001, 0x04300000, 0x0d700000, "ldrt%c\t%12-15R, %a"},
  {0x00000001, 0x04100000, 0x0c500000, "ldr%c\t%12-15r, %a"},

  {0x00000001, 0x092d0001, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x092d0002, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x092d0004, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x092d0008, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x092d0010, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x092d0020, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x092d0040, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x092d0080, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x092d0100, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x092d0200, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x092d0400, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x092d0800, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x092d1000, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x092d2000, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x092d4000, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x092d8000, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x092d0000, 0x0fff0000, "push%c\t%m"},
  {0x00000001, 0x08800000, 0x0ff00000, "stm%c\t%16-19R%21'!, %m%22'^"},
  {0x00000001, 0x08000000, 0x0e100000, "stm%23?id%24?ba%c\t%16-19R%21'!, %m%22'^"},

  {0x00000001, 0x08bd0001, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x08bd0002, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x08bd0004, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x08bd0008, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x08bd0010, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x08bd0020, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x08bd0040, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x08bd0080, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x08bd0100, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x08bd0200, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x08bd0400, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x08bd0800, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x08bd1000, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x08bd2000, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x08bd4000, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x08bd8000, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
  {0x00000001, 0x08bd0000, 0x0fff0000, "pop%c\t%m"},
  {0x00000001, 0x08900000, 0x0f900000, "ldm%c\t%16-19R%21'!, %m%22'^"},
  {0x00000001, 0x08100000, 0x0e100000, "ldm%23?id%24?ba%c\t%16-19R%21'!, %m%22'^"},

  {0x00000001, 0x0a000000, 0x0e000000, "b%24'l%c\t%b"},
  {0x00000001, 0x0f000000, 0x0f000000, "svc%c\t%0-23x"},


  {0x00000001, 0x00000000, 0x00000000, "\t\t; <UNDEFINED> instruction: %0-31x"},
  {0, 0x00000000, 0x00000000, 0}
};
static const struct opcode16 thumb_opcodes[] =
{



  {0x00004000, 0xbf50, 0xffff, "sevl%c"},
  {0x00004000, 0xba80, 0xffc0, "hlt\t%0-5x"},


  {0x00002000, 0xbf00, 0xffff, "nop%c"},
  {0x00002000, 0xbf10, 0xffff, "yield%c"},
  {0x00002000, 0xbf20, 0xffff, "wfe%c"},
  {0x00002000, 0xbf30, 0xffff, "wfi%c"},
  {0x00002000, 0xbf40, 0xffff, "sev%c"},
  {0x00002000, 0xbf00, 0xff0f, "nop%c\t{%4-7d}"},


  {0x00008000, 0xb900, 0xfd00, "cbnz\t%0-2r, %b%X"},
  {0x00008000, 0xb100, 0xfd00, "cbz\t%0-2r, %b%X"},
  {0x00008000, 0xbf00, 0xff00, "it%I%X"},


  {0x00001000, 0xb660, 0xfff8, "cpsie\t%2'a%1'i%0'f%X"},
  {0x00001000, 0xb670, 0xfff8, "cpsid\t%2'a%1'i%0'f%X"},
  {0x00001000, 0x4600, 0xffc0, "mov%c\t%0-2r, %3-5r"},
  {0x00001000, 0xba00, 0xffc0, "rev%c\t%0-2r, %3-5r"},
  {0x00001000, 0xba40, 0xffc0, "rev16%c\t%0-2r, %3-5r"},
  {0x00001000, 0xbac0, 0xffc0, "revsh%c\t%0-2r, %3-5r"},
  {0x00001000, 0xb650, 0xfff7, "setend\t%3?ble%X"},
  {0x00001000, 0xb200, 0xffc0, "sxth%c\t%0-2r, %3-5r"},
  {0x00001000, 0xb240, 0xffc0, "sxtb%c\t%0-2r, %3-5r"},
  {0x00001000, 0xb280, 0xffc0, "uxth%c\t%0-2r, %3-5r"},
  {0x00001000, 0xb2c0, 0xffc0, "uxtb%c\t%0-2r, %3-5r"},


  {0x00000100, 0xbe00, 0xff00, "bkpt\t%0-7x"},

  {0x00000100, 0x4780, 0xff87, "blx%c\t%3-6r%x"},

  {0x00000040, 0x46C0, 0xFFFF, "nop%c\t\t\t; (mov r8, r8)"},

  {0x00000040, 0x4000, 0xFFC0, "and%C\t%0-2r, %3-5r"},
  {0x00000040, 0x4040, 0xFFC0, "eor%C\t%0-2r, %3-5r"},
  {0x00000040, 0x4080, 0xFFC0, "lsl%C\t%0-2r, %3-5r"},
  {0x00000040, 0x40C0, 0xFFC0, "lsr%C\t%0-2r, %3-5r"},
  {0x00000040, 0x4100, 0xFFC0, "asr%C\t%0-2r, %3-5r"},
  {0x00000040, 0x4140, 0xFFC0, "adc%C\t%0-2r, %3-5r"},
  {0x00000040, 0x4180, 0xFFC0, "sbc%C\t%0-2r, %3-5r"},
  {0x00000040, 0x41C0, 0xFFC0, "ror%C\t%0-2r, %3-5r"},
  {0x00000040, 0x4200, 0xFFC0, "tst%c\t%0-2r, %3-5r"},
  {0x00000040, 0x4240, 0xFFC0, "neg%C\t%0-2r, %3-5r"},
  {0x00000040, 0x4280, 0xFFC0, "cmp%c\t%0-2r, %3-5r"},
  {0x00000040, 0x42C0, 0xFFC0, "cmn%c\t%0-2r, %3-5r"},
  {0x00000040, 0x4300, 0xFFC0, "orr%C\t%0-2r, %3-5r"},
  {0x00000040, 0x4340, 0xFFC0, "mul%C\t%0-2r, %3-5r"},
  {0x00000040, 0x4380, 0xFFC0, "bic%C\t%0-2r, %3-5r"},
  {0x00000040, 0x43C0, 0xFFC0, "mvn%C\t%0-2r, %3-5r"},

  {0x00000040, 0xB000, 0xFF80, "add%c\tsp, #%0-6W"},
  {0x00000040, 0xB080, 0xFF80, "sub%c\tsp, #%0-6W"},

  {0x00000040, 0x4700, 0xFF80, "bx%c\t%S%x"},
  {0x00000040, 0x4400, 0xFF00, "add%c\t%D, %S"},
  {0x00000040, 0x4500, 0xFF00, "cmp%c\t%D, %S"},
  {0x00000040, 0x4600, 0xFF00, "mov%c\t%D, %S"},

  {0x00000040, 0xB400, 0xFE00, "push%c\t%N"},
  {0x00000040, 0xBC00, 0xFE00, "pop%c\t%O"},

  {0x00000040, 0x1800, 0xFE00, "add%C\t%0-2r, %3-5r, %6-8r"},
  {0x00000040, 0x1A00, 0xFE00, "sub%C\t%0-2r, %3-5r, %6-8r"},
  {0x00000040, 0x1C00, 0xFE00, "add%C\t%0-2r, %3-5r, #%6-8d"},
  {0x00000040, 0x1E00, 0xFE00, "sub%C\t%0-2r, %3-5r, #%6-8d"},

  {0x00000040, 0x5200, 0xFE00, "strh%c\t%0-2r, [%3-5r, %6-8r]"},
  {0x00000040, 0x5A00, 0xFE00, "ldrh%c\t%0-2r, [%3-5r, %6-8r]"},
  {0x00000040, 0x5600, 0xF600, "ldrs%11?hb%c\t%0-2r, [%3-5r, %6-8r]"},

  {0x00000040, 0x5000, 0xFA00, "str%10'b%c\t%0-2r, [%3-5r, %6-8r]"},
  {0x00000040, 0x5800, 0xFA00, "ldr%10'b%c\t%0-2r, [%3-5r, %6-8r]"},

  {0x00000040, 0x0000, 0xFFC0, "mov%C\t%0-2r, %3-5r"},
  {0x00000040, 0x0000, 0xF800, "lsl%C\t%0-2r, %3-5r, #%6-10d"},
  {0x00000040, 0x0800, 0xF800, "lsr%C\t%0-2r, %3-5r, %s"},
  {0x00000040, 0x1000, 0xF800, "asr%C\t%0-2r, %3-5r, %s"},

  {0x00000040, 0x2000, 0xF800, "mov%C\t%8-10r, #%0-7d"},
  {0x00000040, 0x2800, 0xF800, "cmp%c\t%8-10r, #%0-7d"},
  {0x00000040, 0x3000, 0xF800, "add%C\t%8-10r, #%0-7d"},
  {0x00000040, 0x3800, 0xF800, "sub%C\t%8-10r, #%0-7d"},

  {0x00000040, 0x4800, 0xF800, "ldr%c\t%8-10r, [pc, #%0-7W]\t; (%0-7a)"},

  {0x00000040, 0x6000, 0xF800, "str%c\t%0-2r, [%3-5r, #%6-10W]"},
  {0x00000040, 0x6800, 0xF800, "ldr%c\t%0-2r, [%3-5r, #%6-10W]"},
  {0x00000040, 0x7000, 0xF800, "strb%c\t%0-2r, [%3-5r, #%6-10d]"},
  {0x00000040, 0x7800, 0xF800, "ldrb%c\t%0-2r, [%3-5r, #%6-10d]"},

  {0x00000040, 0x8000, 0xF800, "strh%c\t%0-2r, [%3-5r, #%6-10H]"},
  {0x00000040, 0x8800, 0xF800, "ldrh%c\t%0-2r, [%3-5r, #%6-10H]"},

  {0x00000040, 0x9000, 0xF800, "str%c\t%8-10r, [sp, #%0-7W]"},
  {0x00000040, 0x9800, 0xF800, "ldr%c\t%8-10r, [sp, #%0-7W]"},

  {0x00000040, 0xA000, 0xF800, "add%c\t%8-10r, pc, #%0-7W\t; (adr %8-10r, %0-7a)"},
  {0x00000040, 0xA800, 0xF800, "add%c\t%8-10r, sp, #%0-7W"},

  {0x00000040, 0xC000, 0xF800, "stmia%c\t%8-10r!, %M"},
  {0x00000040, 0xC800, 0xF800, "ldmia%c\t%8-10r%W, %M"},

  {0x00000040, 0xDF00, 0xFF00, "svc%c\t%0-7d"},

  {0x00000040, 0xDE00, 0xFF00, "udf%c\t#%0-7d"},
  {0x00000040, 0xDE00, 0xFE00, "\t\t; <UNDEFINED> instruction: %0-31x"},
  {0x00000040, 0xD000, 0xF000, "b%8-11c.n\t%0-7B%X"},

  {0x00000040, 0xE000, 0xF800, "b%c.n\t%0-10B%x"},





  {0x00000001, 0x0000, 0x0000, "\t\t; <UNDEFINED> instruction: %0-31x"},
  {0, 0, 0, 0}
};
static const struct opcode32 thumb32_opcodes[] =
{

  {0x00004000, 0xf3af8005, 0xffffffff, "sevl%c.w"},
  {0x00004000, 0xf78f8000, 0xfffffffc, "dcps%0-1d"},
  {0x00004000, 0xe8c00f8f, 0xfff00fff, "stlb%c\t%12-15r, [%16-19R]"},
  {0x00004000, 0xe8c00f9f, 0xfff00fff, "stlh%c\t%12-15r, [%16-19R]"},
  {0x00004000, 0xe8c00faf, 0xfff00fff, "stl%c\t%12-15r, [%16-19R]"},
  {0x00004000, 0xe8c00fc0, 0xfff00ff0, "stlexb%c\t%0-3r, %12-15r, [%16-19R]"},
  {0x00004000, 0xe8c00fd0, 0xfff00ff0, "stlexh%c\t%0-3r, %12-15r, [%16-19R]"},
  {0x00004000, 0xe8c00fe0, 0xfff00ff0, "stlex%c\t%0-3r, %12-15r, [%16-19R]"},
  {0x00004000, 0xe8c000f0, 0xfff000f0, "stlexd%c\t%0-3r, %12-15r, %8-11r, [%16-19R]"},
  {0x00004000, 0xe8d00f8f, 0xfff00fff, "ldab%c\t%12-15r, [%16-19R]"},
  {0x00004000, 0xe8d00f9f, 0xfff00fff, "ldah%c\t%12-15r, [%16-19R]"},
  {0x00004000, 0xe8d00faf, 0xfff00fff, "lda%c\t%12-15r, [%16-19R]"},
  {0x00004000, 0xe8d00fcf, 0xfff00fff, "ldaexb%c\t%12-15r, [%16-19R]"},
  {0x00004000, 0xe8d00fdf, 0xfff00fff, "ldaexh%c\t%12-15r, [%16-19R]"},
  {0x00004000, 0xe8d00fef, 0xfff00fff, "ldaex%c\t%12-15r, [%16-19R]"},
  {0x00004000, 0xe8d000ff, 0xfff000ff, "ldaexd%c\t%12-15r, %8-11r, [%16-19R]"},


  {0x00004000, 0xfac0f080, 0xfff0f0f0, "crc32b\t%8-11S, %16-19S, %0-3S"},
  {0x00004000, 0xfac0f090, 0xfff0f0f0, "crc32h\t%9-11S, %16-19S, %0-3S"},
  {0x00004000, 0xfac0f0a0, 0xfff0f0f0, "crc32w\t%8-11S, %16-19S, %0-3S"},
  {0x00004000, 0xfad0f080, 0xfff0f0f0, "crc32cb\t%8-11S, %16-19S, %0-3S"},
  {0x00004000, 0xfad0f090, 0xfff0f0f0, "crc32ch\t%8-11S, %16-19S, %0-3S"},
  {0x00004000, 0xfad0f0a0, 0xfff0f0f0, "crc32cw\t%8-11S, %16-19S, %0-3S"},


  {0x00080000, 0xf910f000, 0xff70f000, "pli%c\t%a"},
  {0x00080000, 0xf3af80f0, 0xfffffff0, "dbg%c\t#%0-3d"},
  {0x00004000, 0xf3bf8f51, 0xfffffff3, "dmb%c\t%U"},
  {0x00004000, 0xf3bf8f41, 0xfffffff3, "dsb%c\t%U"},
  {0x00080000, 0xf3bf8f50, 0xfffffff0, "dmb%c\t%U"},
  {0x00080000, 0xf3bf8f40, 0xfffffff0, "dsb%c\t%U"},
  {0x00080000, 0xf3bf8f60, 0xfffffff0, "isb%c\t%U"},
  {0x00010000, 0xfb90f0f0, 0xfff0f0f0, "sdiv%c\t%8-11r, %16-19r, %0-3r"},
  {0x00010000, 0xfbb0f0f0, 0xfff0f0f0, "udiv%c\t%8-11r, %16-19r, %0-3r"},


  {0x80000000, 0xf7e08000, 0xfff0f000, "hvc%c\t%V"},



  {0x08000000, 0xf830f000, 0xff70f000, "pldw%c\t%a"},


  {0x10000000, 0xf7f08000, 0xfff0f000, "smc%c\t%K"},


  {0x00008000, 0xf3af8000, 0xffffffff, "nop%c.w"},
  {0x00008000, 0xf3af8001, 0xffffffff, "yield%c.w"},
  {0x00008000, 0xf3af8002, 0xffffffff, "wfe%c.w"},
  {0x00008000, 0xf3af8003, 0xffffffff, "wfi%c.w"},
  {0x00008000, 0xf3af8004, 0xffffffff, "sev%c.w"},
  {0x00008000, 0xf3af8000, 0xffffff00, "nop%c.w\t{%0-7d}"},
  {0x00008000, 0xf7f0a000, 0xfff0f000, "udf%c.w\t%H"},

  {0x00008000, 0xf3bf8f2f, 0xffffffff, "clrex%c"},
  {0x00008000, 0xf3af8400, 0xffffff1f, "cpsie.w\t%7'a%6'i%5'f%X"},
  {0x00008000, 0xf3af8600, 0xffffff1f, "cpsid.w\t%7'a%6'i%5'f%X"},
  {0x00008000, 0xf3c08f00, 0xfff0ffff, "bxj%c\t%16-19r%x"},
  {0x00008000, 0xe810c000, 0xffd0ffff, "rfedb%c\t%16-19r%21'!"},
  {0x00008000, 0xe990c000, 0xffd0ffff, "rfeia%c\t%16-19r%21'!"},
  {0x00008000, 0xf3e08000, 0xffe0f000, "mrs%c\t%8-11r, %D"},
  {0x00008000, 0xf3af8100, 0xffffffe0, "cps\t#%0-4d%X"},
  {0x00008000, 0xe8d0f000, 0xfff0fff0, "tbb%c\t[%16-19r, %0-3r]%x"},
  {0x00008000, 0xe8d0f010, 0xfff0fff0, "tbh%c\t[%16-19r, %0-3r, lsl #1]%x"},
  {0x00008000, 0xf3af8500, 0xffffff00, "cpsie\t%7'a%6'i%5'f, #%0-4d%X"},
  {0x00008000, 0xf3af8700, 0xffffff00, "cpsid\t%7'a%6'i%5'f, #%0-4d%X"},
  {0x00008000, 0xf3de8f00, 0xffffff00, "subs%c\tpc, lr, #%0-7d"},
  {0x00008000, 0xf3808000, 0xffe0f000, "msr%c\t%C, %16-19r"},
  {0x00008000, 0xe8500f00, 0xfff00fff, "ldrex%c\t%12-15r, [%16-19r]"},
  {0x00008000, 0xe8d00f4f, 0xfff00fef, "ldrex%4?hb%c\t%12-15r, [%16-19r]"},
  {0x00008000, 0xe800c000, 0xffd0ffe0, "srsdb%c\t%16-19r%21'!, #%0-4d"},
  {0x00008000, 0xe980c000, 0xffd0ffe0, "srsia%c\t%16-19r%21'!, #%0-4d"},
  {0x00008000, 0xfa0ff080, 0xfffff0c0, "sxth%c.w\t%8-11r, %0-3r%R"},
  {0x00008000, 0xfa1ff080, 0xfffff0c0, "uxth%c.w\t%8-11r, %0-3r%R"},
  {0x00008000, 0xfa2ff080, 0xfffff0c0, "sxtb16%c\t%8-11r, %0-3r%R"},
  {0x00008000, 0xfa3ff080, 0xfffff0c0, "uxtb16%c\t%8-11r, %0-3r%R"},
  {0x00008000, 0xfa4ff080, 0xfffff0c0, "sxtb%c.w\t%8-11r, %0-3r%R"},
  {0x00008000, 0xfa5ff080, 0xfffff0c0, "uxtb%c.w\t%8-11r, %0-3r%R"},
  {0x00008000, 0xe8400000, 0xfff000ff, "strex%c\t%8-11r, %12-15r, [%16-19r]"},
  {0x00008000, 0xe8d0007f, 0xfff000ff, "ldrexd%c\t%12-15r, %8-11r, [%16-19r]"},
  {0x00008000, 0xfa80f000, 0xfff0f0f0, "sadd8%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfa80f010, 0xfff0f0f0, "qadd8%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfa80f020, 0xfff0f0f0, "shadd8%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfa80f040, 0xfff0f0f0, "uadd8%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfa80f050, 0xfff0f0f0, "uqadd8%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfa80f060, 0xfff0f0f0, "uhadd8%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfa80f080, 0xfff0f0f0, "qadd%c\t%8-11r, %0-3r, %16-19r"},
  {0x00008000, 0xfa80f090, 0xfff0f0f0, "qdadd%c\t%8-11r, %0-3r, %16-19r"},
  {0x00008000, 0xfa80f0a0, 0xfff0f0f0, "qsub%c\t%8-11r, %0-3r, %16-19r"},
  {0x00008000, 0xfa80f0b0, 0xfff0f0f0, "qdsub%c\t%8-11r, %0-3r, %16-19r"},
  {0x00008000, 0xfa90f000, 0xfff0f0f0, "sadd16%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfa90f010, 0xfff0f0f0, "qadd16%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfa90f020, 0xfff0f0f0, "shadd16%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfa90f040, 0xfff0f0f0, "uadd16%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfa90f050, 0xfff0f0f0, "uqadd16%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfa90f060, 0xfff0f0f0, "uhadd16%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfa90f080, 0xfff0f0f0, "rev%c.w\t%8-11r, %16-19r"},
  {0x00008000, 0xfa90f090, 0xfff0f0f0, "rev16%c.w\t%8-11r, %16-19r"},
  {0x00008000, 0xfa90f0a0, 0xfff0f0f0, "rbit%c\t%8-11r, %16-19r"},
  {0x00008000, 0xfa90f0b0, 0xfff0f0f0, "revsh%c.w\t%8-11r, %16-19r"},
  {0x00008000, 0xfaa0f000, 0xfff0f0f0, "sasx%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfaa0f010, 0xfff0f0f0, "qasx%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfaa0f020, 0xfff0f0f0, "shasx%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfaa0f040, 0xfff0f0f0, "uasx%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfaa0f050, 0xfff0f0f0, "uqasx%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfaa0f060, 0xfff0f0f0, "uhasx%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfaa0f080, 0xfff0f0f0, "sel%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfab0f080, 0xfff0f0f0, "clz%c\t%8-11r, %16-19r"},
  {0x00008000, 0xfac0f000, 0xfff0f0f0, "ssub8%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfac0f010, 0xfff0f0f0, "qsub8%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfac0f020, 0xfff0f0f0, "shsub8%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfac0f040, 0xfff0f0f0, "usub8%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfac0f050, 0xfff0f0f0, "uqsub8%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfac0f060, 0xfff0f0f0, "uhsub8%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfad0f000, 0xfff0f0f0, "ssub16%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfad0f010, 0xfff0f0f0, "qsub16%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfad0f020, 0xfff0f0f0, "shsub16%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfad0f040, 0xfff0f0f0, "usub16%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfad0f050, 0xfff0f0f0, "uqsub16%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfad0f060, 0xfff0f0f0, "uhsub16%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfae0f000, 0xfff0f0f0, "ssax%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfae0f010, 0xfff0f0f0, "qsax%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfae0f020, 0xfff0f0f0, "shsax%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfae0f040, 0xfff0f0f0, "usax%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfae0f050, 0xfff0f0f0, "uqsax%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfae0f060, 0xfff0f0f0, "uhsax%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfb00f000, 0xfff0f0f0, "mul%c.w\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfb70f000, 0xfff0f0f0, "usad8%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfa00f000, 0xffe0f0f0, "lsl%20's%c.w\t%8-11R, %16-19R, %0-3R"},
  {0x00008000, 0xfa20f000, 0xffe0f0f0, "lsr%20's%c.w\t%8-11R, %16-19R, %0-3R"},
  {0x00008000, 0xfa40f000, 0xffe0f0f0, "asr%20's%c.w\t%8-11R, %16-19R, %0-3R"},
  {0x00008000, 0xfa60f000, 0xffe0f0f0, "ror%20's%c.w\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xe8c00f40, 0xfff00fe0, "strex%4?hb%c\t%0-3r, %12-15r, [%16-19r]"},
  {0x00008000, 0xf3200000, 0xfff0f0e0, "ssat16%c\t%8-11r, #%0-4d, %16-19r"},
  {0x00008000, 0xf3a00000, 0xfff0f0e0, "usat16%c\t%8-11r, #%0-4d, %16-19r"},
  {0x00008000, 0xfb20f000, 0xfff0f0e0, "smuad%4'x%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfb30f000, 0xfff0f0e0, "smulw%4?tb%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfb40f000, 0xfff0f0e0, "smusd%4'x%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfb50f000, 0xfff0f0e0, "smmul%4'r%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xfa00f080, 0xfff0f0c0, "sxtah%c\t%8-11r, %16-19r, %0-3r%R"},
  {0x00008000, 0xfa10f080, 0xfff0f0c0, "uxtah%c\t%8-11r, %16-19r, %0-3r%R"},
  {0x00008000, 0xfa20f080, 0xfff0f0c0, "sxtab16%c\t%8-11r, %16-19r, %0-3r%R"},
  {0x00008000, 0xfa30f080, 0xfff0f0c0, "uxtab16%c\t%8-11r, %16-19r, %0-3r%R"},
  {0x00008000, 0xfa40f080, 0xfff0f0c0, "sxtab%c\t%8-11r, %16-19r, %0-3r%R"},
  {0x00008000, 0xfa50f080, 0xfff0f0c0, "uxtab%c\t%8-11r, %16-19r, %0-3r%R"},
  {0x00008000, 0xfb10f000, 0xfff0f0c0, "smul%5?tb%4?tb%c\t%8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xf36f0000, 0xffff8020, "bfc%c\t%8-11r, %E"},
  {0x00008000, 0xea100f00, 0xfff08f00, "tst%c.w\t%16-19r, %S"},
  {0x00008000, 0xea900f00, 0xfff08f00, "teq%c\t%16-19r, %S"},
  {0x00008000, 0xeb100f00, 0xfff08f00, "cmn%c.w\t%16-19r, %S"},
  {0x00008000, 0xebb00f00, 0xfff08f00, "cmp%c.w\t%16-19r, %S"},
  {0x00008000, 0xf0100f00, 0xfbf08f00, "tst%c.w\t%16-19r, %M"},
  {0x00008000, 0xf0900f00, 0xfbf08f00, "teq%c\t%16-19r, %M"},
  {0x00008000, 0xf1100f00, 0xfbf08f00, "cmn%c.w\t%16-19r, %M"},
  {0x00008000, 0xf1b00f00, 0xfbf08f00, "cmp%c.w\t%16-19r, %M"},
  {0x00008000, 0xea4f0000, 0xffef8000, "mov%20's%c.w\t%8-11r, %S"},
  {0x00008000, 0xea6f0000, 0xffef8000, "mvn%20's%c.w\t%8-11r, %S"},
  {0x00008000, 0xe8c00070, 0xfff000f0, "strexd%c\t%0-3r, %12-15r, %8-11r, [%16-19r]"},
  {0x00008000, 0xfb000000, 0xfff000f0, "mla%c\t%8-11r, %16-19r, %0-3r, %12-15r"},
  {0x00008000, 0xfb000010, 0xfff000f0, "mls%c\t%8-11r, %16-19r, %0-3r, %12-15r"},
  {0x00008000, 0xfb700000, 0xfff000f0, "usada8%c\t%8-11R, %16-19R, %0-3R, %12-15R"},
  {0x00008000, 0xfb800000, 0xfff000f0, "smull%c\t%12-15R, %8-11R, %16-19R, %0-3R"},
  {0x00008000, 0xfba00000, 0xfff000f0, "umull%c\t%12-15R, %8-11R, %16-19R, %0-3R"},
  {0x00008000, 0xfbc00000, 0xfff000f0, "smlal%c\t%12-15R, %8-11R, %16-19R, %0-3R"},
  {0x00008000, 0xfbe00000, 0xfff000f0, "umlal%c\t%12-15R, %8-11R, %16-19R, %0-3R"},
  {0x00008000, 0xfbe00060, 0xfff000f0, "umaal%c\t%12-15R, %8-11R, %16-19R, %0-3R"},
  {0x00008000, 0xe8500f00, 0xfff00f00, "ldrex%c\t%12-15r, [%16-19r, #%0-7W]"},
  {0x00008000, 0xf04f0000, 0xfbef8000, "mov%20's%c.w\t%8-11r, %M"},
  {0x00008000, 0xf06f0000, 0xfbef8000, "mvn%20's%c.w\t%8-11r, %M"},
  {0x00008000, 0xf810f000, 0xff70f000, "pld%c\t%a"},
  {0x00008000, 0xfb200000, 0xfff000e0, "smlad%4'x%c\t%8-11R, %16-19R, %0-3R, %12-15R"},
  {0x00008000, 0xfb300000, 0xfff000e0, "smlaw%4?tb%c\t%8-11R, %16-19R, %0-3R, %12-15R"},
  {0x00008000, 0xfb400000, 0xfff000e0, "smlsd%4'x%c\t%8-11R, %16-19R, %0-3R, %12-15R"},
  {0x00008000, 0xfb500000, 0xfff000e0, "smmla%4'r%c\t%8-11R, %16-19R, %0-3R, %12-15R"},
  {0x00008000, 0xfb600000, 0xfff000e0, "smmls%4'r%c\t%8-11R, %16-19R, %0-3R, %12-15R"},
  {0x00008000, 0xfbc000c0, 0xfff000e0, "smlald%4'x%c\t%12-15R, %8-11R, %16-19R, %0-3R"},
  {0x00008000, 0xfbd000c0, 0xfff000e0, "smlsld%4'x%c\t%12-15R, %8-11R, %16-19R, %0-3R"},
  {0x00008000, 0xeac00000, 0xfff08030, "pkhbt%c\t%8-11r, %16-19r, %S"},
  {0x00008000, 0xeac00020, 0xfff08030, "pkhtb%c\t%8-11r, %16-19r, %S"},
  {0x00008000, 0xf3400000, 0xfff08020, "sbfx%c\t%8-11r, %16-19r, %F"},
  {0x00008000, 0xf3c00000, 0xfff08020, "ubfx%c\t%8-11r, %16-19r, %F"},
  {0x00008000, 0xf8000e00, 0xff900f00, "str%wt%c\t%12-15r, %a"},
  {0x00008000, 0xfb100000, 0xfff000c0, "smla%5?tb%4?tb%c\t%8-11r, %16-19r, %0-3r, %12-15r"},
  {0x00008000, 0xfbc00080, 0xfff000c0, "smlal%5?tb%4?tb%c\t%12-15r, %8-11r, %16-19r, %0-3r"},
  {0x00008000, 0xf3600000, 0xfff08020, "bfi%c\t%8-11r, %16-19r, %E"},
  {0x00008000, 0xf8100e00, 0xfe900f00, "ldr%wt%c\t%12-15r, %a"},
  {0x00008000, 0xf3000000, 0xffd08020, "ssat%c\t%8-11r, #%0-4d, %16-19r%s"},
  {0x00008000, 0xf3800000, 0xffd08020, "usat%c\t%8-11r, #%0-4d, %16-19r%s"},
  {0x00008000, 0xf2000000, 0xfbf08000, "addw%c\t%8-11r, %16-19r, %I"},
  {0x00008000, 0xf2400000, 0xfbf08000, "movw%c\t%8-11r, %J"},
  {0x00008000, 0xf2a00000, 0xfbf08000, "subw%c\t%8-11r, %16-19r, %I"},
  {0x00008000, 0xf2c00000, 0xfbf08000, "movt%c\t%8-11r, %J"},
  {0x00008000, 0xea000000, 0xffe08000, "and%20's%c.w\t%8-11r, %16-19r, %S"},
  {0x00008000, 0xea200000, 0xffe08000, "bic%20's%c.w\t%8-11r, %16-19r, %S"},
  {0x00008000, 0xea400000, 0xffe08000, "orr%20's%c.w\t%8-11r, %16-19r, %S"},
  {0x00008000, 0xea600000, 0xffe08000, "orn%20's%c\t%8-11r, %16-19r, %S"},
  {0x00008000, 0xea800000, 0xffe08000, "eor%20's%c.w\t%8-11r, %16-19r, %S"},
  {0x00008000, 0xeb000000, 0xffe08000, "add%20's%c.w\t%8-11r, %16-19r, %S"},
  {0x00008000, 0xeb400000, 0xffe08000, "adc%20's%c.w\t%8-11r, %16-19r, %S"},
  {0x00008000, 0xeb600000, 0xffe08000, "sbc%20's%c.w\t%8-11r, %16-19r, %S"},
  {0x00008000, 0xeba00000, 0xffe08000, "sub%20's%c.w\t%8-11r, %16-19r, %S"},
  {0x00008000, 0xebc00000, 0xffe08000, "rsb%20's%c\t%8-11r, %16-19r, %S"},
  {0x00008000, 0xe8400000, 0xfff00000, "strex%c\t%8-11r, %12-15r, [%16-19r, #%0-7W]"},
  {0x00008000, 0xf0000000, 0xfbe08000, "and%20's%c.w\t%8-11r, %16-19r, %M"},
  {0x00008000, 0xf0200000, 0xfbe08000, "bic%20's%c.w\t%8-11r, %16-19r, %M"},
  {0x00008000, 0xf0400000, 0xfbe08000, "orr%20's%c.w\t%8-11r, %16-19r, %M"},
  {0x00008000, 0xf0600000, 0xfbe08000, "orn%20's%c\t%8-11r, %16-19r, %M"},
  {0x00008000, 0xf0800000, 0xfbe08000, "eor%20's%c.w\t%8-11r, %16-19r, %M"},
  {0x00008000, 0xf1000000, 0xfbe08000, "add%20's%c.w\t%8-11r, %16-19r, %M"},
  {0x00008000, 0xf1400000, 0xfbe08000, "adc%20's%c.w\t%8-11r, %16-19r, %M"},
  {0x00008000, 0xf1600000, 0xfbe08000, "sbc%20's%c.w\t%8-11r, %16-19r, %M"},
  {0x00008000, 0xf1a00000, 0xfbe08000, "sub%20's%c.w\t%8-11r, %16-19r, %M"},
  {0x00008000, 0xf1c00000, 0xfbe08000, "rsb%20's%c\t%8-11r, %16-19r, %M"},
  {0x00008000, 0xe8800000, 0xffd00000, "stmia%c.w\t%16-19r%21'!, %m"},
  {0x00008000, 0xe8900000, 0xffd00000, "ldmia%c.w\t%16-19r%21'!, %m"},
  {0x00008000, 0xe9000000, 0xffd00000, "stmdb%c\t%16-19r%21'!, %m"},
  {0x00008000, 0xe9100000, 0xffd00000, "ldmdb%c\t%16-19r%21'!, %m"},
  {0x00008000, 0xe9c00000, 0xffd000ff, "strd%c\t%12-15r, %8-11r, [%16-19r]"},
  {0x00008000, 0xe9d00000, 0xffd000ff, "ldrd%c\t%12-15r, %8-11r, [%16-19r]"},
  {0x00008000, 0xe9400000, 0xff500000, "strd%c\t%12-15r, %8-11r, [%16-19r, #%23`-%0-7W]%21'!%L"},
  {0x00008000, 0xe9500000, 0xff500000, "ldrd%c\t%12-15r, %8-11r, [%16-19r, #%23`-%0-7W]%21'!%L"},
  {0x00008000, 0xe8600000, 0xff700000, "strd%c\t%12-15r, %8-11r, [%16-19r], #%23`-%0-7W%L"},
  {0x00008000, 0xe8700000, 0xff700000, "ldrd%c\t%12-15r, %8-11r, [%16-19r], #%23`-%0-7W%L"},
  {0x00008000, 0xf8000000, 0xff100000, "str%w%c.w\t%12-15r, %a"},
  {0x00008000, 0xf8100000, 0xfe100000, "ldr%w%c.w\t%12-15r, %a"},


  {0x00008000, 0xf3c08000, 0xfbc0d000, "undefined (bcc, cond=0xF)"},
  {0x00008000, 0xf3808000, 0xfbc0d000, "undefined (bcc, cond=0xE)"},
  {0x00008000, 0xf0008000, 0xf800d000, "b%22-25c.w\t%b%X"},
  {0x00008000, 0xf0009000, 0xf800d000, "b%c.w\t%B%x"},


  {0x00000040, 0xf000c000, 0xf800d001, "blx%c\t%B%x"},
  {0x00000040, 0xf000d000, 0xf800d000, "bl%c\t%B%x"},


  {0x00000001, 0x00000000, 0x00000000, "\t\t; <UNDEFINED> instruction: %0-31x"},
  {0, 0, 0, 0}
};

static const char *const arm_conditional[] =
{"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
 "hi", "ls", "ge", "lt", "gt", "le", "al", "<und>", ""};

static const char *const arm_fp_const[] =
{"0.0", "1.0", "2.0", "3.0", "4.0", "5.0", "0.5", "10.0"};

static const char *const arm_shift[] =
{"lsl", "lsr", "asr", "ror"};

typedef struct
{
  const char *name;
  const char *description;
  const char *reg_names[16];
}
arm_regname;

static const arm_regname regnames[] =
{
  { "raw" , "Select raw register names",
    { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}},
  { "gcc", "Select register names used by GCC",
    { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "sl", "fp", "ip", "sp", "lr", "pc" }},
  { "std", "Select register names used in ARM's ISA documentation",
    { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc" }},
  { "apcs", "Select register names used in the APCS",
    { "a1", "a2", "a3", "a4", "v1", "v2", "v3", "v4", "v5", "v6", "sl", "fp", "ip", "sp", "lr", "pc" }},
  { "atpcs", "Select register names used in the ATPCS",
    { "a1", "a2", "a3", "a4", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "IP", "SP", "LR", "PC" }},
  { "special-atpcs", "Select special register names used in the ATPCS",
    { "a1", "a2", "a3", "a4", "v1", "v2", "v3", "WR", "v5", "SB", "SL", "FP", "IP", "SP", "LR", "PC" }},
};

static const char *const iwmmxt_wwnames[] =
{"b", "h", "w", "d"};

static const char *const iwmmxt_wwssnames[] =
{"b", "bus", "bc", "bss",
 "h", "hus", "hc", "hss",
 "w", "wus", "wc", "wss",
 "d", "dus", "dc", "dss"
};

static const char *const iwmmxt_regnames[] =
{ "wr0", "wr1", "wr2", "wr3", "wr4", "wr5", "wr6", "wr7",
  "wr8", "wr9", "wr10", "wr11", "wr12", "wr13", "wr14", "wr15"
};

static const char *const iwmmxt_cregnames[] =
{ "wcid", "wcon", "wcssf", "wcasf", "reserved", "reserved", "reserved", "reserved",
  "wcgr0", "wcgr1", "wcgr2", "wcgr3", "reserved", "reserved", "reserved", "reserved"
};


static unsigned int regname_selected = 1;




static bfd_boolean force_thumb = 0;



static unsigned int ifthen_state;

static unsigned int ifthen_next_state;

static bfd_vma ifthen_address;







int
get_arm_regname_num_options (void)
{
  return (sizeof (regnames) / sizeof (regnames)[0]);
}

int
set_arm_regname_option (int option)
{
  int old = regname_selected;
  regname_selected = option;
  return old;
}

int
get_arm_regnames (int option,
    const char **setname,
    const char **setdescription,
    const char *const **register_names)
{
  *setname = regnames[option].name;
  *setdescription = regnames[option].description;
  *register_names = regnames[option].reg_names;
  return 16;
}






static const char *
arm_decode_bitfield (const char *ptr,
       unsigned long insn,
       unsigned long *valuep,
       int *widthp)
{
  unsigned long value = 0;
  int width = 0;

  do
    {
      int start, end;
      int bits;

      for (start = 0; *ptr >= '0' && *ptr <= '9'; ptr++)
 start = start * 10 + *ptr - '0';
      if (*ptr == '-')
 for (end = 0, ptr++; *ptr >= '0' && *ptr <= '9'; ptr++)
   end = end * 10 + *ptr - '0';
      else
 end = start;
      bits = end - start;
      if (bits < 0)
 abort ();
      value |= ((insn >> start) & ((2ul << bits) - 1)) << width;
      width += bits + 1;
    }
  while (*ptr++ == ',');
  *valuep = value;
  if (widthp)
    *widthp = width;
  return ptr - 1;
}

static void
arm_decode_shift (long given, fprintf_ftype func, void *stream,
    bfd_boolean print_shift)
{
  func (stream, "%s", regnames[regname_selected].reg_names[given & 0xf]);

  if ((given & 0xff0) != 0)
    {
      if ((given & 0x10) == 0)
 {
   int amount = (given & 0xf80) >> 7;
   int shift = (given & 0x60) >> 5;

   if (amount == 0)
     {
       if (shift == 3)
  {
    func (stream, ", rrx");
    return;
  }

       amount = 32;
     }

   if (print_shift)
     func (stream, ", %s #%d", arm_shift[shift], amount);
   else
     func (stream, ", #%d", amount);
 }
      else if ((given & 0x80) == 0x80)
 func (stream, "\t; <illegal shifter operand>");
      else if (print_shift)
 func (stream, ", %s %s", arm_shift[(given & 0x60) >> 5],
       regnames[regname_selected].reg_names[(given & 0xf00) >> 8]);
      else
 func (stream, ", %s", regnames[regname_selected].reg_names[(given & 0xf00) >> 8]);
    }
}
static bfd_boolean
print_insn_coprocessor (bfd_vma pc,
   struct disassemble_info *info,
   long given,
   bfd_boolean thumb)
{
  const struct opcode32 *insn;
  void *stream = info->stream;
  fprintf_ftype func = info->fprintf_func;
  unsigned long mask;
  unsigned long value = 0;
  struct arm_private_data *private_data = info->private_data;
  unsigned long allowed_arches = private_data->features.coproc;
  int cond;

  for (insn = coprocessor_opcodes; insn->assembler; insn++)
    {
      unsigned long u_reg = 16;
      bfd_boolean is_unpredictable = 0;
      signed long value_in_comment = 0;
      const char *c;

      if (insn->arch == 0)
 switch (insn->value)
   {
   case SENTINEL_IWMMXT_START:
     if (info->mach != 10
  && info->mach != 12
  && info->mach != 13)
       do
  insn++;
       while (insn->arch != 0 && insn->value != SENTINEL_IWMMXT_END);
     continue;

   case SENTINEL_IWMMXT_END:
     continue;

   case SENTINEL_GENERIC_START:
     allowed_arches = private_data->features.core;
     continue;

   default:
     abort ();
   }

      mask = insn->mask;
      value = insn->value;
      if (thumb)
 {



   mask |= 0xf0000000;
   value |= 0xe0000000;
   if (ifthen_state)
     cond = ((ifthen_state >> 4) & 0xf);
   else
     cond = 16;
 }
      else
 {


   if ((given & 0xf0000000) == 0xf0000000)
     {
       mask |= 0xf0000000;
       cond = 16;
     }
   else
     {
       cond = (given >> 28) & 0xf;
       if (cond == 0xe)
  cond = 16;
     }
 }

      if ((given & mask) != value)
 continue;

      if ((insn->arch & allowed_arches) == 0)
 continue;

      for (c = insn->assembler; *c; c++)
 {
   if (*c == '%')
     {
       switch (*++c)
  {
  case '%':
    func (stream, "%%");
    break;

  case 'A':
    {
      int rn = (given >> 16) & 0xf;
        bfd_vma offset = given & 0xff;

      func (stream, "[%s", regnames[regname_selected].reg_names [(given >> 16) & 0xf]);

      if ((given & (1 << 24)) || (given & (1 << 21)))
        {

   offset = offset * 4;
   if (((given & (1 << 23)) == 0))
     offset = - offset;
   if (rn != 15)
     value_in_comment = offset;
        }

      if ((given & (1 << 24)))
        {
   if (offset)
     func (stream, ", #%d]%s",
    (int) offset,
    (given & (1 << 21)) ? "!" : "");
   else if (((given & (1 << 23)) == 0))
     func (stream, ", #-0]");
   else
     func (stream, "]");
        }
      else
        {
   func (stream, "]");

   if ((given & (1 << 21)))
     {
       if (offset)
         func (stream, ", #%d", (int) offset);
       else if (((given & (1 << 23)) == 0))
         func (stream, ", #-0");
     }
   else
     {
       func (stream, ", {%s%d}",
      (((given & (1 << 23)) == 0) && !offset) ? "-" : "",
      (int) offset);
       value_in_comment = offset;
     }
        }
      if (rn == 15 && ((given & (1 << 24)) || (given & (1 << 21))))
        {
   func (stream, "\t; ");


   info->print_address_func (offset + pc
        + info->bytes_per_chunk * 2
        - (pc & 3),
         info);
        }
    }
    break;

  case 'B':
    {
      int regno = ((given >> 12) & 0xf) | ((given >> (22 - 4)) & 0x10);
      int offset = (given >> 1) & 0x3f;

      if (offset == 1)
        func (stream, "{d%d}", regno);
      else if (regno + offset > 32)
        func (stream, "{d%d-<overflow reg d%d>}", regno, regno + offset - 1);
      else
        func (stream, "{d%d-d%d}", regno, regno + offset - 1);
    }
    break;

  case 'u':
    if (cond != 16)
      is_unpredictable = 1;


  case 'c':
    func (stream, "%s", arm_conditional[cond]);
    break;

  case 'I':




    {
      int imm;

      imm = (given & 0xf) | ((given & 0xe0) >> 1);


      if (imm & 0x40)
        imm |= (-1 << 7);

      func (stream, "%d", imm);
    }

    break;

  case 'F':
    switch (given & 0x00408000)
      {
      case 0:
        func (stream, "4");
        break;
      case 0x8000:
        func (stream, "1");
        break;
      case 0x00400000:
        func (stream, "2");
        break;
      default:
        func (stream, "3");
      }
    break;

  case 'P':
    switch (given & 0x00080080)
      {
      case 0:
        func (stream, "s");
        break;
      case 0x80:
        func (stream, "d");
        break;
      case 0x00080000:
        func (stream, "e");
        break;
      default:
        func (stream, dcgettext ("bfd", "<illegal precision>", 5));
        break;
      }
    break;

  case 'Q':
    switch (given & 0x00408000)
      {
      case 0:
        func (stream, "s");
        break;
      case 0x8000:
        func (stream, "d");
        break;
      case 0x00400000:
        func (stream, "e");
        break;
      default:
        func (stream, "p");
        break;
      }
    break;

  case 'R':
    switch (given & 0x60)
      {
      case 0:
        break;
      case 0x20:
        func (stream, "p");
        break;
      case 0x40:
        func (stream, "m");
        break;
      default:
        func (stream, "z");
        break;
      }
    break;

  case '0': case '1': case '2': case '3': case '4':
  case '5': case '6': case '7': case '8': case '9':
    {
      int width;

      c = arm_decode_bitfield (c, given, &value, &width);

      switch (*c)
        {
        case 'R':
   if (value == 15)
     is_unpredictable = 1;

        case 'r':
   if (c[1] == 'u')
     {

       ++ c;

       if (u_reg == value)
         is_unpredictable = 1;
       u_reg = value;
     }
   func (stream, "%s", regnames[regname_selected].reg_names[value]);
   break;
        case 'D':
   func (stream, "d%ld", value);
   break;
        case 'Q':
   if (value & 1)
     func (stream, "<illegal reg q%ld.5>", value >> 1);
   else
     func (stream, "q%ld", value >> 1);
   break;
        case 'd':
   func (stream, "%ld", value);
   value_in_comment = value;
   break;
        case 'k':
   {
     int from = (given & (1 << 7)) ? 32 : 16;
     func (stream, "%ld", from - value);
   }
   break;

        case 'f':
   if (value > 7)
     func (stream, "#%s", arm_fp_const[value & 7]);
   else
     func (stream, "f%ld", value);
   break;

        case 'w':
   if (width == 2)
     func (stream, "%s", iwmmxt_wwnames[value]);
   else
     func (stream, "%s", iwmmxt_wwssnames[value]);
   break;

        case 'g':
   func (stream, "%s", iwmmxt_regnames[value]);
   break;
        case 'G':
   func (stream, "%s", iwmmxt_cregnames[value]);
   break;

        case 'x':
   func (stream, "0x%lx", (value & 0xffffffffUL));
   break;

        case 'c':
   switch (value)
     {
     case 0:
       func (stream, "eq");
       break;

     case 1:
       func (stream, "vs");
       break;

     case 2:
       func (stream, "ge");
       break;

     case 3:
       func (stream, "gt");
       break;

     default:
       func (stream, "??");
       break;
     }
   break;

        case '`':
   c++;
   if (value == 0)
     func (stream, "%c", *c);
   break;
        case '\'':
   c++;
   if (value == ((1ul << width) - 1))
     func (stream, "%c", *c);
   break;
        case '?':
   func (stream, "%c", c[(1 << width) - (int) value]);
   c += 1 << width;
   break;
        default:
   abort ();
        }
      break;

    case 'y':
    case 'z':
      {
        int single = *c++ == 'y';
        int regno;

        switch (*c)
   {
   case '4':
   case '0':
     regno = given & 0x0000000f;
     if (single)
       {
         regno <<= 1;
         regno += (given >> 5) & 1;
       }
     else
       regno += ((given >> 5) & 1) << 4;
     break;

   case '1':
     regno = (given >> 12) & 0x0000000f;
     if (single)
       {
         regno <<= 1;
         regno += (given >> 22) & 1;
       }
     else
       regno += ((given >> 22) & 1) << 4;
     break;

   case '2':
     regno = (given >> 16) & 0x0000000f;
     if (single)
       {
         regno <<= 1;
         regno += (given >> 7) & 1;
       }
     else
       regno += ((given >> 7) & 1) << 4;
     break;

   case '3':
     func (stream, "{");
     regno = (given >> 12) & 0x0000000f;
     if (single)
       {
         regno <<= 1;
         regno += (given >> 22) & 1;
       }
     else
       regno += ((given >> 22) & 1) << 4;
     break;

   default:
     abort ();
   }

        func (stream, "%c%d", single ? 's' : 'd', regno);

        if (*c == '3')
   {
     int count = given & 0xff;

     if (single == 0)
       count >>= 1;

     if (--count)
       {
         func (stream, "-%c%d",
        single ? 's' : 'd',
        regno + count);
       }

     func (stream, "}");
   }
        else if (*c == '4')
   func (stream, ", %c%d", single ? 's' : 'd',
         regno + 1);
      }
      break;

    case 'L':
      switch (given & 0x00400100)
        {
        case 0x00000000: func (stream, "b"); break;
        case 0x00400000: func (stream, "h"); break;
        case 0x00000100: func (stream, "w"); break;
        case 0x00400100: func (stream, "d"); break;
        default:
   break;
        }
      break;

    case 'Z':
      {

        value = ((given >> 16) & 0xf0) | (given & 0xf);
        func (stream, "%d", (int) value);
      }
      break;

    case 'l':



      {
        int offset = given & 0xff;
        int multiplier = (given & 0x00000100) ? 4 : 1;

        func (stream, "[%s", regnames[regname_selected].reg_names [(given >> 16) & 0xf]);

        if (multiplier > 1)
   {
     value_in_comment = offset * multiplier;
     if (((given & (1 << 23)) == 0))
       value_in_comment = - value_in_comment;
   }

        if (offset)
   {
     if ((given & (1 << 24)))
       func (stream, ", #%s%d]%s",
      ((given & (1 << 23)) == 0) ? "-" : "",
      offset * multiplier,
      (given & (1 << 21)) ? "!" : "");
     else
       func (stream, "], #%s%d",
      ((given & (1 << 23)) == 0) ? "-" : "",
      offset * multiplier);
   }
        else
   func (stream, "]");
      }
      break;

    case 'r':
      {
        int imm4 = (given >> 4) & 0xf;
        int puw_bits = ((given >> 22) & 6) | ((given >> 21) & 1);
        int ubit = ! ((given & (1 << 23)) == 0);
        const char *rm = regnames[regname_selected].reg_names [given & 0xf];
        const char *rn = regnames[regname_selected].reg_names [(given >> 16) & 0xf];

        switch (puw_bits)
   {
   case 1:
   case 3:
     func (stream, "[%s], %c%s", rn, ubit ? '+' : '-', rm);
     if (imm4)
       func (stream, ", lsl #%d", imm4);
     break;

   case 4:
   case 5:
   case 6:
   case 7:
     func (stream, "[%s, %c%s", rn, ubit ? '+' : '-', rm);
     if (imm4 > 0)
       func (stream, ", lsl #%d", imm4);
     func (stream, "]");
     if (puw_bits == 5 || puw_bits == 7)
       func (stream, "!");
     break;

   default:
     func (stream, "INVALID");
   }
      }
      break;

    case 'i':
      {
        long imm5;
        imm5 = ((given & 0x100) >> 4) | (given & 0xf);
        func (stream, "%ld", (imm5 == 0) ? 32 : imm5);
      }
      break;

    default:
      abort ();
    }
  }
     }
   else
     func (stream, "%c", *c);
 }

      if (value_in_comment > 32 || value_in_comment < -16)
 func (stream, "\t; 0x%lx", (value_in_comment & 0xffffffffUL));

      if (is_unpredictable)
 func (stream, "\t; <UNPREDICTABLE>");

      return 1;
    }
  return 0;
}






static signed long
print_arm_address (bfd_vma pc, struct disassemble_info *info, long given)
{
  void *stream = info->stream;
  fprintf_ftype func = info->fprintf_func;
  bfd_vma offset = 0;

  if (((given & 0x000f0000) == 0x000f0000)
      && ((given & 0x02000000) == 0))
    {
      offset = given & 0xfff;

      func (stream, "[pc");

      if ((given & (1 << 24)))
 {


   if ((given & (1 << 21)) || ((given & (1 << 23)) == 0) || offset)
     func (stream, ", #%s%d", ((given & (1 << 23)) == 0) ? "-" : "", (int) offset);

   if (((given & (1 << 23)) == 0))
     offset = -offset;

   offset += pc + 8;





   func (stream, "]%s", (given & (1 << 21)) ? "!" : "");
 }
      else
 {
   func (stream, "], #%s%d", ((given & (1 << 23)) == 0) ? "-" : "", (int) offset);


   offset = pc + 8;
 }

      func (stream, "\t; ");
      info->print_address_func (offset, info);
      offset = 0;
    }
  else
    {
      func (stream, "[%s",
     regnames[regname_selected].reg_names[(given >> 16) & 0xf]);

      if ((given & (1 << 24)))
 {
   if ((given & 0x02000000) == 0)
     {

       offset = given & 0xfff;
       if ((given & (1 << 21)) || ((given & (1 << 23)) == 0) || offset)
  func (stream, ", #%s%d", ((given & (1 << 23)) == 0) ? "-" : "", (int) offset);
     }
   else
     {
       func (stream, ", %s", ((given & (1 << 23)) == 0) ? "-" : "");
       arm_decode_shift (given, func, stream, 1);
     }

   func (stream, "]%s",
  (given & (1 << 21)) ? "!" : "");
 }
      else
 {
   if ((given & 0x02000000) == 0)
     {

       offset = given & 0xfff;
       func (stream, "], #%s%d",
      ((given & (1 << 23)) == 0) ? "-" : "", (int) offset);
     }
   else
     {
       func (stream, "], %s",
      ((given & (1 << 23)) == 0) ? "-" : "");
       arm_decode_shift (given, func, stream, 1);
     }
 }
    }

  return (signed long) offset;
}





static bfd_boolean
print_insn_neon (struct disassemble_info *info, long given, bfd_boolean thumb)
{
  const struct opcode32 *insn;
  void *stream = info->stream;
  fprintf_ftype func = info->fprintf_func;

  if (thumb)
    {
      if ((given & 0xef000000) == 0xef000000)
 {

   unsigned long bit28 = given & (1 << 28);

   given &= 0x00ffffff;
   if (bit28)
            given |= 0xf3000000;
          else
     given |= 0xf2000000;
 }
      else if ((given & 0xff000000) == 0xf9000000)
 given ^= 0xf9000000 ^ 0xf4000000;
      else
 return 0;
    }

  for (insn = neon_opcodes; insn->assembler; insn++)
    {
      if ((given & insn->mask) == insn->value)
 {
   signed long value_in_comment = 0;
   bfd_boolean is_unpredictable = 0;
   const char *c;

   for (c = insn->assembler; *c; c++)
     {
       if (*c == '%')
  {
    switch (*++c)
      {
      case '%':
        func (stream, "%%");
        break;

      case 'u':
        if (thumb && ifthen_state)
   is_unpredictable = 1;


      case 'c':
        if (thumb && ifthen_state)
   func (stream, "%s", arm_conditional[((ifthen_state >> 4) & 0xf)]);
        break;

      case 'A':
        {
   static const unsigned char enc[16] =
   {
     0x4, 0x14,
     0x4,
     0x4,
     0x3,
     0x13,
     0x3,
     0x1,
     0x2,
     0x12,
     0x2,
     0, 0, 0, 0, 0
   };
   int rd = ((given >> 12) & 0xf) | (((given >> 22) & 1) << 4);
   int rn = ((given >> 16) & 0xf);
   int rm = ((given >> 0) & 0xf);
   int align = ((given >> 4) & 0x3);
   int type = ((given >> 8) & 0xf);
   int n = enc[type] & 0xf;
   int stride = (enc[type] >> 4) + 1;
   int ix;

   func (stream, "{");
   if (stride > 1)
     for (ix = 0; ix != n; ix++)
       func (stream, "%sd%d", ix ? "," : "", rd + ix * stride);
   else if (n == 1)
     func (stream, "d%d", rd);
   else
     func (stream, "d%d-d%d", rd, rd + n - 1);
   func (stream, "}, [%s", regnames[regname_selected].reg_names[rn]);
   if (align)
     func (stream, " :%d", 32 << align);
   func (stream, "]");
   if (rm == 0xd)
     func (stream, "!");
   else if (rm != 0xf)
     func (stream, ", %s", regnames[regname_selected].reg_names[rm]);
        }
        break;

      case 'B':
        {
   int rd = ((given >> 12) & 0xf) | (((given >> 22) & 1) << 4);
   int rn = ((given >> 16) & 0xf);
   int rm = ((given >> 0) & 0xf);
   int idx_align = ((given >> 4) & 0xf);
                        int align = 0;
   int size = ((given >> 10) & 0x3);
   int idx = idx_align >> (size + 1);
                        int length = ((given >> 8) & 3) + 1;
                        int stride = 1;
                        int i;

                        if (length > 1 && size > 0)
                          stride = (idx_align & (1 << size)) ? 2 : 1;

                        switch (length)
                          {
                          case 1:
                            {
                              int amask = (1 << size) - 1;
                              if ((idx_align & (1 << size)) != 0)
                                return 0;
                              if (size > 0)
                                {
                                  if ((idx_align & amask) == amask)
                                    align = 8 << size;
                                  else if ((idx_align & amask) != 0)
                                    return 0;
                                }
                              }
                            break;

                          case 2:
                            if (size == 2 && (idx_align & 2) != 0)
                              return 0;
                            align = (idx_align & 1) ? 16 << size : 0;
                            break;

                          case 3:
                            if ((size == 2 && (idx_align & 3) != 0)
                                || (idx_align & 1) != 0)
                              return 0;
                            break;

                          case 4:
                            if (size == 2)
                              {
                                if ((idx_align & 3) == 3)
                                  return 0;
                                align = (idx_align & 3) * 64;
                              }
                            else
                              align = (idx_align & 1) ? 32 << size : 0;
                            break;

                          default:
                            abort ();
                          }

   func (stream, "{");
                        for (i = 0; i < length; i++)
                          func (stream, "%sd%d[%d]", (i == 0) ? "" : ",",
                            rd + i * stride, idx);
                        func (stream, "}, [%s", regnames[regname_selected].reg_names[rn]);
   if (align)
     func (stream, " :%d", align);
   func (stream, "]");
   if (rm == 0xd)
     func (stream, "!");
   else if (rm != 0xf)
     func (stream, ", %s", regnames[regname_selected].reg_names[rm]);
        }
        break;

      case 'C':
        {
   int rd = ((given >> 12) & 0xf) | (((given >> 22) & 1) << 4);
   int rn = ((given >> 16) & 0xf);
   int rm = ((given >> 0) & 0xf);
   int align = ((given >> 4) & 0x1);
   int size = ((given >> 6) & 0x3);
   int type = ((given >> 8) & 0x3);
   int n = type + 1;
   int stride = ((given >> 5) & 0x1);
   int ix;

   if (stride && (n == 1))
     n++;
   else
     stride++;

   func (stream, "{");
   if (stride > 1)
     for (ix = 0; ix != n; ix++)
       func (stream, "%sd%d[]", ix ? "," : "", rd + ix * stride);
   else if (n == 1)
     func (stream, "d%d[]", rd);
   else
     func (stream, "d%d[]-d%d[]", rd, rd + n - 1);
   func (stream, "}, [%s", regnames[regname_selected].reg_names[rn]);
   if (align)
     {
                            align = (8 * (type + 1)) << size;
                            if (type == 3)
                              align = (size > 1) ? align >> 1 : align;
       if (type == 2 || (type == 0 && !size))
         func (stream, " :<bad align %d>", align);
       else
         func (stream, " :%d", align);
     }
   func (stream, "]");
   if (rm == 0xd)
     func (stream, "!");
   else if (rm != 0xf)
     func (stream, ", %s", regnames[regname_selected].reg_names[rm]);
        }
        break;

      case 'D':
        {
   int raw_reg = (given & 0xf) | ((given >> 1) & 0x10);
   int size = (given >> 20) & 3;
   int reg = raw_reg & ((4 << size) - 1);
   int ix = raw_reg >> size >> 2;

   func (stream, "d%d[%d]", reg, ix);
        }
        break;

      case 'E':

        {
   int bits = 0;
   int cmode = (given >> 8) & 0xf;
   int op = (given >> 5) & 0x1;
   unsigned long value = 0, hival = 0;
   unsigned shift;
                        int size = 0;
                        int isfloat = 0;

   bits |= ((given >> 24) & 1) << 7;
   bits |= ((given >> 16) & 7) << 4;
   bits |= ((given >> 0) & 15) << 0;

   if (cmode < 8)
     {
       shift = (cmode >> 1) & 3;
       value = (unsigned long) bits << (8 * shift);
                            size = 32;
     }
   else if (cmode < 12)
     {
       shift = (cmode >> 1) & 1;
       value = (unsigned long) bits << (8 * shift);
                            size = 16;
     }
   else if (cmode < 14)
     {
       shift = (cmode & 1) + 1;
       value = (unsigned long) bits << (8 * shift);
       value |= (1ul << (8 * shift)) - 1;
                            size = 32;
     }
   else if (cmode == 14)
     {
       if (op)
         {

    int ix;
    unsigned long mask;

    value = 0;
                                hival = 0;
    for (ix = 7; ix >= 0; ix--)
      {
        mask = ((bits >> ix) & 1) ? 0xff : 0;
                                    if (ix <= 3)
          value = (value << 8) | mask;
                                    else
                                      hival = (hival << 8) | mask;
      }
                                size = 64;
         }
                            else
                              {

                                value = (unsigned long) bits;
                                size = 8;
                              }
     }
   else if (!op)
     {

       int tmp;

       value = (unsigned long) (bits & 0x7f) << 19;
       value |= (unsigned long) (bits & 0x80) << 24;
       tmp = bits & 0x40 ? 0x3c : 0x40;
       value |= (unsigned long) tmp << 24;
                            size = 32;
                            isfloat = 1;
     }
   else
     {
       func (stream, "<illegal constant %.8x:%x:%x>",
                                  bits, cmode, op);
                            size = 32;
       break;
     }
                        switch (size)
                          {
                          case 8:
       func (stream, "#%ld\t; 0x%.2lx", value, value);
                            break;

                          case 16:
                            func (stream, "#%ld\t; 0x%.4lx", value, value);
                            break;

                          case 32:
                            if (isfloat)
                              {
                                unsigned char valbytes[4];



                                valbytes[0] = value & 0xff;
                                valbytes[1] = (value >> 8) & 0xff;
                                valbytes[2] = (value >> 16) & 0xff;
                                valbytes[3] = (value >> 24) & 0xff;
                                float * fvalue = (float *) valbytes;


                                func (stream, "#%.7g\t; 0x%.8lx", *fvalue,
                                      value);
                              }
                            else
                              func (stream, "#%ld\t; 0x%.8lx",
        (long) (((value & 0x80000000L) != 0)
         ? value | ~0xffffffffL : value),
        value);
                            break;

                          case 64:
                            func (stream, "#0x%.8lx%.8lx", hival, value);
                            break;

                          default:
                            abort ();
                          }
        }
        break;

      case 'F':
        {
   int regno = ((given >> 16) & 0xf) | ((given >> (7 - 4)) & 0x10);
   int num = (given >> 8) & 0x3;

   if (!num)
     func (stream, "{d%d}", regno);
   else if (num + regno >= 32)
     func (stream, "{d%d-<overflow reg d%d}", regno, regno + num);
   else
     func (stream, "{d%d-d%d}", regno, regno + num);
        }
        break;


      case '0': case '1': case '2': case '3': case '4':
      case '5': case '6': case '7': case '8': case '9':
        {
   int width;
   unsigned long value;

   c = arm_decode_bitfield (c, given, &value, &width);

   switch (*c)
     {
     case 'r':
       func (stream, "%s", regnames[regname_selected].reg_names[value]);
       break;
     case 'd':
       func (stream, "%ld", value);
       value_in_comment = value;
       break;
     case 'e':
       func (stream, "%ld", (1ul << width) - value);
       break;

     case 'S':
     case 'T':
     case 'U':

       {
         int base = 8 << (*c - 'S');
         int limit;
         unsigned low, high;

         c++;
         if (*c >= '0' && *c <= '9')
    limit = *c - '0';
         else if (*c >= 'a' && *c <= 'f')
    limit = *c - 'a' + 10;
         else
    abort ();
         low = limit >> 2;
         high = limit & 3;

         if (value < low || value > high)
    func (stream, "<illegal width %d>", base << value);
         else
    func (stream, "%d", base << value);
       }
       break;
     case 'R':
       if (given & (1 << 6))
         goto Q;

     case 'D':
       func (stream, "d%ld", value);
       break;
     case 'Q':
     Q:
       if (value & 1)
         func (stream, "<illegal reg q%ld.5>", value >> 1);
       else
         func (stream, "q%ld", value >> 1);
       break;

     case '`':
       c++;
       if (value == 0)
         func (stream, "%c", *c);
       break;
     case '\'':
       c++;
       if (value == ((1ul << width) - 1))
         func (stream, "%c", *c);
       break;
     case '?':
       func (stream, "%c", c[(1 << width) - (int) value]);
       c += 1 << width;
       break;
     default:
       abort ();
     }
   break;

        default:
   abort ();
        }
      }
  }
       else
  func (stream, "%c", *c);
     }

   if (value_in_comment > 32 || value_in_comment < -16)
     func (stream, "\t; 0x%lx", value_in_comment);

   if (is_unpredictable)
     func (stream, "\t; <UNPREDICTABLE>");

   return 1;
 }
    }
  return 0;
}



static const char *
banked_regname (unsigned reg)
{
  switch (reg)
    {
      case 15: return "CPSR";
      case 32: return "R8_usr";
      case 33: return "R9_usr";
      case 34: return "R10_usr";
      case 35: return "R11_usr";
      case 36: return "R12_usr";
      case 37: return "SP_usr";
      case 38: return "LR_usr";
      case 40: return "R8_fiq";
      case 41: return "R9_fiq";
      case 42: return "R10_fiq";
      case 43: return "R11_fiq";
      case 44: return "R12_fiq";
      case 45: return "SP_fiq";
      case 46: return "LR_fiq";
      case 48: return "LR_irq";
      case 49: return "SP_irq";
      case 50: return "LR_svc";
      case 51: return "SP_svc";
      case 52: return "LR_abt";
      case 53: return "SP_abt";
      case 54: return "LR_und";
      case 55: return "SP_und";
      case 60: return "LR_mon";
      case 61: return "SP_mon";
      case 62: return "ELR_hyp";
      case 63: return "SP_hyp";
      case 79: return "SPSR";
      case 110: return "SPSR_fiq";
      case 112: return "SPSR_irq";
      case 114: return "SPSR_svc";
      case 116: return "SPSR_abt";
      case 118: return "SPSR_und";
      case 124: return "SPSR_mon";
      case 126: return "SPSR_hyp";
      default: return ((void *)0);
    }
}


static const char *
data_barrier_option (unsigned option)
{
  switch (option & 0xf)
    {
    case 0xf: return "sy";
    case 0xe: return "st";
    case 0xd: return "ld";
    case 0xb: return "ish";
    case 0xa: return "ishst";
    case 0x9: return "ishld";
    case 0x7: return "un";
    case 0x6: return "unst";
    case 0x5: return "nshld";
    case 0x3: return "osh";
    case 0x2: return "oshst";
    case 0x1: return "oshld";
    default: return ((void *)0);
    }
}



static void
print_insn_arm (bfd_vma pc, struct disassemble_info *info, long given)
{
  const struct opcode32 *insn;
  void *stream = info->stream;
  fprintf_ftype func = info->fprintf_func;
  struct arm_private_data *private_data = info->private_data;

  if (print_insn_coprocessor (pc, info, given, 0))
    return;

  if (print_insn_neon (info, given, 0))
    return;

  for (insn = arm_opcodes; insn->assembler; insn++)
    {
      if ((given & insn->mask) != insn->value)
 continue;

      if ((insn->arch & private_data->features.core) == 0)
 continue;




      if ((given & 0xF0000000) != 0xF0000000
   || (insn->mask & 0xF0000000) == 0xF0000000
   || (insn->mask == 0 && insn->value == 0))
 {
   unsigned long u_reg = 16;
   unsigned long U_reg = 16;
   bfd_boolean is_unpredictable = 0;
   signed long value_in_comment = 0;
   const char *c;

   for (c = insn->assembler; *c; c++)
     {
       if (*c == '%')
  {
    bfd_boolean allow_unpredictable = 0;

    switch (*++c)
      {
      case '%':
        func (stream, "%%");
        break;

      case 'a':
        value_in_comment = print_arm_address (pc, info, given);
        break;

      case 'P':


        value_in_comment = print_arm_address (pc, info, given | (1 << 24));
        break;

      case 'S':
        allow_unpredictable = 1;
      case 's':
                      if ((given & 0x004f0000) == 0x004f0000)
   {

     bfd_vma offset = ((given & 0xf00) >> 4) | (given & 0xf);

     if ((given & (1 << 24)))
       {

         if (offset || ((given & (1 << 23)) == 0))
    func (stream, "[pc, #%s%d]\t; ",
          ((given & (1 << 23)) == 0) ? "-" : "", (int) offset);
         else
    func (stream, "[pc]\t; ");
         if (((given & (1 << 23)) == 0))
    offset = -offset;
         info->print_address_func (offset + pc + 8, info);
       }
     else
       {

         func (stream, "[pc], #%s%d",
        ((given & (1 << 23)) == 0) ? "-" : "", (int) offset);
         if (! allow_unpredictable)
    is_unpredictable = 1;
       }
   }
        else
   {
     int offset = ((given & 0xf00) >> 4) | (given & 0xf);

     func (stream, "[%s",
    regnames[regname_selected].reg_names[(given >> 16) & 0xf]);

     if ((given & (1 << 24)))
       {
         if ((given & (1 << 22)))
    {


      if ((given & (1 << 21)) || ((given & (1 << 23)) == 0)
          || offset)
        func (stream, ", #%s%d",
       ((given & (1 << 23)) == 0) ? "-" : "", offset);

      if (((given & (1 << 23)) == 0))
        offset = -offset;

      value_in_comment = offset;
    }
         else
    {

      func (stream, ", %s%s",
     ((given & (1 << 23)) == 0) ? "-" : "",
     regnames[regname_selected].reg_names[given & 0xf]);



      if (! allow_unpredictable
          && (given & (1 << 21))
          && ((given & 0xf) == ((given >> 12) & 0xf)))
        is_unpredictable = 1;
    }

         func (stream, "]%s",
        (given & (1 << 21)) ? "!" : "");
       }
     else
       {
         if ((given & (1 << 22)))
    {


      func (stream, "], #%s%d",
     ((given & (1 << 23)) == 0) ? "-" : "", offset);
      if (((given & (1 << 23)) == 0))
        offset = -offset;
      value_in_comment = offset;
    }
         else
    {

      func (stream, "], %s%s",
     ((given & (1 << 23)) == 0) ? "-" : "",
     regnames[regname_selected].reg_names[given & 0xf]);



      if (! allow_unpredictable
          && (given & 0xf) == ((given >> 12) & 0xf))
        is_unpredictable = 1;
    }

         if (! allow_unpredictable)
    {



      if ((given & (1 << 21))


          || (! (given & (1 << 22)) && ((given & 0xf) == 0xf)))
        is_unpredictable = 1;
    }
       }
   }
        break;

      case 'b':
        {
   bfd_vma disp = (((given & 0xffffff) ^ 0x800000) - 0x800000);
   info->print_address_func (disp * 4 + pc + 8, info);
        }
        break;

      case 'c':
        if (((given >> 28) & 0xf) != 0xe)
   func (stream, "%s",
         arm_conditional [(given >> 28) & 0xf]);
        break;

      case 'm':
        {
   int started = 0;
   int reg;

   func (stream, "{");
   for (reg = 0; reg < 16; reg++)
     if ((given & (1 << reg)) != 0)
       {
         if (started)
    func (stream, ", ");
         started = 1;
         func (stream, "%s", regnames[regname_selected].reg_names[reg]);
       }
   func (stream, "}");
   if (! started)
     is_unpredictable = 1;
        }
        break;

      case 'q':
        arm_decode_shift (given, func, stream, 0);
        break;

      case 'o':
        if ((given & 0x02000000) != 0)
   {
     unsigned int rotate = (given & 0xf00) >> 7;
     unsigned int immed = (given & 0xff);
     unsigned int a, i;

     a = (((immed << (32 - rotate))
    | (immed >> rotate)) & 0xffffffff);


     for (i = 0; i < 32; i += 2)
       if ((a << i | a >> (32 - i)) <= 0xff)
         break;

     if (i != rotate)
       func (stream, "#%d, %d", immed, rotate);
     else
       func (stream, "#%d", a);
     value_in_comment = a;
   }
        else
   arm_decode_shift (given, func, stream, 1);
        break;

      case 'p':
        if ((given & 0x0000f000) == 0x0000f000)
   {



     if ((private_data->features.core & 0x00001000) == 0)
       func (stream, "p");
   }
        break;

      case 't':
        if ((given & 0x01200000) == 0x00200000)
   func (stream, "t");
        break;

      case 'A':
        {
   int offset = given & 0xff;

   value_in_comment = offset * 4;
   if (((given & (1 << 23)) == 0))
     value_in_comment = - value_in_comment;

   func (stream, "[%s", regnames[regname_selected].reg_names [(given >> 16) & 0xf]);

   if ((given & (1 << 24)))
     {
       if (offset)
         func (stream, ", #%d]%s",
        (int) value_in_comment,
        (given & (1 << 21)) ? "!" : "");
       else
         func (stream, "]");
     }
   else
     {
       func (stream, "]");

       if ((given & (1 << 21)))
         {
    if (offset)
      func (stream, ", #%d", (int) value_in_comment);
         }
       else
         {
    func (stream, ", {%d}", (int) offset);
    value_in_comment = offset;
         }
     }
        }
        break;

      case 'B':

        {
   bfd_vma address;
   bfd_vma offset = 0;

   if (! ((given & (1 << 23)) == 0))

     offset = (-1) ^ 0x00ffffff;


   offset += given & 0x00ffffff;
   offset <<= 2;
   address = offset + pc + 8;

   if (given & 0x01000000)

     address += 2;

          info->print_address_func (address, info);
        }
        break;

      case 'C':
        if ((given & 0x02000200) == 0x200)
   {
     const char * name;
     unsigned sysm = (given & 0x004f0000) >> 16;

     sysm |= (given & 0x300) >> 4;
     name = banked_regname (sysm);

     if (name != ((void *)0))
       func (stream, "%s", name);
     else
       func (stream, "(UNDEF: %lu)", (unsigned long) sysm);
   }
        else
   {
     func (stream, "%cPSR_",
    (given & 0x00400000) ? 'S' : 'C');
     if (given & 0x80000)
       func (stream, "f");
     if (given & 0x40000)
       func (stream, "s");
     if (given & 0x20000)
       func (stream, "x");
     if (given & 0x10000)
       func (stream, "c");
   }
        break;

      case 'U':
        if ((given & 0xf0) == 0x60)
   {
     switch (given & 0xf)
       {
       case 0xf: func (stream, "sy"); break;
       default:
         func (stream, "#%d", (int) given & 0xf);
         break;
       }
   }
        else
   {
     const char * opt = data_barrier_option (given & 0xf);
     if (opt != ((void *)0))
       func (stream, "%s", opt);
     else
         func (stream, "#%d", (int) given & 0xf);
   }
        break;

      case '0': case '1': case '2': case '3': case '4':
      case '5': case '6': case '7': case '8': case '9':
        {
   int width;
   unsigned long value;

   c = arm_decode_bitfield (c, given, &value, &width);

   switch (*c)
     {
     case 'R':
       if (value == 15)
         is_unpredictable = 1;

     case 'r':
     case 'T':

       if (*c == 'T')
         ++value;

       if (c[1] == 'u')
         {

    ++ c;

    if (u_reg == value)
      is_unpredictable = 1;
    u_reg = value;
         }
       if (c[1] == 'U')
         {

    ++ c;

    if (U_reg == value)
      is_unpredictable = 1;
    U_reg = value;
         }
       func (stream, "%s", regnames[regname_selected].reg_names[value]);
       break;
     case 'd':
       func (stream, "%ld", value);
       value_in_comment = value;
       break;
     case 'b':
       func (stream, "%ld", value * 8);
       value_in_comment = value * 8;
       break;
     case 'W':
       func (stream, "%ld", value + 1);
       value_in_comment = value + 1;
       break;
     case 'x':
       func (stream, "0x%08lx", value);



       if ((given & 0x0fffffff) == 0x0FF00000)
         func (stream, "\t; IMB");
       else if ((given & 0x0fffffff) == 0x0FF00001)
         func (stream, "\t; IMBRange");
       break;
     case 'X':
       func (stream, "%01lx", value & 0xf);
       value_in_comment = value;
       break;
     case '`':
       c++;
       if (value == 0)
         func (stream, "%c", *c);
       break;
     case '\'':
       c++;
       if (value == ((1ul << width) - 1))
         func (stream, "%c", *c);
       break;
     case '?':
       func (stream, "%c", c[(1 << width) - (int) value]);
       c += 1 << width;
       break;
     default:
       abort ();
     }
   break;

        case 'e':
   {
     int imm;

     imm = (given & 0xf) | ((given & 0xfff00) >> 4);
     func (stream, "%d", imm);
     value_in_comment = imm;
   }
   break;

        case 'E':


   {
     long msb = (given & 0x001f0000) >> 16;
     long lsb = (given & 0x00000f80) >> 7;
     long w = msb - lsb + 1;

     if (w > 0)
       func (stream, "#%lu, #%lu", lsb, w);
     else
       func (stream, "(invalid: %lu:%lu)", lsb, msb);
   }
   break;

        case 'R':

   {
     const char * name;
     unsigned sysm = (given & 0x004f0000) >> 16;

     sysm |= (given & 0x300) >> 4;
     name = banked_regname (sysm);

     if (name != ((void *)0))
       func (stream, "%s", name);
     else
       func (stream, "(UNDEF: %lu)", (unsigned long) sysm);
   }
   break;

        case 'V':


   {
     long hi = (given & 0x000f0000) >> 4;
     long lo = (given & 0x00000fff);
     long imm16 = hi | lo;

     func (stream, "#%lu", imm16);
     value_in_comment = imm16;
   }
   break;

        default:
   abort ();
        }
      }
  }
       else
  func (stream, "%c", *c);
     }

   if (value_in_comment > 32 || value_in_comment < -16)
     func (stream, "\t; 0x%lx", (value_in_comment & 0xffffffffUL));

   if (is_unpredictable)
     func (stream, "\t; <UNPREDICTABLE>");

   return;
 }
    }
  abort ();
}



static void
print_insn_thumb16 (bfd_vma pc, struct disassemble_info *info, long given)
{
  const struct opcode16 *insn;
  void *stream = info->stream;
  fprintf_ftype func = info->fprintf_func;

  for (insn = thumb_opcodes; insn->assembler; insn++)
    if ((given & insn->mask) == insn->value)
      {
 signed long value_in_comment = 0;
 const char *c = insn->assembler;

 for (; *c; c++)
   {
     int domaskpc = 0;
     int domasklr = 0;

     if (*c != '%')
       {
  func (stream, "%c", *c);
  continue;
       }

     switch (*++c)
       {
       case '%':
  func (stream, "%%");
  break;

       case 'c':
  if (ifthen_state)
    func (stream, "%s", arm_conditional[((ifthen_state >> 4) & 0xf)]);
  break;

       case 'C':
  if (ifthen_state)
    func (stream, "%s", arm_conditional[((ifthen_state >> 4) & 0xf)]);
  else
    func (stream, "s");
  break;

       case 'I':
  {
    unsigned int tmp;

    ifthen_next_state = given & 0xff;
    for (tmp = given << 1; tmp & 0xf; tmp <<= 1)
      func (stream, ((given ^ tmp) & 0x10) ? "e" : "t");
    func (stream, "\t%s", arm_conditional[(given >> 4) & 0xf]);
  }
  break;

       case 'x':
  if (ifthen_next_state)
    func (stream, "\t; unpredictable branch in IT block\n");
  break;

       case 'X':
  if (ifthen_state)
    func (stream, "\t; unpredictable <IT:%s>",
   arm_conditional[((ifthen_state >> 4) & 0xf)]);
  break;

       case 'S':
  {
    long reg;

    reg = (given >> 3) & 0x7;
    if (given & (1 << 6))
      reg += 8;

    func (stream, "%s", regnames[regname_selected].reg_names[reg]);
  }
  break;

       case 'D':
  {
    long reg;

    reg = given & 0x7;
    if (given & (1 << 7))
      reg += 8;

    func (stream, "%s", regnames[regname_selected].reg_names[reg]);
  }
  break;

       case 'N':
  if (given & (1 << 8))
    domasklr = 1;

       case 'O':
  if (*c == 'O' && (given & (1 << 8)))
    domaskpc = 1;

       case 'M':
  {
    int started = 0;
    int reg;

    func (stream, "{");



    for (reg = 0; (reg < 8); reg++)
      if ((given & (1 << reg)) != 0)
        {
   if (started)
     func (stream, ", ");
   started = 1;
   func (stream, "%s", regnames[regname_selected].reg_names[reg]);
        }

    if (domasklr)
      {
        if (started)
   func (stream, ", ");
        started = 1;
        func (stream, "%s", regnames[regname_selected].reg_names[14] );
      }

    if (domaskpc)
      {
        if (started)
   func (stream, ", ");
        func (stream, "%s", regnames[regname_selected].reg_names[15] );
      }

    func (stream, "}");
  }
  break;

       case 'W':



  if ((given & (1 << ((given & 0x0700) >> 8))) == 0)
    func (stream, "!");
        break;

       case 'b':

  {
    bfd_vma address = (pc + 4
         + ((given & 0x00f8) >> 2)
         + ((given & 0x0200) >> 3));
    info->print_address_func (address, info);
  }
  break;

       case 's':


  {
    long imm = (given & 0x07c0) >> 6;
    if (imm == 0)
      imm = 32;
    func (stream, "#%ld", imm);
  }
  break;

       case '0': case '1': case '2': case '3': case '4':
       case '5': case '6': case '7': case '8': case '9':
  {
    int bitstart = *c++ - '0';
    int bitend = 0;

    while (*c >= '0' && *c <= '9')
      bitstart = (bitstart * 10) + *c++ - '0';

    switch (*c)
      {
      case '-':
        {
   bfd_vma reg;

   c++;
   while (*c >= '0' && *c <= '9')
     bitend = (bitend * 10) + *c++ - '0';
   if (!bitend)
     abort ();
   reg = given >> bitstart;
   reg &= (2 << (bitend - bitstart)) - 1;

   switch (*c)
     {
     case 'r':
       func (stream, "%s", regnames[regname_selected].reg_names[reg]);
       break;

     case 'd':
       func (stream, "%ld", (long) reg);
       value_in_comment = reg;
       break;

     case 'H':
       func (stream, "%ld", (long) (reg << 1));
       value_in_comment = reg << 1;
       break;

     case 'W':
       func (stream, "%ld", (long) (reg << 2));
       value_in_comment = reg << 2;
       break;

     case 'a':



       info->print_address_func
         (((pc + 4) & ~3) + (reg << 2), info);
       value_in_comment = 0;
       break;

     case 'x':
       func (stream, "0x%04lx", (long) reg);
       break;

     case 'B':
       reg = ((reg ^ (1 << bitend)) - (1 << bitend));
       info->print_address_func (reg * 2 + pc + 4, info);
       value_in_comment = 0;
       break;

     case 'c':
       func (stream, "%s", arm_conditional [reg]);
       break;

     default:
       abort ();
     }
        }
        break;

      case '\'':
        c++;
        if ((given & (1 << bitstart)) != 0)
   func (stream, "%c", *c);
        break;

      case '?':
        ++c;
        if ((given & (1 << bitstart)) != 0)
   func (stream, "%c", *c++);
        else
   func (stream, "%c", *++c);
        break;

      default:
        abort ();
      }
  }
  break;

       default:
  abort ();
       }
   }

 if (value_in_comment > 32 || value_in_comment < -16)
   func (stream, "\t; 0x%lx", value_in_comment);
 return;
      }


  abort ();
}



static const char *
psr_name (int regno)
{
  switch (regno)
    {
    case 0: return "APSR";
    case 1: return "IAPSR";
    case 2: return "EAPSR";
    case 3: return "PSR";
    case 5: return "IPSR";
    case 6: return "EPSR";
    case 7: return "IEPSR";
    case 8: return "MSP";
    case 9: return "PSP";
    case 16: return "PRIMASK";
    case 17: return "BASEPRI";
    case 18: return "BASEPRI_MAX";
    case 19: return "FAULTMASK";
    case 20: return "CONTROL";
    default: return "<unknown>";
    }
}



static void
print_insn_thumb32 (bfd_vma pc, struct disassemble_info *info, long given)
{
  const struct opcode32 *insn;
  void *stream = info->stream;
  fprintf_ftype func = info->fprintf_func;

  if (print_insn_coprocessor (pc, info, given, 1))
    return;

  if (print_insn_neon (info, given, 1))
    return;

  for (insn = thumb32_opcodes; insn->assembler; insn++)
    if ((given & insn->mask) == insn->value)
      {
 bfd_boolean is_unpredictable = 0;
 signed long value_in_comment = 0;
 const char *c = insn->assembler;

 for (; *c; c++)
   {
     if (*c != '%')
       {
  func (stream, "%c", *c);
  continue;
       }

     switch (*++c)
       {
       case '%':
  func (stream, "%%");
  break;

       case 'c':
  if (ifthen_state)
    func (stream, "%s", arm_conditional[((ifthen_state >> 4) & 0xf)]);
  break;

       case 'x':
  if (ifthen_next_state)
    func (stream, "\t; unpredictable branch in IT block\n");
  break;

       case 'X':
  if (ifthen_state)
    func (stream, "\t; unpredictable <IT:%s>",
   arm_conditional[((ifthen_state >> 4) & 0xf)]);
  break;

       case 'I':
  {
    unsigned int imm12 = 0;

    imm12 |= (given & 0x000000ffu);
    imm12 |= (given & 0x00007000u) >> 4;
    imm12 |= (given & 0x04000000u) >> 15;
    func (stream, "#%u", imm12);
    value_in_comment = imm12;
  }
  break;

       case 'M':
  {
    unsigned int bits = 0, imm, imm8, mod;

    bits |= (given & 0x000000ffu);
    bits |= (given & 0x00007000u) >> 4;
    bits |= (given & 0x04000000u) >> 15;
    imm8 = (bits & 0x0ff);
    mod = (bits & 0xf00) >> 8;
    switch (mod)
      {
      case 0: imm = imm8; break;
      case 1: imm = ((imm8 << 16) | imm8); break;
      case 2: imm = ((imm8 << 24) | (imm8 << 8)); break;
      case 3: imm = ((imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8); break;
      default:
        mod = (bits & 0xf80) >> 7;
        imm8 = (bits & 0x07f) | 0x80;
        imm = (((imm8 << (32 - mod)) | (imm8 >> mod)) & 0xffffffff);
      }
    func (stream, "#%u", imm);
    value_in_comment = imm;
  }
  break;

       case 'J':
  {
    unsigned int imm = 0;

    imm |= (given & 0x000000ffu);
    imm |= (given & 0x00007000u) >> 4;
    imm |= (given & 0x04000000u) >> 15;
    imm |= (given & 0x000f0000u) >> 4;
    func (stream, "#%u", imm);
    value_in_comment = imm;
  }
  break;

       case 'K':
  {
    unsigned int imm = 0;

    imm |= (given & 0x000f0000u) >> 16;
    imm |= (given & 0x00000ff0u) >> 0;
    imm |= (given & 0x0000000fu) << 12;
    func (stream, "#%u", imm);
    value_in_comment = imm;
  }
  break;

       case 'H':
  {
    unsigned int imm = 0;

    imm |= (given & 0x000f0000u) >> 4;
    imm |= (given & 0x00000fffu) >> 0;
    func (stream, "#%u", imm);
    value_in_comment = imm;
  }
  break;

       case 'V':
  {
    unsigned int imm = 0;

    imm |= (given & 0x00000fffu);
    imm |= (given & 0x000f0000u) >> 4;
    func (stream, "#%u", imm);
    value_in_comment = imm;
  }
  break;

       case 'S':
  {
    unsigned int reg = (given & 0x0000000fu);
    unsigned int stp = (given & 0x00000030u) >> 4;
    unsigned int imm = 0;
    imm |= (given & 0x000000c0u) >> 6;
    imm |= (given & 0x00007000u) >> 10;

    func (stream, "%s", regnames[regname_selected].reg_names[reg]);
    switch (stp)
      {
      case 0:
        if (imm > 0)
   func (stream, ", lsl #%u", imm);
        break;

      case 1:
        if (imm == 0)
   imm = 32;
        func (stream, ", lsr #%u", imm);
        break;

      case 2:
        if (imm == 0)
   imm = 32;
        func (stream, ", asr #%u", imm);
        break;

      case 3:
        if (imm == 0)
   func (stream, ", rrx");
        else
   func (stream, ", ror #%u", imm);
      }
  }
  break;

       case 'a':
  {
    unsigned int Rn = (given & 0x000f0000) >> 16;
    unsigned int U = ! ((given & (1 << 23)) == 0);
    unsigned int op = (given & 0x00000f00) >> 8;
    unsigned int i12 = (given & 0x00000fff);
    unsigned int i8 = (given & 0x000000ff);
    bfd_boolean writeback = 0, postind = 0;
    bfd_vma offset = 0;

    func (stream, "[%s", regnames[regname_selected].reg_names[Rn]);
    if (U)
      {
        offset = i12;
        if (Rn != 15)
   value_in_comment = offset;
      }
    else if (Rn == 15)
      offset = - (int) i12;
    else if (op == 0x0)
      {
        unsigned int Rm = (i8 & 0x0f);
        unsigned int sh = (i8 & 0x30) >> 4;

        func (stream, ", %s", regnames[regname_selected].reg_names[Rm]);
        if (sh)
   func (stream, ", lsl #%u", sh);
        func (stream, "]");
        break;
      }
    else switch (op)
      {
      case 0xE:
        offset = i8;
        break;

      case 0xC:
        offset = -i8;
        break;

      case 0xF:
        offset = i8;
        writeback = 1;
        break;

      case 0xD:
        offset = -i8;
        writeback = 1;
        break;

      case 0xB:
        offset = i8;
        postind = 1;
        break;

      case 0x9:
        offset = -i8;
        postind = 1;
        break;

      default:
        func (stream, ", <undefined>]");
        goto skip;
      }

    if (postind)
      func (stream, "], #%d", (int) offset);
    else
      {
        if (offset)
   func (stream, ", #%d", (int) offset);
        func (stream, writeback ? "]!" : "]");
      }

    if (Rn == 15)
      {
        func (stream, "\t; ");
        info->print_address_func (((pc + 4) & ~3) + offset, info);
      }
  }
       skip:
  break;

       case 'A':
  {
    unsigned int U = ! ((given & (1 << 23)) == 0);
    unsigned int W = (given & (1 << 21));
    unsigned int Rn = (given & 0x000f0000) >> 16;
    unsigned int off = (given & 0x000000ff);

    func (stream, "[%s", regnames[regname_selected].reg_names[Rn]);

    if ((given & (1 << 24)))
      {
        if (off || !U)
   {
     func (stream, ", #%c%u", U ? '+' : '-', off * 4);
     value_in_comment = off * 4 * U ? 1 : -1;
   }
        func (stream, "]");
        if (W)
   func (stream, "!");
      }
    else
      {
        func (stream, "], ");
        if (W)
   {
     func (stream, "#%c%u", U ? '+' : '-', off * 4);
     value_in_comment = off * 4 * U ? 1 : -1;
   }
        else
   {
     func (stream, "{%u}", off);
     value_in_comment = off;
   }
      }
  }
  break;

       case 'w':
  {
    unsigned int Sbit = (given & 0x01000000) >> 24;
    unsigned int type = (given & 0x00600000) >> 21;

    switch (type)
      {
      case 0: func (stream, Sbit ? "sb" : "b"); break;
      case 1: func (stream, Sbit ? "sh" : "h"); break;
      case 2:
        if (Sbit)
   func (stream, "??");
        break;
      case 3:
        func (stream, "??");
        break;
      }
  }
  break;

       case 'm':
  {
    int started = 0;
    int reg;

    func (stream, "{");
    for (reg = 0; reg < 16; reg++)
      if ((given & (1 << reg)) != 0)
        {
   if (started)
     func (stream, ", ");
   started = 1;
   func (stream, "%s", regnames[regname_selected].reg_names[reg]);
        }
    func (stream, "}");
  }
  break;

       case 'E':
  {
    unsigned int msb = (given & 0x0000001f);
    unsigned int lsb = 0;

    lsb |= (given & 0x000000c0u) >> 6;
    lsb |= (given & 0x00007000u) >> 10;
    func (stream, "#%u, #%u", lsb, msb - lsb + 1);
  }
  break;

       case 'F':
  {
    unsigned int width = (given & 0x0000001f) + 1;
    unsigned int lsb = 0;

    lsb |= (given & 0x000000c0u) >> 6;
    lsb |= (given & 0x00007000u) >> 10;
    func (stream, "#%u, #%u", lsb, width);
  }
  break;

       case 'b':
  {
    unsigned int S = (given & 0x04000000u) >> 26;
    unsigned int J1 = (given & 0x00002000u) >> 13;
    unsigned int J2 = (given & 0x00000800u) >> 11;
    bfd_vma offset = 0;

    offset |= !S << 20;
    offset |= J2 << 19;
    offset |= J1 << 18;
    offset |= (given & 0x003f0000) >> 4;
    offset |= (given & 0x000007ff) << 1;
    offset -= (1 << 20);

    info->print_address_func (pc + 4 + offset, info);
  }
  break;

       case 'B':
  {
    unsigned int S = (given & 0x04000000u) >> 26;
    unsigned int I1 = (given & 0x00002000u) >> 13;
    unsigned int I2 = (given & 0x00000800u) >> 11;
    bfd_vma offset = 0;

    offset |= !S << 24;
    offset |= !(I1 ^ S) << 23;
    offset |= !(I2 ^ S) << 22;
    offset |= (given & 0x03ff0000u) >> 4;
    offset |= (given & 0x000007ffu) << 1;
    offset -= (1 << 24);
    offset += pc + 4;


    if ((given & 0x00001000u) == 0)
        offset &= ~2u;

    info->print_address_func (offset, info);
  }
  break;

       case 's':
  {
    unsigned int shift = 0;

    shift |= (given & 0x000000c0u) >> 6;
    shift |= (given & 0x00007000u) >> 10;
    if ((given & (1 << 21)))
      func (stream, ", asr #%u", shift);
    else if (shift)
      func (stream, ", lsl #%u", shift);

  }
  break;

       case 'R':
  {
    unsigned int rot = (given & 0x00000030) >> 4;

    if (rot)
      func (stream, ", ror #%u", rot * 8);
  }
  break;

       case 'U':
  if ((given & 0xf0) == 0x60)
    {
      switch (given & 0xf)
        {
   case 0xf: func (stream, "sy"); break;
   default:
     func (stream, "#%d", (int) given & 0xf);
         break;
        }
    }
  else
    {
      const char * opt = data_barrier_option (given & 0xf);
      if (opt != ((void *)0))
        func (stream, "%s", opt);
      else
        func (stream, "#%d", (int) given & 0xf);
     }
  break;

       case 'C':
  if ((given & 0xff) == 0)
    {
      func (stream, "%cPSR_", (given & 0x100000) ? 'S' : 'C');
      if (given & 0x800)
        func (stream, "f");
      if (given & 0x400)
        func (stream, "s");
      if (given & 0x200)
        func (stream, "x");
      if (given & 0x100)
        func (stream, "c");
    }
  else if ((given & 0x20) == 0x20)
    {
      char const* name;
      unsigned sysm = (given & 0xf00) >> 8;

      sysm |= (given & 0x30);
      sysm |= (given & 0x00100000) >> 14;
      name = banked_regname (sysm);

      if (name != ((void *)0))
        func (stream, "%s", name);
      else
        func (stream, "(UNDEF: %lu)", (unsigned long) sysm);
    }
  else
    {
      func (stream, "%s", psr_name (given & 0xff));
    }
  break;

       case 'D':
  if (((given & 0xff) == 0)
      || ((given & 0x20) == 0x20))
    {
      char const* name;
      unsigned sm = (given & 0xf0000) >> 16;

      sm |= (given & 0x30);
      sm |= (given & 0x00100000) >> 14;
      name = banked_regname (sm);

      if (name != ((void *)0))
        func (stream, "%s", name);
      else
        func (stream, "(UNDEF: %lu)", (unsigned long) sm);
    }
  else
    func (stream, "%s", psr_name (given & 0xff));
  break;

       case '0': case '1': case '2': case '3': case '4':
       case '5': case '6': case '7': case '8': case '9':
  {
    int width;
    unsigned long val;

    c = arm_decode_bitfield (c, given, &val, &width);

    switch (*c)
      {
      case 'd':
        func (stream, "%lu", val);
        value_in_comment = val;
        break;

      case 'W':
        func (stream, "%lu", val * 4);
        value_in_comment = val * 4;
        break;

      case 'S':
        if (val == 13)
   is_unpredictable = 1;

      case 'R':
        if (val == 15)
   is_unpredictable = 1;

      case 'r':
        func (stream, "%s", regnames[regname_selected].reg_names[val]);
        break;

      case 'c':
        func (stream, "%s", arm_conditional[val]);
        break;

      case '\'':
        c++;
        if (val == ((1ul << width) - 1))
   func (stream, "%c", *c);
        break;

      case '`':
        c++;
        if (val == 0)
   func (stream, "%c", *c);
        break;

      case '?':
        func (stream, "%c", c[(1 << width) - (int) val]);
        c += 1 << width;
        break;

      case 'x':
        func (stream, "0x%lx", val & 0xffffffffUL);
        break;

      default:
        abort ();
      }
  }
  break;

       case 'L':



  if (((given >> 16) & 0xf) == 0xf)
    {
      bfd_vma offset = (given & 0xff) * 4;

      if ((given & (1 << 23)) == 0)
        offset = - offset;
      func (stream, "\t; ");
      info->print_address_func ((pc & ~3) + 4 + offset, info);
    }
  break;

       default:
  abort ();
       }
   }

 if (value_in_comment > 32 || value_in_comment < -16)
   func (stream, "\t; 0x%lx", value_in_comment);

 if (is_unpredictable)
   func (stream, "\t; <UNPREDICTABLE>");

 return;
      }


  abort ();
}



static void
print_insn_data (bfd_vma pc __attribute__ ((__unused__)),
   struct disassemble_info *info,
   long given)
{
  switch (info->bytes_per_chunk)
    {
    case 1:
      info->fprintf_func (info->stream, ".byte\t0x%02lx", given);
      break;
    case 2:
      info->fprintf_func (info->stream, ".short\t0x%04lx", given);
      break;
    case 4:
      info->fprintf_func (info->stream, ".word\t0x%08lx", given);
      break;
    default:
      abort ();
    }
}




bfd_boolean
arm_symbol_is_valid (asymbol * sym,
       struct disassemble_info * info __attribute__ ((__unused__)))
{
  const char * name;

  if (sym == ((void *)0))
    return 0;

  name = ((sym)->name);

  return (name && *name != '$');
}



static void
find_ifthen_state (bfd_vma pc,
     struct disassemble_info *info,
     bfd_boolean little)
{
  unsigned char b[2];
  unsigned int insn;
  int status;


  int count;
  int it_count;
  unsigned int seen_it;
  bfd_vma addr;

  ifthen_address = pc;
  ifthen_state = 0;

  addr = pc;
  count = 1;
  it_count = 0;
  seen_it = 0;



  for (;;)
    {
      if (addr == 0)
 {


   if (seen_it && (count & 1))
     break;

   return;
 }
      addr -= 2;
      status = info->read_memory_func (addr, (bfd_byte *) b, 2, info);
      if (status)
 return;

      if (little)
 insn = (b[0]) | (b[1] << 8);
      else
 insn = (b[1]) | (b[0] << 8);
      if (seen_it)
 {
   if ((insn & 0xf800) < 0xe800)
     {



       if (count & 1)
  break;
       seen_it = 0;
     }
 }
      if ((insn & 0xff00) == 0xbf00 && (insn & 0xf) != 0)
 {

   seen_it = insn;
   it_count = count >> 1;
 }
      if ((insn & 0xf800) >= 0xe800)
 count++;
      else
 count = (count + 2) | 1;

      if (count >= 8 && !seen_it)
 return;
    }

  ifthen_state = (seen_it & 0xe0) | ((seen_it << it_count) & 0x1f);
  if ((ifthen_state & 0xf) == 0)
    ifthen_state = 0;
}










static void
select_arm_features (unsigned long mach,
       arm_feature_set * features)
{






  switch (mach)
    {
    case 1: features->core = ((0x00000001 | 0x00000002)); features->coproc = (0) | (0x40000000 | 0x20000000); return;
    case 2: features->core = (((0x00000001 | 0x00000002) | 0x00000004)); features->coproc = (0) | (0x40000000 | 0x20000000); return;
    case 3: features->core = ((((0x00000001 | 0x00000002) | 0x00000004) | 0x00000008)); features->coproc = (0) | (0x40000000 | 0x20000000); return;
    case 4: features->core = (((((0x00000001 | 0x00000002) | 0x00000004) | 0x00000008) | 0x00000010)); features->coproc = (0) | (0x40000000 | 0x20000000); return;
    case 5: features->core = ((((((0x00000001 | 0x00000002) | 0x00000004) | 0x00000008) | 0x00000010) | 0x00000020)); features->coproc = (0) | (0x40000000 | 0x20000000); return;
    case 6: features->core = (((((((0x00000001 | 0x00000002) | 0x00000004) | 0x00000008) | 0x00000010) | 0x00000020) | 0x00000040)); features->coproc = (0) | (0x40000000 | 0x20000000); return;
    case 7: features->core = (((((((0x00000001 | 0x00000002) | 0x00000004) | 0x00000008) | 0x00000010) | 0x00000020) | 0x00000080)); features->coproc = (0) | (0x40000000 | 0x20000000); return;
    case 8: features->core = ((((((((0x00000001 | 0x00000002) | 0x00000004) | 0x00000008) | 0x00000010) | 0x00000020) | 0x00000080) | 0x00000040 | 0x00000100)); features->coproc = (0) | (0x40000000 | 0x20000000); return;
    case 9: features->core = ((((((((((0x00000001 | 0x00000002) | 0x00000004) | 0x00000008) | 0x00000010) | 0x00000020) | 0x00000080) | 0x00000040 | 0x00000100) | 0x00000200) | 0x00000400)); features->coproc = (0) | (0x40000000 | 0x20000000); return;
    case 10: features->core = ((((((((((0x00000001 | 0x00000002) | 0x00000004) | 0x00000008) | 0x00000010) | 0x00000020) | 0x00000080) | 0x00000040 | 0x00000100) | 0x00000200) | 0x00000400)); features->coproc = (0x00000001) | (0x40000000 | 0x20000000); return;
    case 11: features->core = (((((((0x00000001 | 0x00000002) | 0x00000004) | 0x00000008) | 0x00000010) | 0x00000020) | 0x00000040)); features->coproc = (0x00000002 | 0x10000000) | (0x40000000 | 0x20000000); return;
    case 12: features->core = ((((((((((0x00000001 | 0x00000002) | 0x00000004) | 0x00000008) | 0x00000010) | 0x00000020) | 0x00000080) | 0x00000040 | 0x00000100) | 0x00000200) | 0x00000400)); features->coproc = (0x00000001 | 0x00000004) | (0x40000000 | 0x20000000); return;
    case 13: features->core = ((((((((((0x00000001 | 0x00000002) | 0x00000004) | 0x00000008) | 0x00000010) | 0x00000020) | 0x00000080) | 0x00000040 | 0x00000100) | 0x00000200) | 0x00000400)); features->coproc = (0x00000001 | 0x00000004 | 0x00000008) | (0x40000000 | 0x20000000); return;


    case 0: features->core = (-1UL); features->coproc = (-1UL) | (0x40000000 | 0x20000000); return;
    default:
      abort ();
    }
}





static int
print_insn (bfd_vma pc, struct disassemble_info *info, bfd_boolean little)
{
  unsigned char b[4];
  long given;
  int status;
  int is_thumb = 0;
  int is_data = 0;
  int little_code;
  unsigned int size = 4;
  void (*printer) (bfd_vma, struct disassemble_info *, long);
  bfd_boolean found = 0;
  struct arm_private_data *private_data;



  if (info->private_data == ((void *)0))
    {
      static struct arm_private_data private;




      select_arm_features (info->mach, & private.features);

      private.has_mapping_symbols = -1;
      private.last_mapping_sym = -1;
      private.last_mapping_addr = 0;

      info->private_data = & private;
    }

  private_data = info->private_data;



  little_code = (little);


  if (pc & 1)
    {
    is_thumb = 1;
    pc &= -2;
    }

  if (is_data)
    info->display_endian = little ? BFD_ENDIAN_LITTLE : BFD_ENDIAN_BIG;
  else
    info->display_endian = little_code ? BFD_ENDIAN_LITTLE : BFD_ENDIAN_BIG;

  info->bytes_per_line = 4;


  if (!is_thumb)
    {


      printer = print_insn_arm;
      info->bytes_per_chunk = 4;
      size = 4;

      status = info->read_memory_func (pc, (bfd_byte *) b, 4, info);
      if (little_code)
 given = (b[0]) | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
      else
 given = (b[3]) | (b[2] << 8) | (b[1] << 16) | (b[0] << 24);
    }
  else
    {




      printer = print_insn_thumb16;
      info->bytes_per_chunk = 2;
      size = 2;

      status = info->read_memory_func (pc, (bfd_byte *) b, 2, info);
      if (little_code)
 given = (b[0]) | (b[1] << 8);
      else
 given = (b[1]) | (b[0] << 8);

      if (!status)
 {


   if ((given & 0xF800) == 0xF800
       || (given & 0xF800) == 0xF000
       || (given & 0xF800) == 0xE800)
     {
       status = info->read_memory_func (pc + 2, (bfd_byte *) b, 2, info);
       if (little_code)
  given = (b[0]) | (b[1] << 8) | (given << 16);
       else
  given = (b[1]) | (b[0] << 8) | (given << 16);

       printer = print_insn_thumb32;
       size = 4;
     }
 }

      if (ifthen_address != pc)
 find_ifthen_state (pc, info, little_code);

      if (ifthen_state)
 {
   if ((ifthen_state & 0xf) == 0x8)
     ifthen_next_state = 0;
   else
     ifthen_next_state = (ifthen_state & 0xe0)
    | ((ifthen_state & 0xf) << 1);
 }
    }

  if (status)
    {
      info->memory_error_func (status, pc, info);
      return -1;
    }

  printer (pc, info, given);

  if (is_thumb)
    {
      ifthen_state = ifthen_next_state;
      ifthen_address += size;
    }
  return size;
}

int
print_insn_big_arm (bfd_vma pc, struct disassemble_info *info)
{

  return print_insn (pc, info, 0);
}

int
print_insn_little_arm (bfd_vma pc, struct disassemble_info *info)
{
  return print_insn (pc, info, 1);
}

void
print_arm_disassembler_options (FILE *stream)
{
  int i;

  fprintf (stream, dcgettext ("bfd", "\nThe following ARM specific disassembler options are supported for use with\nthe -M switch:\n", 5)

                  );

  for (i = (sizeof (regnames) / sizeof (regnames)[0]); i--;)
    fprintf (stream, "  reg-names-%s %*c%s\n",
      regnames[i].name,
      (int)(14 - strlen (regnames[i].name)), ' ',
      regnames[i].description);

  fprintf (stream, "  force-thumb              Assume all insns are Thumb insns\n");
  fprintf (stream, "  no-force-thumb           Examine preceding label to determine an insn's type\n\n");
}
