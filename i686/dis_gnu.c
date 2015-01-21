#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include <setjmp.h>
#include <sys/stat.h>

#include "dis_gnu.h"


/* Copy SRC to DEST, returning the address of the terminating '\0' in DEST.  */
#define dcgettext(a, b, c) b
extern char *
stpcpy (char *dest, const char *src);

char *
__stpcpy (char *dest, const char *src)
{
  register char *d = dest;
  register const char *s = src;

  do
    *d++ = *s;
  while (*s++ != '\0');

  return d - 1;
}
__weak_alias (stpcpy, __stpcpy);

typedef int (*disassembler_ftype)(bfd_vma, disassemble_info *);

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
extern void print_mips_disassembler_options (FILE *);
extern void print_ppc_disassembler_options (FILE *);
extern void print_arm_disassembler_options (FILE *);
extern void parse_arm_disassembler_option (char *);
extern void print_s390_disassembler_options (FILE *);
extern int get_arm_regname_num_options (void);
extern int set_arm_regname_option (int);
extern int get_arm_regnames (int, const char **, const char **,
                             const char *const **);
extern bfd_boolean aarch64_symbol_is_valid (asymbol *,
                                            struct disassemble_info *);
extern bfd_boolean arm_symbol_is_valid (asymbol *, struct disassemble_info *);
extern void disassemble_init_powerpc (struct disassemble_info *);

extern disassembler_ftype disassembler (bfd *);

extern void disassemble_init_for_target (struct disassemble_info *dinfo);

extern void disassembler_usage (FILE *);

extern int buffer_read_memory (bfd_vma, bfd_byte *, unsigned int,
                               struct disassemble_info *);

extern void perror_memory (int, bfd_vma, struct disassemble_info *);

extern void generic_print_address (bfd_vma, struct disassemble_info *);

extern int generic_symbol_at_address (bfd_vma, struct disassemble_info *);

extern bfd_boolean generic_symbol_is_valid (asymbol *,
                                            struct disassemble_info *);

extern void init_disassemble_info (struct disassemble_info *dinfo,
                                   void *stream, fprintf_ftype fprintf_func);


static int print_insn (bfd_vma, disassemble_info *);
static void dofloat (int);
static void OP_ST (int, int);
static void OP_STi (int, int);
static int putop (const char *, int);
static void oappend (const char *);
static void append_seg (void);
static void OP_indirE (int, int);
static void print_operand_value (char *, int, bfd_vma);
static void OP_E_register (int, int);
static void OP_E_memory (int, int);
static void print_displacement (char *, bfd_vma);
static void OP_E (int, int);
static void OP_G (int, int);
static bfd_vma get64 (void);
static bfd_signed_vma get32 (void);
static bfd_signed_vma get32s (void);
static int get16 (void);
static void set_op (bfd_vma, int);
static void OP_Skip_MODRM (int, int);
static void OP_REG (int, int);
static void OP_IMREG (int, int);
static void OP_I (int, int);
static void OP_I64 (int, int);
static void OP_sI (int, int);
static void OP_J (int, int);
static void OP_SEG (int, int);
static void OP_DIR (int, int);
static void OP_OFF (int, int);
static void OP_OFF64 (int, int);
static void ptr_reg (int, int);
static void OP_ESreg (int, int);
static void OP_DSreg (int, int);
static void OP_C (int, int);
static void OP_D (int, int);
static void OP_T (int, int);
static void OP_R (int, int);
static void OP_MMX (int, int);
static void OP_XMM (int, int);
static void OP_EM (int, int);
static void OP_EX (int, int);
static void OP_EMC (int, int);
static void OP_MXC (int, int);
static void OP_MS (int, int);
static void OP_XS (int, int);
static void OP_M (int, int);
static void OP_VEX (int, int);
static void OP_EX_Vex (int, int);
static void OP_EX_VexW (int, int);
static void OP_EX_VexImmW (int, int);
static void OP_XMM_Vex (int, int);
static void OP_XMM_VexW (int, int);
static void OP_Rounding (int, int);
static void OP_REG_VexI4 (int, int);
static void PCLMUL_Fixup (int, int);
static void VEXI4_Fixup (int, int);
static void VZERO_Fixup (int, int);
static void VCMP_Fixup (int, int);
static void VPCMP_Fixup (int, int);
static void OP_0f07 (int, int);
static void OP_Monitor (int, int);
static void OP_Mwait (int, int);
static void NOP_Fixup1 (int, int);
static void NOP_Fixup2 (int, int);
static void OP_3DNowSuffix (int, int);
static void CMP_Fixup (int, int);
static void BadOp (void);
static void REP_Fixup (int, int);
static void BND_Fixup (int, int);
static void HLE_Fixup1 (int, int);
static void HLE_Fixup2 (int, int);
static void HLE_Fixup3 (int, int);
static void CMPXCHG8B_Fixup (int, int);
static void XMM_Fixup (int, int);
static void CRC32_Fixup (int, int);
static void FXSAVE_Fixup (int, int);
static void OP_LWPCB_E (int, int);
static void OP_LWP_E (int, int);
static void OP_Vex_2src_1 (int, int);
static void OP_Vex_2src_2 (int, int);

static void MOVBE_Fixup (int, int);

static void OP_Mask (int, int);

struct dis_private
{

  bfd_byte *max_fetched;
  bfd_byte the_buffer[20];
  bfd_vma insn_start;
  int orig_sizeflag;
  jmp_buf bailout;
};

enum address_mode address_mode;

static int prefixes;

static int rex;

static int rex_used;

static int rex_ignored;
static int used_prefixes;
static int
fetch_data (struct disassemble_info *info, bfd_byte *addr)
{
  int status;
  struct dis_private *priv = (struct dis_private *)info->private_data;
  bfd_vma start = priv->insn_start + (priv->max_fetched - priv->the_buffer);

  if (addr <= priv->the_buffer + 20)
    status = (*info->read_memory_func)(start, priv->max_fetched,
                                       addr - priv->max_fetched, info);
  else
    status = -1;
  if (status != 0)
    {

      if (priv->max_fetched == priv->the_buffer)
        (*info->memory_error_func)(status, start, info);
      longjmp ((priv->bailout), (1));
    }
  else
    priv->max_fetched = addr;
  return 1;
}
enum
{

  b_mode = 1,

  b_swap_mode,

  b_T_mode,

  v_mode,

  v_swap_mode,

  w_mode,

  d_mode,

  d_swap_mode,

  q_mode,

  q_swap_mode,

  t_mode,

  x_mode,

  evex_x_gscat_mode,

  evex_x_nobcst_mode,

  x_swap_mode,

  xmm_mode,

  xmmq_mode,

  evex_half_bcst_xmmq_mode,

  xmm_mb_mode,

  xmm_mw_mode,

  xmm_md_mode,

  xmm_mq_mode,

  xmm_mdq_mode,

  xmmdw_mode,

  xmmqd_mode,

  ymm_mode,

  ymmq_mode,

  ymmxmm_mode,

  m_mode,

  a_mode,
  cond_jump_mode,
  loop_jcxz_mode,
  v_bnd_mode,

  dq_mode,

  dqw_mode,
  bnd_mode,

  f_mode,
  const_1_mode,

  stack_v_mode,

  z_mode,

  o_mode,

  dqb_mode,

  dqd_mode,

  vex_mode,

  vex128_mode,

  vex256_mode,

  vex_w_dq_mode,

  vex_vsib_d_w_dq_mode,

  vex_vsib_d_w_d_mode,

  vex_vsib_q_w_dq_mode,

  vex_vsib_q_w_d_mode,

  scalar_mode,

  d_scalar_mode,

  d_scalar_swap_mode,

  q_scalar_mode,

  q_scalar_swap_mode,

  vex_scalar_mode,

  vex_scalar_w_dq_mode,

  evex_rounding_mode,

  evex_sae_mode,

  mask_mode,

  es_reg,
  cs_reg,
  ss_reg,
  ds_reg,
  fs_reg,
  gs_reg,

  eAX_reg,
  eCX_reg,
  eDX_reg,
  eBX_reg,
  eSP_reg,
  eBP_reg,
  eSI_reg,
  eDI_reg,

  al_reg,
  cl_reg,
  dl_reg,
  bl_reg,
  ah_reg,
  ch_reg,
  dh_reg,
  bh_reg,

  ax_reg,
  cx_reg,
  dx_reg,
  bx_reg,
  sp_reg,
  bp_reg,
  si_reg,
  di_reg,

  rAX_reg,
  rCX_reg,
  rDX_reg,
  rBX_reg,
  rSP_reg,
  rBP_reg,
  rSI_reg,
  rDI_reg,

  z_mode_ax_reg,
  indir_dx_reg
};

enum
{
  FLOATCODE = 1,
  USE_REG_TABLE,
  USE_MOD_TABLE,
  USE_RM_TABLE,
  USE_PREFIX_TABLE,
  USE_X86_64_TABLE,
  USE_3BYTE_TABLE,
  USE_XOP_8F_TABLE,
  USE_VEX_C4_TABLE,
  USE_VEX_C5_TABLE,
  USE_VEX_LEN_TABLE,
  USE_VEX_W_TABLE,
  USE_EVEX_TABLE
};
enum
{
  REG_80 = 0,
  REG_81,
  REG_82,
  REG_8F,
  REG_C0,
  REG_C1,
  REG_C6,
  REG_C7,
  REG_D0,
  REG_D1,
  REG_D2,
  REG_D3,
  REG_F6,
  REG_F7,
  REG_FE,
  REG_FF,
  REG_0F00,
  REG_0F01,
  REG_0F0D,
  REG_0F18,
  REG_0F71,
  REG_0F72,
  REG_0F73,
  REG_0FA6,
  REG_0FA7,
  REG_0FAE,
  REG_0FBA,
  REG_0FC7,
  REG_VEX_0F71,
  REG_VEX_0F72,
  REG_VEX_0F73,
  REG_VEX_0FAE,
  REG_VEX_0F38F3,
  REG_XOP_LWPCB,
  REG_XOP_LWP,
  REG_XOP_TBM_01,
  REG_XOP_TBM_02,

  REG_EVEX_0F72,
  REG_EVEX_0F73,
  REG_EVEX_0F38C6,
  REG_EVEX_0F38C7
};

enum
{
  MOD_8D = 0,
  MOD_C6_REG_7,
  MOD_C7_REG_7,
  MOD_FF_REG_3,
  MOD_FF_REG_5,
  MOD_0F01_REG_0,
  MOD_0F01_REG_1,
  MOD_0F01_REG_2,
  MOD_0F01_REG_3,
  MOD_0F01_REG_7,
  MOD_0F12_PREFIX_0,
  MOD_0F13,
  MOD_0F16_PREFIX_0,
  MOD_0F17,
  MOD_0F18_REG_0,
  MOD_0F18_REG_1,
  MOD_0F18_REG_2,
  MOD_0F18_REG_3,
  MOD_0F18_REG_4,
  MOD_0F18_REG_5,
  MOD_0F18_REG_6,
  MOD_0F18_REG_7,
  MOD_0F1A_PREFIX_0,
  MOD_0F1B_PREFIX_0,
  MOD_0F1B_PREFIX_1,
  MOD_0F20,
  MOD_0F21,
  MOD_0F22,
  MOD_0F23,
  MOD_0F24,
  MOD_0F26,
  MOD_0F2B_PREFIX_0,
  MOD_0F2B_PREFIX_1,
  MOD_0F2B_PREFIX_2,
  MOD_0F2B_PREFIX_3,
  MOD_0F51,
  MOD_0F71_REG_2,
  MOD_0F71_REG_4,
  MOD_0F71_REG_6,
  MOD_0F72_REG_2,
  MOD_0F72_REG_4,
  MOD_0F72_REG_6,
  MOD_0F73_REG_2,
  MOD_0F73_REG_3,
  MOD_0F73_REG_6,
  MOD_0F73_REG_7,
  MOD_0FAE_REG_0,
  MOD_0FAE_REG_1,
  MOD_0FAE_REG_2,
  MOD_0FAE_REG_3,
  MOD_0FAE_REG_4,
  MOD_0FAE_REG_5,
  MOD_0FAE_REG_6,
  MOD_0FAE_REG_7,
  MOD_0FB2,
  MOD_0FB4,
  MOD_0FB5,
  MOD_0FC7_REG_3,
  MOD_0FC7_REG_4,
  MOD_0FC7_REG_5,
  MOD_0FC7_REG_6,
  MOD_0FC7_REG_7,
  MOD_0FD7,
  MOD_0FE7_PREFIX_2,
  MOD_0FF0_PREFIX_3,
  MOD_0F382A_PREFIX_2,
  MOD_62_32BIT,
  MOD_C4_32BIT,
  MOD_C5_32BIT,
  MOD_VEX_0F12_PREFIX_0,
  MOD_VEX_0F13,
  MOD_VEX_0F16_PREFIX_0,
  MOD_VEX_0F17,
  MOD_VEX_0F2B,
  MOD_VEX_0F50,
  MOD_VEX_0F71_REG_2,
  MOD_VEX_0F71_REG_4,
  MOD_VEX_0F71_REG_6,
  MOD_VEX_0F72_REG_2,
  MOD_VEX_0F72_REG_4,
  MOD_VEX_0F72_REG_6,
  MOD_VEX_0F73_REG_2,
  MOD_VEX_0F73_REG_3,
  MOD_VEX_0F73_REG_6,
  MOD_VEX_0F73_REG_7,
  MOD_VEX_0FAE_REG_2,
  MOD_VEX_0FAE_REG_3,
  MOD_VEX_0FD7_PREFIX_2,
  MOD_VEX_0FE7_PREFIX_2,
  MOD_VEX_0FF0_PREFIX_3,
  MOD_VEX_0F381A_PREFIX_2,
  MOD_VEX_0F382A_PREFIX_2,
  MOD_VEX_0F382C_PREFIX_2,
  MOD_VEX_0F382D_PREFIX_2,
  MOD_VEX_0F382E_PREFIX_2,
  MOD_VEX_0F382F_PREFIX_2,
  MOD_VEX_0F385A_PREFIX_2,
  MOD_VEX_0F388C_PREFIX_2,
  MOD_VEX_0F388E_PREFIX_2,

  MOD_EVEX_0F10_PREFIX_1,
  MOD_EVEX_0F10_PREFIX_3,
  MOD_EVEX_0F11_PREFIX_1,
  MOD_EVEX_0F11_PREFIX_3,
  MOD_EVEX_0F12_PREFIX_0,
  MOD_EVEX_0F16_PREFIX_0,
  MOD_EVEX_0F38C6_REG_1,
  MOD_EVEX_0F38C6_REG_2,
  MOD_EVEX_0F38C6_REG_5,
  MOD_EVEX_0F38C6_REG_6,
  MOD_EVEX_0F38C7_REG_1,
  MOD_EVEX_0F38C7_REG_2,
  MOD_EVEX_0F38C7_REG_5,
  MOD_EVEX_0F38C7_REG_6
};

enum
{
  RM_C6_REG_7 = 0,
  RM_C7_REG_7,
  RM_0F01_REG_0,
  RM_0F01_REG_1,
  RM_0F01_REG_2,
  RM_0F01_REG_3,
  RM_0F01_REG_7,
  RM_0FAE_REG_5,
  RM_0FAE_REG_6,
  RM_0FAE_REG_7
};

enum
{
  PREFIX_90 = 0,
  PREFIX_0F10,
  PREFIX_0F11,
  PREFIX_0F12,
  PREFIX_0F16,
  PREFIX_0F1A,
  PREFIX_0F1B,
  PREFIX_0F2A,
  PREFIX_0F2B,
  PREFIX_0F2C,
  PREFIX_0F2D,
  PREFIX_0F2E,
  PREFIX_0F2F,
  PREFIX_0F51,
  PREFIX_0F52,
  PREFIX_0F53,
  PREFIX_0F58,
  PREFIX_0F59,
  PREFIX_0F5A,
  PREFIX_0F5B,
  PREFIX_0F5C,
  PREFIX_0F5D,
  PREFIX_0F5E,
  PREFIX_0F5F,
  PREFIX_0F60,
  PREFIX_0F61,
  PREFIX_0F62,
  PREFIX_0F6C,
  PREFIX_0F6D,
  PREFIX_0F6F,
  PREFIX_0F70,
  PREFIX_0F73_REG_3,
  PREFIX_0F73_REG_7,
  PREFIX_0F78,
  PREFIX_0F79,
  PREFIX_0F7C,
  PREFIX_0F7D,
  PREFIX_0F7E,
  PREFIX_0F7F,
  PREFIX_0FAE_REG_0,
  PREFIX_0FAE_REG_1,
  PREFIX_0FAE_REG_2,
  PREFIX_0FAE_REG_3,
  PREFIX_0FAE_REG_7,
  PREFIX_0FB8,
  PREFIX_0FBC,
  PREFIX_0FBD,
  PREFIX_0FC2,
  PREFIX_0FC3,
  PREFIX_0FC7_REG_6,
  PREFIX_0FD0,
  PREFIX_0FD6,
  PREFIX_0FE6,
  PREFIX_0FE7,
  PREFIX_0FF0,
  PREFIX_0FF7,
  PREFIX_0F3810,
  PREFIX_0F3814,
  PREFIX_0F3815,
  PREFIX_0F3817,
  PREFIX_0F3820,
  PREFIX_0F3821,
  PREFIX_0F3822,
  PREFIX_0F3823,
  PREFIX_0F3824,
  PREFIX_0F3825,
  PREFIX_0F3828,
  PREFIX_0F3829,
  PREFIX_0F382A,
  PREFIX_0F382B,
  PREFIX_0F3830,
  PREFIX_0F3831,
  PREFIX_0F3832,
  PREFIX_0F3833,
  PREFIX_0F3834,
  PREFIX_0F3835,
  PREFIX_0F3837,
  PREFIX_0F3838,
  PREFIX_0F3839,
  PREFIX_0F383A,
  PREFIX_0F383B,
  PREFIX_0F383C,
  PREFIX_0F383D,
  PREFIX_0F383E,
  PREFIX_0F383F,
  PREFIX_0F3840,
  PREFIX_0F3841,
  PREFIX_0F3880,
  PREFIX_0F3881,
  PREFIX_0F3882,
  PREFIX_0F38C8,
  PREFIX_0F38C9,
  PREFIX_0F38CA,
  PREFIX_0F38CB,
  PREFIX_0F38CC,
  PREFIX_0F38CD,
  PREFIX_0F38DB,
  PREFIX_0F38DC,
  PREFIX_0F38DD,
  PREFIX_0F38DE,
  PREFIX_0F38DF,
  PREFIX_0F38F0,
  PREFIX_0F38F1,
  PREFIX_0F38F6,
  PREFIX_0F3A08,
  PREFIX_0F3A09,
  PREFIX_0F3A0A,
  PREFIX_0F3A0B,
  PREFIX_0F3A0C,
  PREFIX_0F3A0D,
  PREFIX_0F3A0E,
  PREFIX_0F3A14,
  PREFIX_0F3A15,
  PREFIX_0F3A16,
  PREFIX_0F3A17,
  PREFIX_0F3A20,
  PREFIX_0F3A21,
  PREFIX_0F3A22,
  PREFIX_0F3A40,
  PREFIX_0F3A41,
  PREFIX_0F3A42,
  PREFIX_0F3A44,
  PREFIX_0F3A60,
  PREFIX_0F3A61,
  PREFIX_0F3A62,
  PREFIX_0F3A63,
  PREFIX_0F3ACC,
  PREFIX_0F3ADF,
  PREFIX_VEX_0F10,
  PREFIX_VEX_0F11,
  PREFIX_VEX_0F12,
  PREFIX_VEX_0F16,
  PREFIX_VEX_0F2A,
  PREFIX_VEX_0F2C,
  PREFIX_VEX_0F2D,
  PREFIX_VEX_0F2E,
  PREFIX_VEX_0F2F,
  PREFIX_VEX_0F41,
  PREFIX_VEX_0F42,
  PREFIX_VEX_0F44,
  PREFIX_VEX_0F45,
  PREFIX_VEX_0F46,
  PREFIX_VEX_0F47,
  PREFIX_VEX_0F4B,
  PREFIX_VEX_0F51,
  PREFIX_VEX_0F52,
  PREFIX_VEX_0F53,
  PREFIX_VEX_0F58,
  PREFIX_VEX_0F59,
  PREFIX_VEX_0F5A,
  PREFIX_VEX_0F5B,
  PREFIX_VEX_0F5C,
  PREFIX_VEX_0F5D,
  PREFIX_VEX_0F5E,
  PREFIX_VEX_0F5F,
  PREFIX_VEX_0F60,
  PREFIX_VEX_0F61,
  PREFIX_VEX_0F62,
  PREFIX_VEX_0F63,
  PREFIX_VEX_0F64,
  PREFIX_VEX_0F65,
  PREFIX_VEX_0F66,
  PREFIX_VEX_0F67,
  PREFIX_VEX_0F68,
  PREFIX_VEX_0F69,
  PREFIX_VEX_0F6A,
  PREFIX_VEX_0F6B,
  PREFIX_VEX_0F6C,
  PREFIX_VEX_0F6D,
  PREFIX_VEX_0F6E,
  PREFIX_VEX_0F6F,
  PREFIX_VEX_0F70,
  PREFIX_VEX_0F71_REG_2,
  PREFIX_VEX_0F71_REG_4,
  PREFIX_VEX_0F71_REG_6,
  PREFIX_VEX_0F72_REG_2,
  PREFIX_VEX_0F72_REG_4,
  PREFIX_VEX_0F72_REG_6,
  PREFIX_VEX_0F73_REG_2,
  PREFIX_VEX_0F73_REG_3,
  PREFIX_VEX_0F73_REG_6,
  PREFIX_VEX_0F73_REG_7,
  PREFIX_VEX_0F74,
  PREFIX_VEX_0F75,
  PREFIX_VEX_0F76,
  PREFIX_VEX_0F77,
  PREFIX_VEX_0F7C,
  PREFIX_VEX_0F7D,
  PREFIX_VEX_0F7E,
  PREFIX_VEX_0F7F,
  PREFIX_VEX_0F90,
  PREFIX_VEX_0F91,
  PREFIX_VEX_0F92,
  PREFIX_VEX_0F93,
  PREFIX_VEX_0F98,
  PREFIX_VEX_0FC2,
  PREFIX_VEX_0FC4,
  PREFIX_VEX_0FC5,
  PREFIX_VEX_0FD0,
  PREFIX_VEX_0FD1,
  PREFIX_VEX_0FD2,
  PREFIX_VEX_0FD3,
  PREFIX_VEX_0FD4,
  PREFIX_VEX_0FD5,
  PREFIX_VEX_0FD6,
  PREFIX_VEX_0FD7,
  PREFIX_VEX_0FD8,
  PREFIX_VEX_0FD9,
  PREFIX_VEX_0FDA,
  PREFIX_VEX_0FDB,
  PREFIX_VEX_0FDC,
  PREFIX_VEX_0FDD,
  PREFIX_VEX_0FDE,
  PREFIX_VEX_0FDF,
  PREFIX_VEX_0FE0,
  PREFIX_VEX_0FE1,
  PREFIX_VEX_0FE2,
  PREFIX_VEX_0FE3,
  PREFIX_VEX_0FE4,
  PREFIX_VEX_0FE5,
  PREFIX_VEX_0FE6,
  PREFIX_VEX_0FE7,
  PREFIX_VEX_0FE8,
  PREFIX_VEX_0FE9,
  PREFIX_VEX_0FEA,
  PREFIX_VEX_0FEB,
  PREFIX_VEX_0FEC,
  PREFIX_VEX_0FED,
  PREFIX_VEX_0FEE,
  PREFIX_VEX_0FEF,
  PREFIX_VEX_0FF0,
  PREFIX_VEX_0FF1,
  PREFIX_VEX_0FF2,
  PREFIX_VEX_0FF3,
  PREFIX_VEX_0FF4,
  PREFIX_VEX_0FF5,
  PREFIX_VEX_0FF6,
  PREFIX_VEX_0FF7,
  PREFIX_VEX_0FF8,
  PREFIX_VEX_0FF9,
  PREFIX_VEX_0FFA,
  PREFIX_VEX_0FFB,
  PREFIX_VEX_0FFC,
  PREFIX_VEX_0FFD,
  PREFIX_VEX_0FFE,
  PREFIX_VEX_0F3800,
  PREFIX_VEX_0F3801,
  PREFIX_VEX_0F3802,
  PREFIX_VEX_0F3803,
  PREFIX_VEX_0F3804,
  PREFIX_VEX_0F3805,
  PREFIX_VEX_0F3806,
  PREFIX_VEX_0F3807,
  PREFIX_VEX_0F3808,
  PREFIX_VEX_0F3809,
  PREFIX_VEX_0F380A,
  PREFIX_VEX_0F380B,
  PREFIX_VEX_0F380C,
  PREFIX_VEX_0F380D,
  PREFIX_VEX_0F380E,
  PREFIX_VEX_0F380F,
  PREFIX_VEX_0F3813,
  PREFIX_VEX_0F3816,
  PREFIX_VEX_0F3817,
  PREFIX_VEX_0F3818,
  PREFIX_VEX_0F3819,
  PREFIX_VEX_0F381A,
  PREFIX_VEX_0F381C,
  PREFIX_VEX_0F381D,
  PREFIX_VEX_0F381E,
  PREFIX_VEX_0F3820,
  PREFIX_VEX_0F3821,
  PREFIX_VEX_0F3822,
  PREFIX_VEX_0F3823,
  PREFIX_VEX_0F3824,
  PREFIX_VEX_0F3825,
  PREFIX_VEX_0F3828,
  PREFIX_VEX_0F3829,
  PREFIX_VEX_0F382A,
  PREFIX_VEX_0F382B,
  PREFIX_VEX_0F382C,
  PREFIX_VEX_0F382D,
  PREFIX_VEX_0F382E,
  PREFIX_VEX_0F382F,
  PREFIX_VEX_0F3830,
  PREFIX_VEX_0F3831,
  PREFIX_VEX_0F3832,
  PREFIX_VEX_0F3833,
  PREFIX_VEX_0F3834,
  PREFIX_VEX_0F3835,
  PREFIX_VEX_0F3836,
  PREFIX_VEX_0F3837,
  PREFIX_VEX_0F3838,
  PREFIX_VEX_0F3839,
  PREFIX_VEX_0F383A,
  PREFIX_VEX_0F383B,
  PREFIX_VEX_0F383C,
  PREFIX_VEX_0F383D,
  PREFIX_VEX_0F383E,
  PREFIX_VEX_0F383F,
  PREFIX_VEX_0F3840,
  PREFIX_VEX_0F3841,
  PREFIX_VEX_0F3845,
  PREFIX_VEX_0F3846,
  PREFIX_VEX_0F3847,
  PREFIX_VEX_0F3858,
  PREFIX_VEX_0F3859,
  PREFIX_VEX_0F385A,
  PREFIX_VEX_0F3878,
  PREFIX_VEX_0F3879,
  PREFIX_VEX_0F388C,
  PREFIX_VEX_0F388E,
  PREFIX_VEX_0F3890,
  PREFIX_VEX_0F3891,
  PREFIX_VEX_0F3892,
  PREFIX_VEX_0F3893,
  PREFIX_VEX_0F3896,
  PREFIX_VEX_0F3897,
  PREFIX_VEX_0F3898,
  PREFIX_VEX_0F3899,
  PREFIX_VEX_0F389A,
  PREFIX_VEX_0F389B,
  PREFIX_VEX_0F389C,
  PREFIX_VEX_0F389D,
  PREFIX_VEX_0F389E,
  PREFIX_VEX_0F389F,
  PREFIX_VEX_0F38A6,
  PREFIX_VEX_0F38A7,
  PREFIX_VEX_0F38A8,
  PREFIX_VEX_0F38A9,
  PREFIX_VEX_0F38AA,
  PREFIX_VEX_0F38AB,
  PREFIX_VEX_0F38AC,
  PREFIX_VEX_0F38AD,
  PREFIX_VEX_0F38AE,
  PREFIX_VEX_0F38AF,
  PREFIX_VEX_0F38B6,
  PREFIX_VEX_0F38B7,
  PREFIX_VEX_0F38B8,
  PREFIX_VEX_0F38B9,
  PREFIX_VEX_0F38BA,
  PREFIX_VEX_0F38BB,
  PREFIX_VEX_0F38BC,
  PREFIX_VEX_0F38BD,
  PREFIX_VEX_0F38BE,
  PREFIX_VEX_0F38BF,
  PREFIX_VEX_0F38DB,
  PREFIX_VEX_0F38DC,
  PREFIX_VEX_0F38DD,
  PREFIX_VEX_0F38DE,
  PREFIX_VEX_0F38DF,
  PREFIX_VEX_0F38F2,
  PREFIX_VEX_0F38F3_REG_1,
  PREFIX_VEX_0F38F3_REG_2,
  PREFIX_VEX_0F38F3_REG_3,
  PREFIX_VEX_0F38F5,
  PREFIX_VEX_0F38F6,
  PREFIX_VEX_0F38F7,
  PREFIX_VEX_0F3A00,
  PREFIX_VEX_0F3A01,
  PREFIX_VEX_0F3A02,
  PREFIX_VEX_0F3A04,
  PREFIX_VEX_0F3A05,
  PREFIX_VEX_0F3A06,
  PREFIX_VEX_0F3A08,
  PREFIX_VEX_0F3A09,
  PREFIX_VEX_0F3A0A,
  PREFIX_VEX_0F3A0B,
  PREFIX_VEX_0F3A0C,
  PREFIX_VEX_0F3A0D,
  PREFIX_VEX_0F3A0E,
  PREFIX_VEX_0F3A0F,
  PREFIX_VEX_0F3A14,
  PREFIX_VEX_0F3A15,
  PREFIX_VEX_0F3A16,
  PREFIX_VEX_0F3A17,
  PREFIX_VEX_0F3A18,
  PREFIX_VEX_0F3A19,
  PREFIX_VEX_0F3A1D,
  PREFIX_VEX_0F3A20,
  PREFIX_VEX_0F3A21,
  PREFIX_VEX_0F3A22,
  PREFIX_VEX_0F3A30,
  PREFIX_VEX_0F3A32,
  PREFIX_VEX_0F3A38,
  PREFIX_VEX_0F3A39,
  PREFIX_VEX_0F3A40,
  PREFIX_VEX_0F3A41,
  PREFIX_VEX_0F3A42,
  PREFIX_VEX_0F3A44,
  PREFIX_VEX_0F3A46,
  PREFIX_VEX_0F3A48,
  PREFIX_VEX_0F3A49,
  PREFIX_VEX_0F3A4A,
  PREFIX_VEX_0F3A4B,
  PREFIX_VEX_0F3A4C,
  PREFIX_VEX_0F3A5C,
  PREFIX_VEX_0F3A5D,
  PREFIX_VEX_0F3A5E,
  PREFIX_VEX_0F3A5F,
  PREFIX_VEX_0F3A60,
  PREFIX_VEX_0F3A61,
  PREFIX_VEX_0F3A62,
  PREFIX_VEX_0F3A63,
  PREFIX_VEX_0F3A68,
  PREFIX_VEX_0F3A69,
  PREFIX_VEX_0F3A6A,
  PREFIX_VEX_0F3A6B,
  PREFIX_VEX_0F3A6C,
  PREFIX_VEX_0F3A6D,
  PREFIX_VEX_0F3A6E,
  PREFIX_VEX_0F3A6F,
  PREFIX_VEX_0F3A78,
  PREFIX_VEX_0F3A79,
  PREFIX_VEX_0F3A7A,
  PREFIX_VEX_0F3A7B,
  PREFIX_VEX_0F3A7C,
  PREFIX_VEX_0F3A7D,
  PREFIX_VEX_0F3A7E,
  PREFIX_VEX_0F3A7F,
  PREFIX_VEX_0F3ADF,
  PREFIX_VEX_0F3AF0,

  PREFIX_EVEX_0F10,
  PREFIX_EVEX_0F11,
  PREFIX_EVEX_0F12,
  PREFIX_EVEX_0F13,
  PREFIX_EVEX_0F14,
  PREFIX_EVEX_0F15,
  PREFIX_EVEX_0F16,
  PREFIX_EVEX_0F17,
  PREFIX_EVEX_0F28,
  PREFIX_EVEX_0F29,
  PREFIX_EVEX_0F2A,
  PREFIX_EVEX_0F2B,
  PREFIX_EVEX_0F2C,
  PREFIX_EVEX_0F2D,
  PREFIX_EVEX_0F2E,
  PREFIX_EVEX_0F2F,
  PREFIX_EVEX_0F51,
  PREFIX_EVEX_0F58,
  PREFIX_EVEX_0F59,
  PREFIX_EVEX_0F5A,
  PREFIX_EVEX_0F5B,
  PREFIX_EVEX_0F5C,
  PREFIX_EVEX_0F5D,
  PREFIX_EVEX_0F5E,
  PREFIX_EVEX_0F5F,
  PREFIX_EVEX_0F62,
  PREFIX_EVEX_0F66,
  PREFIX_EVEX_0F6A,
  PREFIX_EVEX_0F6C,
  PREFIX_EVEX_0F6D,
  PREFIX_EVEX_0F6E,
  PREFIX_EVEX_0F6F,
  PREFIX_EVEX_0F70,
  PREFIX_EVEX_0F72_REG_0,
  PREFIX_EVEX_0F72_REG_1,
  PREFIX_EVEX_0F72_REG_2,
  PREFIX_EVEX_0F72_REG_4,
  PREFIX_EVEX_0F72_REG_6,
  PREFIX_EVEX_0F73_REG_2,
  PREFIX_EVEX_0F73_REG_6,
  PREFIX_EVEX_0F76,
  PREFIX_EVEX_0F78,
  PREFIX_EVEX_0F79,
  PREFIX_EVEX_0F7A,
  PREFIX_EVEX_0F7B,
  PREFIX_EVEX_0F7E,
  PREFIX_EVEX_0F7F,
  PREFIX_EVEX_0FC2,
  PREFIX_EVEX_0FC6,
  PREFIX_EVEX_0FD2,
  PREFIX_EVEX_0FD3,
  PREFIX_EVEX_0FD4,
  PREFIX_EVEX_0FD6,
  PREFIX_EVEX_0FDB,
  PREFIX_EVEX_0FDF,
  PREFIX_EVEX_0FE2,
  PREFIX_EVEX_0FE6,
  PREFIX_EVEX_0FE7,
  PREFIX_EVEX_0FEB,
  PREFIX_EVEX_0FEF,
  PREFIX_EVEX_0FF2,
  PREFIX_EVEX_0FF3,
  PREFIX_EVEX_0FF4,
  PREFIX_EVEX_0FFA,
  PREFIX_EVEX_0FFB,
  PREFIX_EVEX_0FFE,
  PREFIX_EVEX_0F380C,
  PREFIX_EVEX_0F380D,
  PREFIX_EVEX_0F3811,
  PREFIX_EVEX_0F3812,
  PREFIX_EVEX_0F3813,
  PREFIX_EVEX_0F3814,
  PREFIX_EVEX_0F3815,
  PREFIX_EVEX_0F3816,
  PREFIX_EVEX_0F3818,
  PREFIX_EVEX_0F3819,
  PREFIX_EVEX_0F381A,
  PREFIX_EVEX_0F381B,
  PREFIX_EVEX_0F381E,
  PREFIX_EVEX_0F381F,
  PREFIX_EVEX_0F3821,
  PREFIX_EVEX_0F3822,
  PREFIX_EVEX_0F3823,
  PREFIX_EVEX_0F3824,
  PREFIX_EVEX_0F3825,
  PREFIX_EVEX_0F3827,
  PREFIX_EVEX_0F3828,
  PREFIX_EVEX_0F3829,
  PREFIX_EVEX_0F382A,
  PREFIX_EVEX_0F382C,
  PREFIX_EVEX_0F382D,
  PREFIX_EVEX_0F3831,
  PREFIX_EVEX_0F3832,
  PREFIX_EVEX_0F3833,
  PREFIX_EVEX_0F3834,
  PREFIX_EVEX_0F3835,
  PREFIX_EVEX_0F3836,
  PREFIX_EVEX_0F3837,
  PREFIX_EVEX_0F3839,
  PREFIX_EVEX_0F383A,
  PREFIX_EVEX_0F383B,
  PREFIX_EVEX_0F383D,
  PREFIX_EVEX_0F383F,
  PREFIX_EVEX_0F3840,
  PREFIX_EVEX_0F3842,
  PREFIX_EVEX_0F3843,
  PREFIX_EVEX_0F3844,
  PREFIX_EVEX_0F3845,
  PREFIX_EVEX_0F3846,
  PREFIX_EVEX_0F3847,
  PREFIX_EVEX_0F384C,
  PREFIX_EVEX_0F384D,
  PREFIX_EVEX_0F384E,
  PREFIX_EVEX_0F384F,
  PREFIX_EVEX_0F3858,
  PREFIX_EVEX_0F3859,
  PREFIX_EVEX_0F385A,
  PREFIX_EVEX_0F385B,
  PREFIX_EVEX_0F3864,
  PREFIX_EVEX_0F3865,
  PREFIX_EVEX_0F3876,
  PREFIX_EVEX_0F3877,
  PREFIX_EVEX_0F387C,
  PREFIX_EVEX_0F387E,
  PREFIX_EVEX_0F387F,
  PREFIX_EVEX_0F3888,
  PREFIX_EVEX_0F3889,
  PREFIX_EVEX_0F388A,
  PREFIX_EVEX_0F388B,
  PREFIX_EVEX_0F3890,
  PREFIX_EVEX_0F3891,
  PREFIX_EVEX_0F3892,
  PREFIX_EVEX_0F3893,
  PREFIX_EVEX_0F3896,
  PREFIX_EVEX_0F3897,
  PREFIX_EVEX_0F3898,
  PREFIX_EVEX_0F3899,
  PREFIX_EVEX_0F389A,
  PREFIX_EVEX_0F389B,
  PREFIX_EVEX_0F389C,
  PREFIX_EVEX_0F389D,
  PREFIX_EVEX_0F389E,
  PREFIX_EVEX_0F389F,
  PREFIX_EVEX_0F38A0,
  PREFIX_EVEX_0F38A1,
  PREFIX_EVEX_0F38A2,
  PREFIX_EVEX_0F38A3,
  PREFIX_EVEX_0F38A6,
  PREFIX_EVEX_0F38A7,
  PREFIX_EVEX_0F38A8,
  PREFIX_EVEX_0F38A9,
  PREFIX_EVEX_0F38AA,
  PREFIX_EVEX_0F38AB,
  PREFIX_EVEX_0F38AC,
  PREFIX_EVEX_0F38AD,
  PREFIX_EVEX_0F38AE,
  PREFIX_EVEX_0F38AF,
  PREFIX_EVEX_0F38B6,
  PREFIX_EVEX_0F38B7,
  PREFIX_EVEX_0F38B8,
  PREFIX_EVEX_0F38B9,
  PREFIX_EVEX_0F38BA,
  PREFIX_EVEX_0F38BB,
  PREFIX_EVEX_0F38BC,
  PREFIX_EVEX_0F38BD,
  PREFIX_EVEX_0F38BE,
  PREFIX_EVEX_0F38BF,
  PREFIX_EVEX_0F38C4,
  PREFIX_EVEX_0F38C6_REG_1,
  PREFIX_EVEX_0F38C6_REG_2,
  PREFIX_EVEX_0F38C6_REG_5,
  PREFIX_EVEX_0F38C6_REG_6,
  PREFIX_EVEX_0F38C7_REG_1,
  PREFIX_EVEX_0F38C7_REG_2,
  PREFIX_EVEX_0F38C7_REG_5,
  PREFIX_EVEX_0F38C7_REG_6,
  PREFIX_EVEX_0F38C8,
  PREFIX_EVEX_0F38CA,
  PREFIX_EVEX_0F38CB,
  PREFIX_EVEX_0F38CC,
  PREFIX_EVEX_0F38CD,

  PREFIX_EVEX_0F3A00,
  PREFIX_EVEX_0F3A01,
  PREFIX_EVEX_0F3A03,
  PREFIX_EVEX_0F3A04,
  PREFIX_EVEX_0F3A05,
  PREFIX_EVEX_0F3A08,
  PREFIX_EVEX_0F3A09,
  PREFIX_EVEX_0F3A0A,
  PREFIX_EVEX_0F3A0B,
  PREFIX_EVEX_0F3A17,
  PREFIX_EVEX_0F3A18,
  PREFIX_EVEX_0F3A19,
  PREFIX_EVEX_0F3A1A,
  PREFIX_EVEX_0F3A1B,
  PREFIX_EVEX_0F3A1D,
  PREFIX_EVEX_0F3A1E,
  PREFIX_EVEX_0F3A1F,
  PREFIX_EVEX_0F3A21,
  PREFIX_EVEX_0F3A23,
  PREFIX_EVEX_0F3A25,
  PREFIX_EVEX_0F3A26,
  PREFIX_EVEX_0F3A27,
  PREFIX_EVEX_0F3A38,
  PREFIX_EVEX_0F3A39,
  PREFIX_EVEX_0F3A3A,
  PREFIX_EVEX_0F3A3B,
  PREFIX_EVEX_0F3A43,
  PREFIX_EVEX_0F3A54,
  PREFIX_EVEX_0F3A55,
};

enum
{
  X86_64_06 = 0,
  X86_64_07,
  X86_64_0D,
  X86_64_16,
  X86_64_17,
  X86_64_1E,
  X86_64_1F,
  X86_64_27,
  X86_64_2F,
  X86_64_37,
  X86_64_3F,
  X86_64_60,
  X86_64_61,
  X86_64_62,
  X86_64_63,
  X86_64_6D,
  X86_64_6F,
  X86_64_9A,
  X86_64_C4,
  X86_64_C5,
  X86_64_CE,
  X86_64_D4,
  X86_64_D5,
  X86_64_EA,
  X86_64_0F01_REG_0,
  X86_64_0F01_REG_1,
  X86_64_0F01_REG_2,
  X86_64_0F01_REG_3
};

enum
{
  THREE_BYTE_0F38 = 0,
  THREE_BYTE_0F3A,
  THREE_BYTE_0F7A
};

enum
{
  XOP_08 = 0,
  XOP_09,
  XOP_0A
};

enum
{
  VEX_0F = 0,
  VEX_0F38,
  VEX_0F3A
};

enum
{
  EVEX_0F = 0,
  EVEX_0F38,
  EVEX_0F3A
};

enum
{
  VEX_LEN_0F10_P_1 = 0,
  VEX_LEN_0F10_P_3,
  VEX_LEN_0F11_P_1,
  VEX_LEN_0F11_P_3,
  VEX_LEN_0F12_P_0_M_0,
  VEX_LEN_0F12_P_0_M_1,
  VEX_LEN_0F12_P_2,
  VEX_LEN_0F13_M_0,
  VEX_LEN_0F16_P_0_M_0,
  VEX_LEN_0F16_P_0_M_1,
  VEX_LEN_0F16_P_2,
  VEX_LEN_0F17_M_0,
  VEX_LEN_0F2A_P_1,
  VEX_LEN_0F2A_P_3,
  VEX_LEN_0F2C_P_1,
  VEX_LEN_0F2C_P_3,
  VEX_LEN_0F2D_P_1,
  VEX_LEN_0F2D_P_3,
  VEX_LEN_0F2E_P_0,
  VEX_LEN_0F2E_P_2,
  VEX_LEN_0F2F_P_0,
  VEX_LEN_0F2F_P_2,
  VEX_LEN_0F41_P_0,
  VEX_LEN_0F42_P_0,
  VEX_LEN_0F44_P_0,
  VEX_LEN_0F45_P_0,
  VEX_LEN_0F46_P_0,
  VEX_LEN_0F47_P_0,
  VEX_LEN_0F4B_P_2,
  VEX_LEN_0F51_P_1,
  VEX_LEN_0F51_P_3,
  VEX_LEN_0F52_P_1,
  VEX_LEN_0F53_P_1,
  VEX_LEN_0F58_P_1,
  VEX_LEN_0F58_P_3,
  VEX_LEN_0F59_P_1,
  VEX_LEN_0F59_P_3,
  VEX_LEN_0F5A_P_1,
  VEX_LEN_0F5A_P_3,
  VEX_LEN_0F5C_P_1,
  VEX_LEN_0F5C_P_3,
  VEX_LEN_0F5D_P_1,
  VEX_LEN_0F5D_P_3,
  VEX_LEN_0F5E_P_1,
  VEX_LEN_0F5E_P_3,
  VEX_LEN_0F5F_P_1,
  VEX_LEN_0F5F_P_3,
  VEX_LEN_0F6E_P_2,
  VEX_LEN_0F7E_P_1,
  VEX_LEN_0F7E_P_2,
  VEX_LEN_0F90_P_0,
  VEX_LEN_0F91_P_0,
  VEX_LEN_0F92_P_0,
  VEX_LEN_0F93_P_0,
  VEX_LEN_0F98_P_0,
  VEX_LEN_0FAE_R_2_M_0,
  VEX_LEN_0FAE_R_3_M_0,
  VEX_LEN_0FC2_P_1,
  VEX_LEN_0FC2_P_3,
  VEX_LEN_0FC4_P_2,
  VEX_LEN_0FC5_P_2,
  VEX_LEN_0FD6_P_2,
  VEX_LEN_0FF7_P_2,
  VEX_LEN_0F3816_P_2,
  VEX_LEN_0F3819_P_2,
  VEX_LEN_0F381A_P_2_M_0,
  VEX_LEN_0F3836_P_2,
  VEX_LEN_0F3841_P_2,
  VEX_LEN_0F385A_P_2_M_0,
  VEX_LEN_0F38DB_P_2,
  VEX_LEN_0F38DC_P_2,
  VEX_LEN_0F38DD_P_2,
  VEX_LEN_0F38DE_P_2,
  VEX_LEN_0F38DF_P_2,
  VEX_LEN_0F38F2_P_0,
  VEX_LEN_0F38F3_R_1_P_0,
  VEX_LEN_0F38F3_R_2_P_0,
  VEX_LEN_0F38F3_R_3_P_0,
  VEX_LEN_0F38F5_P_0,
  VEX_LEN_0F38F5_P_1,
  VEX_LEN_0F38F5_P_3,
  VEX_LEN_0F38F6_P_3,
  VEX_LEN_0F38F7_P_0,
  VEX_LEN_0F38F7_P_1,
  VEX_LEN_0F38F7_P_2,
  VEX_LEN_0F38F7_P_3,
  VEX_LEN_0F3A00_P_2,
  VEX_LEN_0F3A01_P_2,
  VEX_LEN_0F3A06_P_2,
  VEX_LEN_0F3A0A_P_2,
  VEX_LEN_0F3A0B_P_2,
  VEX_LEN_0F3A14_P_2,
  VEX_LEN_0F3A15_P_2,
  VEX_LEN_0F3A16_P_2,
  VEX_LEN_0F3A17_P_2,
  VEX_LEN_0F3A18_P_2,
  VEX_LEN_0F3A19_P_2,
  VEX_LEN_0F3A20_P_2,
  VEX_LEN_0F3A21_P_2,
  VEX_LEN_0F3A22_P_2,
  VEX_LEN_0F3A30_P_2,
  VEX_LEN_0F3A32_P_2,
  VEX_LEN_0F3A38_P_2,
  VEX_LEN_0F3A39_P_2,
  VEX_LEN_0F3A41_P_2,
  VEX_LEN_0F3A44_P_2,
  VEX_LEN_0F3A46_P_2,
  VEX_LEN_0F3A60_P_2,
  VEX_LEN_0F3A61_P_2,
  VEX_LEN_0F3A62_P_2,
  VEX_LEN_0F3A63_P_2,
  VEX_LEN_0F3A6A_P_2,
  VEX_LEN_0F3A6B_P_2,
  VEX_LEN_0F3A6E_P_2,
  VEX_LEN_0F3A6F_P_2,
  VEX_LEN_0F3A7A_P_2,
  VEX_LEN_0F3A7B_P_2,
  VEX_LEN_0F3A7E_P_2,
  VEX_LEN_0F3A7F_P_2,
  VEX_LEN_0F3ADF_P_2,
  VEX_LEN_0F3AF0_P_3,
  VEX_LEN_0FXOP_08_CC,
  VEX_LEN_0FXOP_08_CD,
  VEX_LEN_0FXOP_08_CE,
  VEX_LEN_0FXOP_08_CF,
  VEX_LEN_0FXOP_08_EC,
  VEX_LEN_0FXOP_08_ED,
  VEX_LEN_0FXOP_08_EE,
  VEX_LEN_0FXOP_08_EF,
  VEX_LEN_0FXOP_09_80,
  VEX_LEN_0FXOP_09_81
};

enum
{
  VEX_W_0F10_P_0 = 0,
  VEX_W_0F10_P_1,
  VEX_W_0F10_P_2,
  VEX_W_0F10_P_3,
  VEX_W_0F11_P_0,
  VEX_W_0F11_P_1,
  VEX_W_0F11_P_2,
  VEX_W_0F11_P_3,
  VEX_W_0F12_P_0_M_0,
  VEX_W_0F12_P_0_M_1,
  VEX_W_0F12_P_1,
  VEX_W_0F12_P_2,
  VEX_W_0F12_P_3,
  VEX_W_0F13_M_0,
  VEX_W_0F14,
  VEX_W_0F15,
  VEX_W_0F16_P_0_M_0,
  VEX_W_0F16_P_0_M_1,
  VEX_W_0F16_P_1,
  VEX_W_0F16_P_2,
  VEX_W_0F17_M_0,
  VEX_W_0F28,
  VEX_W_0F29,
  VEX_W_0F2B_M_0,
  VEX_W_0F2E_P_0,
  VEX_W_0F2E_P_2,
  VEX_W_0F2F_P_0,
  VEX_W_0F2F_P_2,
  VEX_W_0F41_P_0_LEN_1,
  VEX_W_0F42_P_0_LEN_1,
  VEX_W_0F44_P_0_LEN_0,
  VEX_W_0F45_P_0_LEN_1,
  VEX_W_0F46_P_0_LEN_1,
  VEX_W_0F47_P_0_LEN_1,
  VEX_W_0F4B_P_2_LEN_1,
  VEX_W_0F50_M_0,
  VEX_W_0F51_P_0,
  VEX_W_0F51_P_1,
  VEX_W_0F51_P_2,
  VEX_W_0F51_P_3,
  VEX_W_0F52_P_0,
  VEX_W_0F52_P_1,
  VEX_W_0F53_P_0,
  VEX_W_0F53_P_1,
  VEX_W_0F58_P_0,
  VEX_W_0F58_P_1,
  VEX_W_0F58_P_2,
  VEX_W_0F58_P_3,
  VEX_W_0F59_P_0,
  VEX_W_0F59_P_1,
  VEX_W_0F59_P_2,
  VEX_W_0F59_P_3,
  VEX_W_0F5A_P_0,
  VEX_W_0F5A_P_1,
  VEX_W_0F5A_P_3,
  VEX_W_0F5B_P_0,
  VEX_W_0F5B_P_1,
  VEX_W_0F5B_P_2,
  VEX_W_0F5C_P_0,
  VEX_W_0F5C_P_1,
  VEX_W_0F5C_P_2,
  VEX_W_0F5C_P_3,
  VEX_W_0F5D_P_0,
  VEX_W_0F5D_P_1,
  VEX_W_0F5D_P_2,
  VEX_W_0F5D_P_3,
  VEX_W_0F5E_P_0,
  VEX_W_0F5E_P_1,
  VEX_W_0F5E_P_2,
  VEX_W_0F5E_P_3,
  VEX_W_0F5F_P_0,
  VEX_W_0F5F_P_1,
  VEX_W_0F5F_P_2,
  VEX_W_0F5F_P_3,
  VEX_W_0F60_P_2,
  VEX_W_0F61_P_2,
  VEX_W_0F62_P_2,
  VEX_W_0F63_P_2,
  VEX_W_0F64_P_2,
  VEX_W_0F65_P_2,
  VEX_W_0F66_P_2,
  VEX_W_0F67_P_2,
  VEX_W_0F68_P_2,
  VEX_W_0F69_P_2,
  VEX_W_0F6A_P_2,
  VEX_W_0F6B_P_2,
  VEX_W_0F6C_P_2,
  VEX_W_0F6D_P_2,
  VEX_W_0F6F_P_1,
  VEX_W_0F6F_P_2,
  VEX_W_0F70_P_1,
  VEX_W_0F70_P_2,
  VEX_W_0F70_P_3,
  VEX_W_0F71_R_2_P_2,
  VEX_W_0F71_R_4_P_2,
  VEX_W_0F71_R_6_P_2,
  VEX_W_0F72_R_2_P_2,
  VEX_W_0F72_R_4_P_2,
  VEX_W_0F72_R_6_P_2,
  VEX_W_0F73_R_2_P_2,
  VEX_W_0F73_R_3_P_2,
  VEX_W_0F73_R_6_P_2,
  VEX_W_0F73_R_7_P_2,
  VEX_W_0F74_P_2,
  VEX_W_0F75_P_2,
  VEX_W_0F76_P_2,
  VEX_W_0F77_P_0,
  VEX_W_0F7C_P_2,
  VEX_W_0F7C_P_3,
  VEX_W_0F7D_P_2,
  VEX_W_0F7D_P_3,
  VEX_W_0F7E_P_1,
  VEX_W_0F7F_P_1,
  VEX_W_0F7F_P_2,
  VEX_W_0F90_P_0_LEN_0,
  VEX_W_0F91_P_0_LEN_0,
  VEX_W_0F92_P_0_LEN_0,
  VEX_W_0F93_P_0_LEN_0,
  VEX_W_0F98_P_0_LEN_0,
  VEX_W_0FAE_R_2_M_0,
  VEX_W_0FAE_R_3_M_0,
  VEX_W_0FC2_P_0,
  VEX_W_0FC2_P_1,
  VEX_W_0FC2_P_2,
  VEX_W_0FC2_P_3,
  VEX_W_0FC4_P_2,
  VEX_W_0FC5_P_2,
  VEX_W_0FD0_P_2,
  VEX_W_0FD0_P_3,
  VEX_W_0FD1_P_2,
  VEX_W_0FD2_P_2,
  VEX_W_0FD3_P_2,
  VEX_W_0FD4_P_2,
  VEX_W_0FD5_P_2,
  VEX_W_0FD6_P_2,
  VEX_W_0FD7_P_2_M_1,
  VEX_W_0FD8_P_2,
  VEX_W_0FD9_P_2,
  VEX_W_0FDA_P_2,
  VEX_W_0FDB_P_2,
  VEX_W_0FDC_P_2,
  VEX_W_0FDD_P_2,
  VEX_W_0FDE_P_2,
  VEX_W_0FDF_P_2,
  VEX_W_0FE0_P_2,
  VEX_W_0FE1_P_2,
  VEX_W_0FE2_P_2,
  VEX_W_0FE3_P_2,
  VEX_W_0FE4_P_2,
  VEX_W_0FE5_P_2,
  VEX_W_0FE6_P_1,
  VEX_W_0FE6_P_2,
  VEX_W_0FE6_P_3,
  VEX_W_0FE7_P_2_M_0,
  VEX_W_0FE8_P_2,
  VEX_W_0FE9_P_2,
  VEX_W_0FEA_P_2,
  VEX_W_0FEB_P_2,
  VEX_W_0FEC_P_2,
  VEX_W_0FED_P_2,
  VEX_W_0FEE_P_2,
  VEX_W_0FEF_P_2,
  VEX_W_0FF0_P_3_M_0,
  VEX_W_0FF1_P_2,
  VEX_W_0FF2_P_2,
  VEX_W_0FF3_P_2,
  VEX_W_0FF4_P_2,
  VEX_W_0FF5_P_2,
  VEX_W_0FF6_P_2,
  VEX_W_0FF7_P_2,
  VEX_W_0FF8_P_2,
  VEX_W_0FF9_P_2,
  VEX_W_0FFA_P_2,
  VEX_W_0FFB_P_2,
  VEX_W_0FFC_P_2,
  VEX_W_0FFD_P_2,
  VEX_W_0FFE_P_2,
  VEX_W_0F3800_P_2,
  VEX_W_0F3801_P_2,
  VEX_W_0F3802_P_2,
  VEX_W_0F3803_P_2,
  VEX_W_0F3804_P_2,
  VEX_W_0F3805_P_2,
  VEX_W_0F3806_P_2,
  VEX_W_0F3807_P_2,
  VEX_W_0F3808_P_2,
  VEX_W_0F3809_P_2,
  VEX_W_0F380A_P_2,
  VEX_W_0F380B_P_2,
  VEX_W_0F380C_P_2,
  VEX_W_0F380D_P_2,
  VEX_W_0F380E_P_2,
  VEX_W_0F380F_P_2,
  VEX_W_0F3816_P_2,
  VEX_W_0F3817_P_2,
  VEX_W_0F3818_P_2,
  VEX_W_0F3819_P_2,
  VEX_W_0F381A_P_2_M_0,
  VEX_W_0F381C_P_2,
  VEX_W_0F381D_P_2,
  VEX_W_0F381E_P_2,
  VEX_W_0F3820_P_2,
  VEX_W_0F3821_P_2,
  VEX_W_0F3822_P_2,
  VEX_W_0F3823_P_2,
  VEX_W_0F3824_P_2,
  VEX_W_0F3825_P_2,
  VEX_W_0F3828_P_2,
  VEX_W_0F3829_P_2,
  VEX_W_0F382A_P_2_M_0,
  VEX_W_0F382B_P_2,
  VEX_W_0F382C_P_2_M_0,
  VEX_W_0F382D_P_2_M_0,
  VEX_W_0F382E_P_2_M_0,
  VEX_W_0F382F_P_2_M_0,
  VEX_W_0F3830_P_2,
  VEX_W_0F3831_P_2,
  VEX_W_0F3832_P_2,
  VEX_W_0F3833_P_2,
  VEX_W_0F3834_P_2,
  VEX_W_0F3835_P_2,
  VEX_W_0F3836_P_2,
  VEX_W_0F3837_P_2,
  VEX_W_0F3838_P_2,
  VEX_W_0F3839_P_2,
  VEX_W_0F383A_P_2,
  VEX_W_0F383B_P_2,
  VEX_W_0F383C_P_2,
  VEX_W_0F383D_P_2,
  VEX_W_0F383E_P_2,
  VEX_W_0F383F_P_2,
  VEX_W_0F3840_P_2,
  VEX_W_0F3841_P_2,
  VEX_W_0F3846_P_2,
  VEX_W_0F3858_P_2,
  VEX_W_0F3859_P_2,
  VEX_W_0F385A_P_2_M_0,
  VEX_W_0F3878_P_2,
  VEX_W_0F3879_P_2,
  VEX_W_0F38DB_P_2,
  VEX_W_0F38DC_P_2,
  VEX_W_0F38DD_P_2,
  VEX_W_0F38DE_P_2,
  VEX_W_0F38DF_P_2,
  VEX_W_0F3A00_P_2,
  VEX_W_0F3A01_P_2,
  VEX_W_0F3A02_P_2,
  VEX_W_0F3A04_P_2,
  VEX_W_0F3A05_P_2,
  VEX_W_0F3A06_P_2,
  VEX_W_0F3A08_P_2,
  VEX_W_0F3A09_P_2,
  VEX_W_0F3A0A_P_2,
  VEX_W_0F3A0B_P_2,
  VEX_W_0F3A0C_P_2,
  VEX_W_0F3A0D_P_2,
  VEX_W_0F3A0E_P_2,
  VEX_W_0F3A0F_P_2,
  VEX_W_0F3A14_P_2,
  VEX_W_0F3A15_P_2,
  VEX_W_0F3A18_P_2,
  VEX_W_0F3A19_P_2,
  VEX_W_0F3A20_P_2,
  VEX_W_0F3A21_P_2,
  VEX_W_0F3A30_P_2_LEN_0,
  VEX_W_0F3A32_P_2_LEN_0,
  VEX_W_0F3A38_P_2,
  VEX_W_0F3A39_P_2,
  VEX_W_0F3A40_P_2,
  VEX_W_0F3A41_P_2,
  VEX_W_0F3A42_P_2,
  VEX_W_0F3A44_P_2,
  VEX_W_0F3A46_P_2,
  VEX_W_0F3A48_P_2,
  VEX_W_0F3A49_P_2,
  VEX_W_0F3A4A_P_2,
  VEX_W_0F3A4B_P_2,
  VEX_W_0F3A4C_P_2,
  VEX_W_0F3A60_P_2,
  VEX_W_0F3A61_P_2,
  VEX_W_0F3A62_P_2,
  VEX_W_0F3A63_P_2,
  VEX_W_0F3ADF_P_2,

  EVEX_W_0F10_P_0,
  EVEX_W_0F10_P_1_M_0,
  EVEX_W_0F10_P_1_M_1,
  EVEX_W_0F10_P_2,
  EVEX_W_0F10_P_3_M_0,
  EVEX_W_0F10_P_3_M_1,
  EVEX_W_0F11_P_0,
  EVEX_W_0F11_P_1_M_0,
  EVEX_W_0F11_P_1_M_1,
  EVEX_W_0F11_P_2,
  EVEX_W_0F11_P_3_M_0,
  EVEX_W_0F11_P_3_M_1,
  EVEX_W_0F12_P_0_M_0,
  EVEX_W_0F12_P_0_M_1,
  EVEX_W_0F12_P_1,
  EVEX_W_0F12_P_2,
  EVEX_W_0F12_P_3,
  EVEX_W_0F13_P_0,
  EVEX_W_0F13_P_2,
  EVEX_W_0F14_P_0,
  EVEX_W_0F14_P_2,
  EVEX_W_0F15_P_0,
  EVEX_W_0F15_P_2,
  EVEX_W_0F16_P_0_M_0,
  EVEX_W_0F16_P_0_M_1,
  EVEX_W_0F16_P_1,
  EVEX_W_0F16_P_2,
  EVEX_W_0F17_P_0,
  EVEX_W_0F17_P_2,
  EVEX_W_0F28_P_0,
  EVEX_W_0F28_P_2,
  EVEX_W_0F29_P_0,
  EVEX_W_0F29_P_2,
  EVEX_W_0F2A_P_1,
  EVEX_W_0F2A_P_3,
  EVEX_W_0F2B_P_0,
  EVEX_W_0F2B_P_2,
  EVEX_W_0F2E_P_0,
  EVEX_W_0F2E_P_2,
  EVEX_W_0F2F_P_0,
  EVEX_W_0F2F_P_2,
  EVEX_W_0F51_P_0,
  EVEX_W_0F51_P_1,
  EVEX_W_0F51_P_2,
  EVEX_W_0F51_P_3,
  EVEX_W_0F58_P_0,
  EVEX_W_0F58_P_1,
  EVEX_W_0F58_P_2,
  EVEX_W_0F58_P_3,
  EVEX_W_0F59_P_0,
  EVEX_W_0F59_P_1,
  EVEX_W_0F59_P_2,
  EVEX_W_0F59_P_3,
  EVEX_W_0F5A_P_0,
  EVEX_W_0F5A_P_1,
  EVEX_W_0F5A_P_2,
  EVEX_W_0F5A_P_3,
  EVEX_W_0F5B_P_0,
  EVEX_W_0F5B_P_1,
  EVEX_W_0F5B_P_2,
  EVEX_W_0F5C_P_0,
  EVEX_W_0F5C_P_1,
  EVEX_W_0F5C_P_2,
  EVEX_W_0F5C_P_3,
  EVEX_W_0F5D_P_0,
  EVEX_W_0F5D_P_1,
  EVEX_W_0F5D_P_2,
  EVEX_W_0F5D_P_3,
  EVEX_W_0F5E_P_0,
  EVEX_W_0F5E_P_1,
  EVEX_W_0F5E_P_2,
  EVEX_W_0F5E_P_3,
  EVEX_W_0F5F_P_0,
  EVEX_W_0F5F_P_1,
  EVEX_W_0F5F_P_2,
  EVEX_W_0F5F_P_3,
  EVEX_W_0F62_P_2,
  EVEX_W_0F66_P_2,
  EVEX_W_0F6A_P_2,
  EVEX_W_0F6C_P_2,
  EVEX_W_0F6D_P_2,
  EVEX_W_0F6E_P_2,
  EVEX_W_0F6F_P_1,
  EVEX_W_0F6F_P_2,
  EVEX_W_0F70_P_2,
  EVEX_W_0F72_R_2_P_2,
  EVEX_W_0F72_R_6_P_2,
  EVEX_W_0F73_R_2_P_2,
  EVEX_W_0F73_R_6_P_2,
  EVEX_W_0F76_P_2,
  EVEX_W_0F78_P_0,
  EVEX_W_0F79_P_0,
  EVEX_W_0F7A_P_1,
  EVEX_W_0F7A_P_3,
  EVEX_W_0F7B_P_1,
  EVEX_W_0F7B_P_3,
  EVEX_W_0F7E_P_1,
  EVEX_W_0F7E_P_2,
  EVEX_W_0F7F_P_1,
  EVEX_W_0F7F_P_2,
  EVEX_W_0FC2_P_0,
  EVEX_W_0FC2_P_1,
  EVEX_W_0FC2_P_2,
  EVEX_W_0FC2_P_3,
  EVEX_W_0FC6_P_0,
  EVEX_W_0FC6_P_2,
  EVEX_W_0FD2_P_2,
  EVEX_W_0FD3_P_2,
  EVEX_W_0FD4_P_2,
  EVEX_W_0FD6_P_2,
  EVEX_W_0FE6_P_1,
  EVEX_W_0FE6_P_2,
  EVEX_W_0FE6_P_3,
  EVEX_W_0FE7_P_2,
  EVEX_W_0FF2_P_2,
  EVEX_W_0FF3_P_2,
  EVEX_W_0FF4_P_2,
  EVEX_W_0FFA_P_2,
  EVEX_W_0FFB_P_2,
  EVEX_W_0FFE_P_2,
  EVEX_W_0F380C_P_2,
  EVEX_W_0F380D_P_2,
  EVEX_W_0F3811_P_1,
  EVEX_W_0F3812_P_1,
  EVEX_W_0F3813_P_1,
  EVEX_W_0F3813_P_2,
  EVEX_W_0F3814_P_1,
  EVEX_W_0F3815_P_1,
  EVEX_W_0F3818_P_2,
  EVEX_W_0F3819_P_2,
  EVEX_W_0F381A_P_2,
  EVEX_W_0F381B_P_2,
  EVEX_W_0F381E_P_2,
  EVEX_W_0F381F_P_2,
  EVEX_W_0F3821_P_1,
  EVEX_W_0F3822_P_1,
  EVEX_W_0F3823_P_1,
  EVEX_W_0F3824_P_1,
  EVEX_W_0F3825_P_1,
  EVEX_W_0F3825_P_2,
  EVEX_W_0F3828_P_2,
  EVEX_W_0F3829_P_2,
  EVEX_W_0F382A_P_1,
  EVEX_W_0F382A_P_2,
  EVEX_W_0F3831_P_1,
  EVEX_W_0F3832_P_1,
  EVEX_W_0F3833_P_1,
  EVEX_W_0F3834_P_1,
  EVEX_W_0F3835_P_1,
  EVEX_W_0F3835_P_2,
  EVEX_W_0F3837_P_2,
  EVEX_W_0F383A_P_1,
  EVEX_W_0F3840_P_2,
  EVEX_W_0F3858_P_2,
  EVEX_W_0F3859_P_2,
  EVEX_W_0F385A_P_2,
  EVEX_W_0F385B_P_2,
  EVEX_W_0F3891_P_2,
  EVEX_W_0F3893_P_2,
  EVEX_W_0F38A1_P_2,
  EVEX_W_0F38A3_P_2,
  EVEX_W_0F38C7_R_1_P_2,
  EVEX_W_0F38C7_R_2_P_2,
  EVEX_W_0F38C7_R_5_P_2,
  EVEX_W_0F38C7_R_6_P_2,

  EVEX_W_0F3A00_P_2,
  EVEX_W_0F3A01_P_2,
  EVEX_W_0F3A04_P_2,
  EVEX_W_0F3A05_P_2,
  EVEX_W_0F3A08_P_2,
  EVEX_W_0F3A09_P_2,
  EVEX_W_0F3A0A_P_2,
  EVEX_W_0F3A0B_P_2,
  EVEX_W_0F3A18_P_2,
  EVEX_W_0F3A19_P_2,
  EVEX_W_0F3A1A_P_2,
  EVEX_W_0F3A1B_P_2,
  EVEX_W_0F3A1D_P_2,
  EVEX_W_0F3A21_P_2,
  EVEX_W_0F3A23_P_2,
  EVEX_W_0F3A38_P_2,
  EVEX_W_0F3A39_P_2,
  EVEX_W_0F3A3A_P_2,
  EVEX_W_0F3A3B_P_2,
  EVEX_W_0F3A43_P_2,
};

typedef void (*op_rtn)(int bytemode, int sizeflag);

struct dis386
{
  const char *name;
  struct
  {
    op_rtn rtn;
    int bytemode;
  } op[5];
};
static const struct dis386 dis386[] = {

  { "addB", { { HLE_Fixup1, b_mode }, { OP_G, b_mode } } },
  { "addS", { { HLE_Fixup1, v_mode }, { OP_G, v_mode } } },
  { "addB", { { OP_G, b_mode }, { OP_E, b_swap_mode } } },
  { "addS", { { OP_G, v_mode }, { OP_E, v_swap_mode } } },
  { "addB", { { OP_IMREG, al_reg }, { OP_I, b_mode } } },
  { "addS", { { OP_IMREG, eAX_reg }, { OP_I, v_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_06)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_07)) } } },

  { "orB", { { HLE_Fixup1, b_mode }, { OP_G, b_mode } } },
  { "orS", { { HLE_Fixup1, v_mode }, { OP_G, v_mode } } },
  { "orB", { { OP_G, b_mode }, { OP_E, b_swap_mode } } },
  { "orS", { { OP_G, v_mode }, { OP_E, v_swap_mode } } },
  { "orB", { { OP_IMREG, al_reg }, { OP_I, b_mode } } },
  { "orS", { { OP_IMREG, eAX_reg }, { OP_I, v_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_0D)) } } },
  { ((void *)0), { { ((void *)0), 0 } } },

  { "adcB", { { HLE_Fixup1, b_mode }, { OP_G, b_mode } } },
  { "adcS", { { HLE_Fixup1, v_mode }, { OP_G, v_mode } } },
  { "adcB", { { OP_G, b_mode }, { OP_E, b_swap_mode } } },
  { "adcS", { { OP_G, v_mode }, { OP_E, v_swap_mode } } },
  { "adcB", { { OP_IMREG, al_reg }, { OP_I, b_mode } } },
  { "adcS", { { OP_IMREG, eAX_reg }, { OP_I, v_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_16)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_17)) } } },

  { "sbbB", { { HLE_Fixup1, b_mode }, { OP_G, b_mode } } },
  { "sbbS", { { HLE_Fixup1, v_mode }, { OP_G, v_mode } } },
  { "sbbB", { { OP_G, b_mode }, { OP_E, b_swap_mode } } },
  { "sbbS", { { OP_G, v_mode }, { OP_E, v_swap_mode } } },
  { "sbbB", { { OP_IMREG, al_reg }, { OP_I, b_mode } } },
  { "sbbS", { { OP_IMREG, eAX_reg }, { OP_I, v_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_1E)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_1F)) } } },

  { "andB", { { HLE_Fixup1, b_mode }, { OP_G, b_mode } } },
  { "andS", { { HLE_Fixup1, v_mode }, { OP_G, v_mode } } },
  { "andB", { { OP_G, b_mode }, { OP_E, b_swap_mode } } },
  { "andS", { { OP_G, v_mode }, { OP_E, v_swap_mode } } },
  { "andB", { { OP_IMREG, al_reg }, { OP_I, b_mode } } },
  { "andS", { { OP_IMREG, eAX_reg }, { OP_I, v_mode } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_27)) } } },

  { "subB", { { HLE_Fixup1, b_mode }, { OP_G, b_mode } } },
  { "subS", { { HLE_Fixup1, v_mode }, { OP_G, v_mode } } },
  { "subB", { { OP_G, b_mode }, { OP_E, b_swap_mode } } },
  { "subS", { { OP_G, v_mode }, { OP_E, v_swap_mode } } },
  { "subB", { { OP_IMREG, al_reg }, { OP_I, b_mode } } },
  { "subS", { { OP_IMREG, eAX_reg }, { OP_I, v_mode } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_2F)) } } },

  { "xorB", { { HLE_Fixup1, b_mode }, { OP_G, b_mode } } },
  { "xorS", { { HLE_Fixup1, v_mode }, { OP_G, v_mode } } },
  { "xorB", { { OP_G, b_mode }, { OP_E, b_swap_mode } } },
  { "xorS", { { OP_G, v_mode }, { OP_E, v_swap_mode } } },
  { "xorB", { { OP_IMREG, al_reg }, { OP_I, b_mode } } },
  { "xorS", { { OP_IMREG, eAX_reg }, { OP_I, v_mode } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_37)) } } },

  { "cmpB", { { OP_E, b_mode }, { OP_G, b_mode } } },
  { "cmpS", { { OP_E, v_mode }, { OP_G, v_mode } } },
  { "cmpB", { { OP_G, b_mode }, { OP_E, b_swap_mode } } },
  { "cmpS", { { OP_G, v_mode }, { OP_E, v_swap_mode } } },
  { "cmpB", { { OP_IMREG, al_reg }, { OP_I, b_mode } } },
  { "cmpS", { { OP_IMREG, eAX_reg }, { OP_I, v_mode } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_3F)) } } },

  { "inc{S|}", { { OP_REG, eAX_reg } } },
  { "inc{S|}", { { OP_REG, eCX_reg } } },
  { "inc{S|}", { { OP_REG, eDX_reg } } },
  { "inc{S|}", { { OP_REG, eBX_reg } } },
  { "inc{S|}", { { OP_REG, eSP_reg } } },
  { "inc{S|}", { { OP_REG, eBP_reg } } },
  { "inc{S|}", { { OP_REG, eSI_reg } } },
  { "inc{S|}", { { OP_REG, eDI_reg } } },

  { "dec{S|}", { { OP_REG, eAX_reg } } },
  { "dec{S|}", { { OP_REG, eCX_reg } } },
  { "dec{S|}", { { OP_REG, eDX_reg } } },
  { "dec{S|}", { { OP_REG, eBX_reg } } },
  { "dec{S|}", { { OP_REG, eSP_reg } } },
  { "dec{S|}", { { OP_REG, eBP_reg } } },
  { "dec{S|}", { { OP_REG, eSI_reg } } },
  { "dec{S|}", { { OP_REG, eDI_reg } } },

  { "pushV", { { OP_REG, rAX_reg } } },
  { "pushV", { { OP_REG, rCX_reg } } },
  { "pushV", { { OP_REG, rDX_reg } } },
  { "pushV", { { OP_REG, rBX_reg } } },
  { "pushV", { { OP_REG, rSP_reg } } },
  { "pushV", { { OP_REG, rBP_reg } } },
  { "pushV", { { OP_REG, rSI_reg } } },
  { "pushV", { { OP_REG, rDI_reg } } },

  { "popV", { { OP_REG, rAX_reg } } },
  { "popV", { { OP_REG, rCX_reg } } },
  { "popV", { { OP_REG, rDX_reg } } },
  { "popV", { { OP_REG, rBX_reg } } },
  { "popV", { { OP_REG, rSP_reg } } },
  { "popV", { { OP_REG, rBP_reg } } },
  { "popV", { { OP_REG, rSI_reg } } },
  { "popV", { { OP_REG, rDI_reg } } },

  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_60)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_61)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_62)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_63)) } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0), { { ((void *)0), 0 } } },

  { "pushT", { { OP_sI, v_mode } } },
  { "imulS", { { OP_G, v_mode }, { OP_E, v_mode }, { OP_I, v_mode } } },
  { "pushT", { { OP_sI, b_T_mode } } },
  { "imulS", { { OP_G, v_mode }, { OP_E, v_mode }, { OP_sI, b_mode } } },
  { "ins{b|}", { { REP_Fixup, eDI_reg }, { OP_IMREG, indir_dx_reg } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_6D)) } } },
  { "outs{b|}", { { REP_Fixup, indir_dx_reg }, { OP_DSreg, eSI_reg } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_6F)) } } },

  { "joH",
    { { OP_J, b_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jnoH",
    { { OP_J, b_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jbH",
    { { OP_J, b_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jaeH",
    { { OP_J, b_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jeH",
    { { OP_J, b_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jneH",
    { { OP_J, b_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jbeH",
    { { OP_J, b_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jaH",
    { { OP_J, b_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },

  { "jsH",
    { { OP_J, b_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jnsH",
    { { OP_J, b_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jpH",
    { { OP_J, b_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jnpH",
    { { OP_J, b_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jlH",
    { { OP_J, b_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jgeH",
    { { OP_J, b_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jleH",
    { { OP_J, b_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jgH",
    { { OP_J, b_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },

  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_80)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_81)) } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_82)) } } },
  { "testB", { { OP_E, b_mode }, { OP_G, b_mode } } },
  { "testS", { { OP_E, v_mode }, { OP_G, v_mode } } },
  { "xchgB", { { HLE_Fixup2, b_mode }, { OP_G, b_mode } } },
  { "xchgS", { { HLE_Fixup2, v_mode }, { OP_G, v_mode } } },

  { "movB", { { HLE_Fixup3, b_mode }, { OP_G, b_mode } } },
  { "movS", { { HLE_Fixup3, v_mode }, { OP_G, v_mode } } },
  { "movB", { { OP_G, b_mode }, { OP_E, b_swap_mode } } },
  { "movS", { { OP_G, v_mode }, { OP_E, v_swap_mode } } },
  { "movD", { { OP_SEG, v_mode }, { OP_SEG, w_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_8D)) } } },
  { "movD", { { OP_SEG, w_mode }, { OP_SEG, v_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_8F)) } } },

  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) }, { ((void *)0), ((PREFIX_90)) } } },
  { "xchgS", { { OP_REG, eCX_reg }, { OP_IMREG, eAX_reg } } },
  { "xchgS", { { OP_REG, eDX_reg }, { OP_IMREG, eAX_reg } } },
  { "xchgS", { { OP_REG, eBX_reg }, { OP_IMREG, eAX_reg } } },
  { "xchgS", { { OP_REG, eSP_reg }, { OP_IMREG, eAX_reg } } },
  { "xchgS", { { OP_REG, eBP_reg }, { OP_IMREG, eAX_reg } } },
  { "xchgS", { { OP_REG, eSI_reg }, { OP_IMREG, eAX_reg } } },
  { "xchgS", { { OP_REG, eDI_reg }, { OP_IMREG, eAX_reg } } },

  { "cW{t|}R", { { ((void *)0), 0 } } },
  { "cR{t|}O", { { ((void *)0), 0 } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_9A)) } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { "pushfT", { { ((void *)0), 0 } } },
  { "popfT", { { ((void *)0), 0 } } },
  { "sahf", { { ((void *)0), 0 } } },
  { "lahf", { { ((void *)0), 0 } } },

  { "mov%LB", { { OP_IMREG, al_reg }, { OP_OFF64, b_mode } } },
  { "mov%LS", { { OP_IMREG, eAX_reg }, { OP_OFF64, v_mode } } },
  { "mov%LB", { { OP_OFF64, b_mode }, { OP_IMREG, al_reg } } },
  { "mov%LS", { { OP_OFF64, v_mode }, { OP_IMREG, eAX_reg } } },
  { "movs{b|}", { { REP_Fixup, eDI_reg }, { OP_DSreg, eSI_reg } } },
  { "movs{R|}", { { REP_Fixup, eDI_reg }, { OP_DSreg, eSI_reg } } },
  { "cmps{b|}", { { OP_DSreg, eSI_reg }, { OP_ESreg, eDI_reg } } },
  { "cmps{R|}", { { OP_DSreg, eSI_reg }, { OP_ESreg, eDI_reg } } },

  { "testB", { { OP_IMREG, al_reg }, { OP_I, b_mode } } },
  { "testS", { { OP_IMREG, eAX_reg }, { OP_I, v_mode } } },
  { "stosB", { { REP_Fixup, eDI_reg }, { OP_IMREG, al_reg } } },
  { "stosS", { { REP_Fixup, eDI_reg }, { OP_IMREG, eAX_reg } } },
  { "lodsB", { { REP_Fixup, al_reg }, { OP_DSreg, eSI_reg } } },
  { "lodsS", { { REP_Fixup, eAX_reg }, { OP_DSreg, eSI_reg } } },
  { "scasB", { { OP_IMREG, al_reg }, { OP_ESreg, eDI_reg } } },
  { "scasS", { { OP_IMREG, eAX_reg }, { OP_ESreg, eDI_reg } } },

  { "movB", { { OP_REG, al_reg }, { OP_I, b_mode } } },
  { "movB", { { OP_REG, cl_reg }, { OP_I, b_mode } } },
  { "movB", { { OP_REG, dl_reg }, { OP_I, b_mode } } },
  { "movB", { { OP_REG, bl_reg }, { OP_I, b_mode } } },
  { "movB", { { OP_REG, ah_reg }, { OP_I, b_mode } } },
  { "movB", { { OP_REG, ch_reg }, { OP_I, b_mode } } },
  { "movB", { { OP_REG, dh_reg }, { OP_I, b_mode } } },
  { "movB", { { OP_REG, bh_reg }, { OP_I, b_mode } } },

  { "mov%LV", { { OP_REG, eAX_reg }, { OP_I64, v_mode } } },
  { "mov%LV", { { OP_REG, eCX_reg }, { OP_I64, v_mode } } },
  { "mov%LV", { { OP_REG, eDX_reg }, { OP_I64, v_mode } } },
  { "mov%LV", { { OP_REG, eBX_reg }, { OP_I64, v_mode } } },
  { "mov%LV", { { OP_REG, eSP_reg }, { OP_I64, v_mode } } },
  { "mov%LV", { { OP_REG, eBP_reg }, { OP_I64, v_mode } } },
  { "mov%LV", { { OP_REG, eSI_reg }, { OP_I64, v_mode } } },
  { "mov%LV", { { OP_REG, eDI_reg }, { OP_I64, v_mode } } },

  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_C0)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_C1)) } } },
  { "retT", { { OP_I, w_mode }, { BND_Fixup, 0 } } },
  { "retT", { { BND_Fixup, 0 } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_C4)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_C5)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_C6)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_C7)) } } },

  { "enterT", { { OP_I, w_mode }, { OP_I, b_mode } } },
  { "leaveT", { { ((void *)0), 0 } } },
  { "Jret{|f}P", { { OP_I, w_mode } } },
  { "Jret{|f}P", { { ((void *)0), 0 } } },
  { "int3", { { ((void *)0), 0 } } },
  { "int", { { OP_I, b_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_CE)) } } },
  { "iretP", { { ((void *)0), 0 } } },

  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_D0)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_D1)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_D2)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_D3)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_D4)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_D5)) } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { "xlat", { { OP_DSreg, eBX_reg } } },

  { ((void *)0), { { ((void *)0), FLOATCODE } } },
  { ((void *)0), { { ((void *)0), FLOATCODE } } },
  { ((void *)0), { { ((void *)0), FLOATCODE } } },
  { ((void *)0), { { ((void *)0), FLOATCODE } } },
  { ((void *)0), { { ((void *)0), FLOATCODE } } },
  { ((void *)0), { { ((void *)0), FLOATCODE } } },
  { ((void *)0), { { ((void *)0), FLOATCODE } } },
  { ((void *)0), { { ((void *)0), FLOATCODE } } },

  { "loopneFH",
    { { OP_J, b_mode },
      { ((void *)0), 0 },
      { ((void *)0), loop_jcxz_mode } } },
  { "loopeFH",
    { { OP_J, b_mode },
      { ((void *)0), 0 },
      { ((void *)0), loop_jcxz_mode } } },
  { "loopFH",
    { { OP_J, b_mode },
      { ((void *)0), 0 },
      { ((void *)0), loop_jcxz_mode } } },
  { "jEcxzH",
    { { OP_J, b_mode },
      { ((void *)0), 0 },
      { ((void *)0), loop_jcxz_mode } } },
  { "inB", { { OP_IMREG, al_reg }, { OP_I, b_mode } } },
  { "inG", { { OP_IMREG, z_mode_ax_reg }, { OP_I, b_mode } } },
  { "outB", { { OP_I, b_mode }, { OP_IMREG, al_reg } } },
  { "outG", { { OP_I, b_mode }, { OP_IMREG, z_mode_ax_reg } } },

  { "callT", { { OP_J, v_mode }, { BND_Fixup, 0 } } },
  { "jmpT", { { OP_J, v_mode }, { BND_Fixup, 0 } } },
  { ((void *)0),
    { { ((void *)0), (USE_X86_64_TABLE) }, { ((void *)0), ((X86_64_EA)) } } },
  { "jmp", { { OP_J, b_mode }, { BND_Fixup, 0 } } },
  { "inB", { { OP_IMREG, al_reg }, { OP_IMREG, indir_dx_reg } } },
  { "inG", { { OP_IMREG, z_mode_ax_reg }, { OP_IMREG, indir_dx_reg } } },
  { "outB", { { OP_IMREG, indir_dx_reg }, { OP_IMREG, al_reg } } },
  { "outG", { { OP_IMREG, indir_dx_reg }, { OP_IMREG, z_mode_ax_reg } } },

  { ((void *)0), { { ((void *)0), 0 } } },
  { "icebp", { { ((void *)0), 0 } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { "hlt", { { ((void *)0), 0 } } },
  { "cmc", { { ((void *)0), 0 } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_F6)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_F7)) } } },

  { "clc", { { ((void *)0), 0 } } },
  { "stc", { { ((void *)0), 0 } } },
  { "cli", { { ((void *)0), 0 } } },
  { "sti", { { ((void *)0), 0 } } },
  { "cld", { { ((void *)0), 0 } } },
  { "std", { { ((void *)0), 0 } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_FE)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_FF)) } } },
};

static const struct dis386 dis386_twobyte[] = {

  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_0F00)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_0F01)) } } },
  { "larS", { { OP_G, v_mode }, { OP_E, w_mode } } },
  { "lslS", { { OP_G, v_mode }, { OP_E, w_mode } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { "syscall", { { ((void *)0), 0 } } },
  { "clts", { { ((void *)0), 0 } } },
  { "sysretP", { { ((void *)0), 0 } } },

  { "invd", { { ((void *)0), 0 } } },
  { "wbinvd", { { ((void *)0), 0 } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { "ud2", { { ((void *)0), 0 } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_0F0D)) } } },
  { "femms", { { ((void *)0), 0 } } },
  { "", { { OP_MMX, 0 }, { OP_EM, v_mode }, { OP_3DNowSuffix, 0 } } },

  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F10)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F11)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F12)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_0F13)) } } },
  { "unpcklpX", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  { "unpckhpX", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F16)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_0F17)) } } },

  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_0F18)) } } },
  { "nopQ", { { OP_E, v_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F1A)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F1B)) } } },
  { "nopQ", { { OP_E, v_mode } } },
  { "nopQ", { { OP_E, v_mode } } },
  { "nopQ", { { OP_E, v_mode } } },
  { "nopQ", { { OP_E, v_mode } } },

  { ((void *)0),
    { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_0F20)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_0F21)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_0F22)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_0F23)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_0F24)) } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0),
    { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_0F26)) } } },
  { ((void *)0), { { ((void *)0), 0 } } },

  { "movapX", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  { "movapX", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F2A)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F2B)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F2C)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F2D)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F2E)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F2F)) } } },

  { "wrmsr", { { ((void *)0), 0 } } },
  { "rdtsc", { { ((void *)0), 0 } } },
  { "rdmsr", { { ((void *)0), 0 } } },
  { "rdpmc", { { ((void *)0), 0 } } },
  { "sysenter", { { ((void *)0), 0 } } },
  { "sysexit", { { ((void *)0), 0 } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { "getsec", { { ((void *)0), 0 } } },

  { ((void *)0),
    { { ((void *)0), (USE_3BYTE_TABLE) },
      { ((void *)0), ((THREE_BYTE_0F38)) } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0),
    { { ((void *)0), (USE_3BYTE_TABLE) },
      { ((void *)0), ((THREE_BYTE_0F3A)) } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0), { { ((void *)0), 0 } } },

  { "cmovoS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  { "cmovnoS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  { "cmovbS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  { "cmovaeS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  { "cmoveS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  { "cmovneS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  { "cmovbeS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  { "cmovaS", { { OP_G, v_mode }, { OP_E, v_mode } } },

  { "cmovsS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  { "cmovnsS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  { "cmovpS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  { "cmovnpS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  { "cmovlS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  { "cmovgeS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  { "cmovleS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  { "cmovgS", { { OP_G, v_mode }, { OP_E, v_mode } } },

  { ((void *)0),
    { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_0F51)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F51)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F52)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F53)) } } },
  { "andpX", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  { "andnpX", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  { "orpX", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  { "xorpX", { { OP_XMM, 0 }, { OP_EX, x_mode } } },

  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F58)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F59)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F5A)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F5B)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F5C)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F5D)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F5E)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F5F)) } } },

  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F60)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F61)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F62)) } } },
  { "packsswb", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pcmpgtb", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pcmpgtw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pcmpgtd", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "packuswb", { { OP_MMX, 0 }, { OP_EM, v_mode } } },

  { "punpckhbw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "punpckhwd", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "punpckhdq", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "packssdw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F6C)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F6D)) } } },
  { "movK", { { OP_MMX, 0 }, { OP_E, dq_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F6F)) } } },

  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F70)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_0F71)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_0F72)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_0F73)) } } },
  { "pcmpeqb", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pcmpeqw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pcmpeqd", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "emms", { { ((void *)0), 0 } } },

  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F78)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F79)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_3BYTE_TABLE) },
      { ((void *)0), ((THREE_BYTE_0F7A)) } } },
  { ((void *)0), { { ((void *)0), 0 } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F7C)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F7D)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F7E)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0F7F)) } } },

  { "joH",
    { { OP_J, v_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jnoH",
    { { OP_J, v_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jbH",
    { { OP_J, v_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jaeH",
    { { OP_J, v_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jeH",
    { { OP_J, v_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jneH",
    { { OP_J, v_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jbeH",
    { { OP_J, v_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jaH",
    { { OP_J, v_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },

  { "jsH",
    { { OP_J, v_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jnsH",
    { { OP_J, v_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jpH",
    { { OP_J, v_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jnpH",
    { { OP_J, v_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jlH",
    { { OP_J, v_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jgeH",
    { { OP_J, v_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jleH",
    { { OP_J, v_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },
  { "jgH",
    { { OP_J, v_mode }, { BND_Fixup, 0 }, { ((void *)0), cond_jump_mode } } },

  { "seto", { { OP_E, b_mode } } },
  { "setno", { { OP_E, b_mode } } },
  { "setb", { { OP_E, b_mode } } },
  { "setae", { { OP_E, b_mode } } },
  { "sete", { { OP_E, b_mode } } },
  { "setne", { { OP_E, b_mode } } },
  { "setbe", { { OP_E, b_mode } } },
  { "seta", { { OP_E, b_mode } } },

  { "sets", { { OP_E, b_mode } } },
  { "setns", { { OP_E, b_mode } } },
  { "setp", { { OP_E, b_mode } } },
  { "setnp", { { OP_E, b_mode } } },
  { "setl", { { OP_E, b_mode } } },
  { "setge", { { OP_E, b_mode } } },
  { "setle", { { OP_E, b_mode } } },
  { "setg", { { OP_E, b_mode } } },

  { "pushT", { { OP_REG, fs_reg } } },
  { "popT", { { OP_REG, fs_reg } } },
  { "cpuid", { { ((void *)0), 0 } } },
  { "btS", { { OP_E, v_mode }, { OP_G, v_mode } } },
  { "shldS", { { OP_E, v_mode }, { OP_G, v_mode }, { OP_I, b_mode } } },
  { "shldS", { { OP_E, v_mode }, { OP_G, v_mode }, { OP_IMREG, cl_reg } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_0FA6)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_0FA7)) } } },

  { "pushT", { { OP_REG, gs_reg } } },
  { "popT", { { OP_REG, gs_reg } } },
  { "rsm", { { ((void *)0), 0 } } },
  { "btsS", { { HLE_Fixup1, v_mode }, { OP_G, v_mode } } },
  { "shrdS", { { OP_E, v_mode }, { OP_G, v_mode }, { OP_I, b_mode } } },
  { "shrdS", { { OP_E, v_mode }, { OP_G, v_mode }, { OP_IMREG, cl_reg } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_0FAE)) } } },
  { "imulS", { { OP_G, v_mode }, { OP_E, v_mode } } },

  { "cmpxchgB", { { HLE_Fixup1, b_mode }, { OP_G, b_mode } } },
  { "cmpxchgS", { { HLE_Fixup1, v_mode }, { OP_G, v_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_0FB2)) } } },
  { "btrS", { { HLE_Fixup1, v_mode }, { OP_G, v_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_0FB4)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_0FB5)) } } },
  { "movz{bR|x}", { { OP_G, v_mode }, { OP_E, b_mode } } },
  { "movz{wR|x}", { { OP_G, v_mode }, { OP_E, w_mode } } },

  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0FB8)) } } },
  { "ud1", { { ((void *)0), 0 } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_0FBA)) } } },
  { "btcS", { { HLE_Fixup1, v_mode }, { OP_G, v_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0FBC)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0FBD)) } } },
  { "movs{bR|x}", { { OP_G, v_mode }, { OP_E, b_mode } } },
  { "movs{wR|x}", { { OP_G, v_mode }, { OP_E, w_mode } } },

  { "xaddB", { { HLE_Fixup1, b_mode }, { OP_G, b_mode } } },
  { "xaddS", { { HLE_Fixup1, v_mode }, { OP_G, v_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0FC2)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0FC3)) } } },
  { "pinsrw", { { OP_MMX, 0 }, { OP_E, dqw_mode }, { OP_I, b_mode } } },
  { "pextrw", { { OP_G, dq_mode }, { OP_MS, v_mode }, { OP_I, b_mode } } },
  { "shufpX", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_0FC7)) } } },

  { "bswap", { { OP_REG, eAX_reg } } },
  { "bswap", { { OP_REG, eCX_reg } } },
  { "bswap", { { OP_REG, eDX_reg } } },
  { "bswap", { { OP_REG, eBX_reg } } },
  { "bswap", { { OP_REG, eSP_reg } } },
  { "bswap", { { OP_REG, eBP_reg } } },
  { "bswap", { { OP_REG, eSI_reg } } },
  { "bswap", { { OP_REG, eDI_reg } } },

  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0FD0)) } } },
  { "psrlw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "psrld", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "psrlq", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "paddq", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pmullw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0FD6)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_0FD7)) } } },

  { "psubusb", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "psubusw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pminub", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pand", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "paddusb", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "paddusw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pmaxub", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pandn", { { OP_MMX, 0 }, { OP_EM, v_mode } } },

  { "pavgb", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "psraw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "psrad", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pavgw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pmulhuw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pmulhw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0FE6)) } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0FE7)) } } },

  { "psubsb", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "psubsw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pminsw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "por", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "paddsb", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "paddsw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pmaxsw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pxor", { { OP_MMX, 0 }, { OP_EM, v_mode } } },

  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0FF0)) } } },
  { "psllw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pslld", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "psllq", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pmuludq", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "pmaddwd", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "psadbw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { ((void *)0),
    { { ((void *)0), (USE_PREFIX_TABLE) },
      { ((void *)0), ((PREFIX_0FF7)) } } },

  { "psubb", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "psubw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "psubd", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "psubq", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "paddb", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "paddw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { "paddd", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
  { ((void *)0), { { ((void *)0), 0 } } },
};

static const unsigned char onebyte_has_modrm[256] = {

  1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1,
  1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1,
  0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0,
  0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
  1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1

};

static const unsigned char twobyte_has_modrm[256] = {

  1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0,
  0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0

};

static const unsigned char twobyte_has_mandatory_prefix[256] = {

  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0

};

static char obuf[100];
static char *obufp;
static char *mnemonicendp;
static char scratchbuf[100];
static unsigned char *start_codep;
static unsigned char *insn_codep;
static unsigned char *codep;
static unsigned char *end_codep;
static int last_lock_prefix;
static int last_repz_prefix;
static int last_repnz_prefix;
static int last_data_prefix;
static int last_addr_prefix;
static int last_rex_prefix;
static int last_seg_prefix;
static int fwait_prefix;

static int mandatory_prefix;

static int active_seg_prefix;

static int all_prefixes[15 - 1];
static disassemble_info *the_info;
static struct
{
  int mod;
  int reg;
  int rm;
} modrm;
static unsigned char need_modrm;
static struct
{
  int scale;
  int index;
  int base;
} sib;
static struct
{
  int register_specifier;
  int length;
  int prefix;
  int w;
  int evex;
  int r;
  int v;
  int mask_register_specifier;
  int zeroing;
  int ll;
  int b;
} vex;
static unsigned char need_vex;
static unsigned char need_vex_reg;
static unsigned char vex_w_done;

struct op
{
  const char *name;
  unsigned int len;
};

static const char **names64;
static const char **names32;
static const char **names16;
static const char **names8;
static const char **names8rex;
static const char **names_seg;
static const char *index64;
static const char *index32;
static const char **index16;
static const char **names_bnd;

static const char *intel_names64[]
    = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15" };
static const char *intel_names32[]
    = { "eax", "ecx", "edx",  "ebx",  "esp",  "ebp",  "esi",  "edi",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d" };
static const char *intel_names16[]
    = { "ax",  "cx",  "dx",   "bx",   "sp",   "bp",   "si",   "di",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w" };
static const char *intel_names8[] = {
  "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
};
static const char *intel_names8rex[]
    = { "al",  "cl",  "dl",   "bl",   "spl",  "bpl",  "sil",  "dil",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b" };
static const char *intel_names_seg[] = {
  "es", "cs", "ss", "ds", "fs", "gs", "?", "?",
};
static const char *intel_index64 = "riz";
static const char *intel_index32 = "eiz";
static const char *intel_index16[]
    = { "bx+si", "bx+di", "bp+si", "bp+di", "si", "di", "bp", "bx" };

static const char *att_names64[]
    = { "%rax", "%rcx", "%rdx", "%rbx", "%rsp", "%rbp", "%rsi", "%rdi",
        "%r8",  "%r9",  "%r10", "%r11", "%r12", "%r13", "%r14", "%r15" };
static const char *att_names32[]
    = { "%eax", "%ecx", "%edx",  "%ebx",  "%esp",  "%ebp",  "%esi",  "%edi",
        "%r8d", "%r9d", "%r10d", "%r11d", "%r12d", "%r13d", "%r14d", "%r15d" };
static const char *att_names16[]
    = { "%ax",  "%cx",  "%dx",   "%bx",   "%sp",   "%bp",   "%si",   "%di",
        "%r8w", "%r9w", "%r10w", "%r11w", "%r12w", "%r13w", "%r14w", "%r15w" };
static const char *att_names8[] = {
  "%al", "%cl", "%dl", "%bl", "%ah", "%ch", "%dh", "%bh",
};
static const char *att_names8rex[]
    = { "%al",  "%cl",  "%dl",   "%bl",   "%spl",  "%bpl",  "%sil",  "%dil",
        "%r8b", "%r9b", "%r10b", "%r11b", "%r12b", "%r13b", "%r14b", "%r15b" };
static const char *att_names_seg[] = {
  "%es", "%cs", "%ss", "%ds", "%fs", "%gs", "%?", "%?",
};
static const char *att_index64 = "%riz";
static const char *att_index32 = "%eiz";
static const char *att_index16[] = { "%bx,%si", "%bx,%di", "%bp,%si",
                                     "%bp,%di", "%si",     "%di",
                                     "%bp",     "%bx" };

static const char **names_mm;
static const char *intel_names_mm[]
    = { "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7" };
static const char *att_names_mm[]
    = { "%mm0", "%mm1", "%mm2", "%mm3", "%mm4", "%mm5", "%mm6", "%mm7" };

static const char *intel_names_bnd[] = { "bnd0", "bnd1", "bnd2", "bnd3" };

static const char *att_names_bnd[] = { "%bnd0", "%bnd1", "%bnd2", "%bnd3" };

static const char **names_xmm;
static const char *intel_names_xmm[] = {
  "xmm0",  "xmm1",  "xmm2",  "xmm3",  "xmm4",  "xmm5",  "xmm6",  "xmm7",
  "xmm8",  "xmm9",  "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
  "xmm16", "xmm17", "xmm18", "xmm19", "xmm20", "xmm21", "xmm22", "xmm23",
  "xmm24", "xmm25", "xmm26", "xmm27", "xmm28", "xmm29", "xmm30", "xmm31"
};
static const char *att_names_xmm[]
    = { "%xmm0",  "%xmm1",  "%xmm2",  "%xmm3",  "%xmm4",  "%xmm5",  "%xmm6",
        "%xmm7",  "%xmm8",  "%xmm9",  "%xmm10", "%xmm11", "%xmm12", "%xmm13",
        "%xmm14", "%xmm15", "%xmm16", "%xmm17", "%xmm18", "%xmm19", "%xmm20",
        "%xmm21", "%xmm22", "%xmm23", "%xmm24", "%xmm25", "%xmm26", "%xmm27",
        "%xmm28", "%xmm29", "%xmm30", "%xmm31" };

static const char **names_ymm;
static const char *intel_names_ymm[] = {
  "ymm0",  "ymm1",  "ymm2",  "ymm3",  "ymm4",  "ymm5",  "ymm6",  "ymm7",
  "ymm8",  "ymm9",  "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",
  "ymm16", "ymm17", "ymm18", "ymm19", "ymm20", "ymm21", "ymm22", "ymm23",
  "ymm24", "ymm25", "ymm26", "ymm27", "ymm28", "ymm29", "ymm30", "ymm31"
};
static const char *att_names_ymm[]
    = { "%ymm0",  "%ymm1",  "%ymm2",  "%ymm3",  "%ymm4",  "%ymm5",  "%ymm6",
        "%ymm7",  "%ymm8",  "%ymm9",  "%ymm10", "%ymm11", "%ymm12", "%ymm13",
        "%ymm14", "%ymm15", "%ymm16", "%ymm17", "%ymm18", "%ymm19", "%ymm20",
        "%ymm21", "%ymm22", "%ymm23", "%ymm24", "%ymm25", "%ymm26", "%ymm27",
        "%ymm28", "%ymm29", "%ymm30", "%ymm31" };

static const char **names_zmm;
static const char *intel_names_zmm[] = {
  "zmm0",  "zmm1",  "zmm2",  "zmm3",  "zmm4",  "zmm5",  "zmm6",  "zmm7",
  "zmm8",  "zmm9",  "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15",
  "zmm16", "zmm17", "zmm18", "zmm19", "zmm20", "zmm21", "zmm22", "zmm23",
  "zmm24", "zmm25", "zmm26", "zmm27", "zmm28", "zmm29", "zmm30", "zmm31"
};
static const char *att_names_zmm[]
    = { "%zmm0",  "%zmm1",  "%zmm2",  "%zmm3",  "%zmm4",  "%zmm5",  "%zmm6",
        "%zmm7",  "%zmm8",  "%zmm9",  "%zmm10", "%zmm11", "%zmm12", "%zmm13",
        "%zmm14", "%zmm15", "%zmm16", "%zmm17", "%zmm18", "%zmm19", "%zmm20",
        "%zmm21", "%zmm22", "%zmm23", "%zmm24", "%zmm25", "%zmm26", "%zmm27",
        "%zmm28", "%zmm29", "%zmm30", "%zmm31" };

static const char **names_mask;
static const char *intel_names_mask[]
    = { "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7" };
static const char *att_names_mask[]
    = { "%k0", "%k1", "%k2", "%k3", "%k4", "%k5", "%k6", "%k7" };

static const char *names_rounding[]
    = { "{rn-sae}", "{rd-sae}", "{ru-sae}", "{rz-sae}" };

static const struct dis386 reg_table[][8] = {

  {
   { "addA", { { HLE_Fixup1, b_mode }, { OP_I, b_mode } } },
   { "orA", { { HLE_Fixup1, b_mode }, { OP_I, b_mode } } },
   { "adcA", { { HLE_Fixup1, b_mode }, { OP_I, b_mode } } },
   { "sbbA", { { HLE_Fixup1, b_mode }, { OP_I, b_mode } } },
   { "andA", { { HLE_Fixup1, b_mode }, { OP_I, b_mode } } },
   { "subA", { { HLE_Fixup1, b_mode }, { OP_I, b_mode } } },
   { "xorA", { { HLE_Fixup1, b_mode }, { OP_I, b_mode } } },
   { "cmpA", { { OP_E, b_mode }, { OP_I, b_mode } } },
  },

  {
   { "addQ", { { HLE_Fixup1, v_mode }, { OP_I, v_mode } } },
   { "orQ", { { HLE_Fixup1, v_mode }, { OP_I, v_mode } } },
   { "adcQ", { { HLE_Fixup1, v_mode }, { OP_I, v_mode } } },
   { "sbbQ", { { HLE_Fixup1, v_mode }, { OP_I, v_mode } } },
   { "andQ", { { HLE_Fixup1, v_mode }, { OP_I, v_mode } } },
   { "subQ", { { HLE_Fixup1, v_mode }, { OP_I, v_mode } } },
   { "xorQ", { { HLE_Fixup1, v_mode }, { OP_I, v_mode } } },
   { "cmpQ", { { OP_E, v_mode }, { OP_I, v_mode } } },
  },

  {
   { "addQ", { { HLE_Fixup1, v_mode }, { OP_sI, b_mode } } },
   { "orQ", { { HLE_Fixup1, v_mode }, { OP_sI, b_mode } } },
   { "adcQ", { { HLE_Fixup1, v_mode }, { OP_sI, b_mode } } },
   { "sbbQ", { { HLE_Fixup1, v_mode }, { OP_sI, b_mode } } },
   { "andQ", { { HLE_Fixup1, v_mode }, { OP_sI, b_mode } } },
   { "subQ", { { HLE_Fixup1, v_mode }, { OP_sI, b_mode } } },
   { "xorQ", { { HLE_Fixup1, v_mode }, { OP_sI, b_mode } } },
   { "cmpQ", { { OP_E, v_mode }, { OP_sI, b_mode } } },
  },

  {
   { "popU", { { OP_E, stack_v_mode } } },
   { ((void *)0),
     { { ((void *)0), (USE_XOP_8F_TABLE) }, { ((void *)0), ((XOP_09)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_XOP_8F_TABLE) }, { ((void *)0), ((XOP_09)) } } },
  },

  {
   { "rolA", { { OP_E, b_mode }, { OP_I, b_mode } } },
   { "rorA", { { OP_E, b_mode }, { OP_I, b_mode } } },
   { "rclA", { { OP_E, b_mode }, { OP_I, b_mode } } },
   { "rcrA", { { OP_E, b_mode }, { OP_I, b_mode } } },
   { "shlA", { { OP_E, b_mode }, { OP_I, b_mode } } },
   { "shrA", { { OP_E, b_mode }, { OP_I, b_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "sarA", { { OP_E, b_mode }, { OP_I, b_mode } } },
  },

  {
   { "rolQ", { { OP_E, v_mode }, { OP_I, b_mode } } },
   { "rorQ", { { OP_E, v_mode }, { OP_I, b_mode } } },
   { "rclQ", { { OP_E, v_mode }, { OP_I, b_mode } } },
   { "rcrQ", { { OP_E, v_mode }, { OP_I, b_mode } } },
   { "shlQ", { { OP_E, v_mode }, { OP_I, b_mode } } },
   { "shrQ", { { OP_E, v_mode }, { OP_I, b_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "sarQ", { { OP_E, v_mode }, { OP_I, b_mode } } },
  },

  {
   { "movA", { { HLE_Fixup3, b_mode }, { OP_I, b_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_C6_REG_7)) } } },
  },

  {
   { "movQ", { { HLE_Fixup3, v_mode }, { OP_I, v_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_C7_REG_7)) } } },
  },

  {
   { "rolA", { { OP_E, b_mode }, { OP_I, const_1_mode } } },
   { "rorA", { { OP_E, b_mode }, { OP_I, const_1_mode } } },
   { "rclA", { { OP_E, b_mode }, { OP_I, const_1_mode } } },
   { "rcrA", { { OP_E, b_mode }, { OP_I, const_1_mode } } },
   { "shlA", { { OP_E, b_mode }, { OP_I, const_1_mode } } },
   { "shrA", { { OP_E, b_mode }, { OP_I, const_1_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "sarA", { { OP_E, b_mode }, { OP_I, const_1_mode } } },
  },

  {
   { "rolQ", { { OP_E, v_mode }, { OP_I, const_1_mode } } },
   { "rorQ", { { OP_E, v_mode }, { OP_I, const_1_mode } } },
   { "rclQ", { { OP_E, v_mode }, { OP_I, const_1_mode } } },
   { "rcrQ", { { OP_E, v_mode }, { OP_I, const_1_mode } } },
   { "shlQ", { { OP_E, v_mode }, { OP_I, const_1_mode } } },
   { "shrQ", { { OP_E, v_mode }, { OP_I, const_1_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "sarQ", { { OP_E, v_mode }, { OP_I, const_1_mode } } },
  },

  {
   { "rolA", { { OP_E, b_mode }, { OP_IMREG, cl_reg } } },
   { "rorA", { { OP_E, b_mode }, { OP_IMREG, cl_reg } } },
   { "rclA", { { OP_E, b_mode }, { OP_IMREG, cl_reg } } },
   { "rcrA", { { OP_E, b_mode }, { OP_IMREG, cl_reg } } },
   { "shlA", { { OP_E, b_mode }, { OP_IMREG, cl_reg } } },
   { "shrA", { { OP_E, b_mode }, { OP_IMREG, cl_reg } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "sarA", { { OP_E, b_mode }, { OP_IMREG, cl_reg } } },
  },

  {
   { "rolQ", { { OP_E, v_mode }, { OP_IMREG, cl_reg } } },
   { "rorQ", { { OP_E, v_mode }, { OP_IMREG, cl_reg } } },
   { "rclQ", { { OP_E, v_mode }, { OP_IMREG, cl_reg } } },
   { "rcrQ", { { OP_E, v_mode }, { OP_IMREG, cl_reg } } },
   { "shlQ", { { OP_E, v_mode }, { OP_IMREG, cl_reg } } },
   { "shrQ", { { OP_E, v_mode }, { OP_IMREG, cl_reg } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "sarQ", { { OP_E, v_mode }, { OP_IMREG, cl_reg } } },
  },

  {
   { "testA", { { OP_E, b_mode }, { OP_I, b_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "notA", { { HLE_Fixup1, b_mode } } },
   { "negA", { { HLE_Fixup1, b_mode } } },
   { "mulA", { { OP_E, b_mode } } },
   { "imulA", { { OP_E, b_mode } } },
   { "divA", { { OP_E, b_mode } } },
   { "idivA", { { OP_E, b_mode } } },
  },

  {
   { "testQ", { { OP_E, v_mode }, { OP_I, v_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "notQ", { { HLE_Fixup1, v_mode } } },
   { "negQ", { { HLE_Fixup1, v_mode } } },
   { "mulQ", { { OP_E, v_mode } } },
   { "imulQ", { { OP_E, v_mode } } },
   { "divQ", { { OP_E, v_mode } } },
   { "idivQ", { { OP_E, v_mode } } },
  },

  {
   { "incA", { { HLE_Fixup1, b_mode } } },
   { "decA", { { HLE_Fixup1, b_mode } } },
  },

  {
   { "incQ", { { HLE_Fixup1, v_mode } } },
   { "decQ", { { HLE_Fixup1, v_mode } } },
   { "call{T|}", { { OP_indirE, stack_v_mode }, { BND_Fixup, 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_FF_REG_3)) } } },
   { "jmp{T|}", { { OP_indirE, stack_v_mode }, { BND_Fixup, 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_FF_REG_5)) } } },
   { "pushU", { { OP_E, stack_v_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {
   { "sldtD", { { OP_SEG, v_mode } } },
   { "strD", { { OP_SEG, v_mode } } },
   { "lldt", { { OP_E, w_mode } } },
   { "ltr", { { OP_E, w_mode } } },
   { "verr", { { OP_E, w_mode } } },
   { "verw", { { OP_E, w_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F01_REG_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F01_REG_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F01_REG_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F01_REG_3)) } } },
   { "smswD", { { OP_SEG, v_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "lmsw", { { OP_E, w_mode } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F01_REG_7)) } } },
  },

  {
   { "prefetch", { { OP_M, b_mode } } },
   { "prefetchw", { { OP_M, b_mode } } },
   { "prefetchwt1", { { OP_M, b_mode } } },
   { "prefetch", { { OP_M, b_mode } } },
   { "prefetch", { { OP_M, b_mode } } },
   { "prefetch", { { OP_M, b_mode } } },
   { "prefetch", { { OP_M, b_mode } } },
   { "prefetch", { { OP_M, b_mode } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F18_REG_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F18_REG_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F18_REG_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F18_REG_3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F18_REG_4)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F18_REG_5)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F18_REG_6)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F18_REG_7)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F71_REG_2)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F71_REG_4)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F71_REG_6)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F72_REG_2)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F72_REG_4)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F72_REG_6)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F73_REG_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F73_REG_3)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F73_REG_6)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F73_REG_7)) } } },
  },

  {
   { "montmul", { { OP_0f07, 0 } } },
   { "xsha1", { { OP_0f07, 0 } } },
   { "xsha256", { { OP_0f07, 0 } } },
  },

  {
   { "xstore-rng", { { OP_0f07, 0 } } },
   { "xcrypt-ecb", { { OP_0f07, 0 } } },
   { "xcrypt-cbc", { { OP_0f07, 0 } } },
   { "xcrypt-ctr", { { OP_0f07, 0 } } },
   { "xcrypt-cfb", { { OP_0f07, 0 } } },
   { "xcrypt-ofb", { { OP_0f07, 0 } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0FAE_REG_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0FAE_REG_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0FAE_REG_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0FAE_REG_3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0FAE_REG_4)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0FAE_REG_5)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0FAE_REG_6)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0FAE_REG_7)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "btQ", { { OP_E, v_mode }, { OP_I, b_mode } } },
   { "btsQ", { { HLE_Fixup1, v_mode }, { OP_I, b_mode } } },
   { "btrQ", { { HLE_Fixup1, v_mode }, { OP_I, b_mode } } },
   { "btcQ", { { HLE_Fixup1, v_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "cmpxchg8b", { { CMPXCHG8B_Fixup, q_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0FC7_REG_3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0FC7_REG_4)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0FC7_REG_5)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0FC7_REG_6)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0FC7_REG_7)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F71_REG_2)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F71_REG_4)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F71_REG_6)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F72_REG_2)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F72_REG_4)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F72_REG_6)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F73_REG_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F73_REG_3)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F73_REG_6)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F73_REG_7)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0FAE_REG_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0FAE_REG_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38F3_REG_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38F3_REG_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38F3_REG_3)) } } },
  },

  {
   { "llwpcb", { { OP_LWPCB_E, 0 } } }, { "slwpcb", { { OP_LWPCB_E, 0 } } },
  },

  {
   { "lwpins", { { OP_LWP_E, 0 }, { OP_E, d_mode }, { OP_I, q_mode } } },
   { "lwpval", { { OP_LWP_E, 0 }, { OP_E, d_mode }, { OP_I, q_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "blcfill", { { OP_LWP_E, 0 }, { OP_E, v_mode } } },
   { "blsfill", { { OP_LWP_E, 0 }, { OP_E, v_mode } } },
   { "blcs", { { OP_LWP_E, 0 }, { OP_E, v_mode } } },
   { "tzmsk", { { OP_LWP_E, 0 }, { OP_E, v_mode } } },
   { "blcic", { { OP_LWP_E, 0 }, { OP_E, v_mode } } },
   { "blsic", { { OP_LWP_E, 0 }, { OP_E, v_mode } } },
   { "t1mskc", { { OP_LWP_E, 0 }, { OP_E, v_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "blcmsk", { { OP_LWP_E, 0 }, { OP_E, v_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "blci", { { OP_LWP_E, 0 }, { OP_E, v_mode } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F72_REG_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F72_REG_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F72_REG_2)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F72_REG_4)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F72_REG_6)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F73_REG_2)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F73_REG_6)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_EVEX_0F38C6_REG_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_EVEX_0F38C6_REG_2)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_EVEX_0F38C6_REG_5)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_EVEX_0F38C6_REG_6)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_EVEX_0F38C7_REG_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_EVEX_0F38C7_REG_2)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_EVEX_0F38C7_REG_5)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_EVEX_0F38C7_REG_6)) } } },
  },

};

static const struct dis386 prefix_table[][4] = {

  {
   { "xchgS", { { NOP_Fixup1, eAX_reg }, { NOP_Fixup2, eAX_reg } } },
   { "pause", { { ((void *)0), 0 } } },
   { "xchgS", { { NOP_Fixup1, eAX_reg }, { NOP_Fixup2, eAX_reg } } },
  },

  {
   { "movups", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "movss", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
   { "movupd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "movsd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { "movups", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
   { "movss", { { OP_EX, d_swap_mode }, { OP_XMM, 0 } } },
   { "movupd", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
   { "movsd", { { OP_EX, q_swap_mode }, { OP_XMM, 0 } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F12_PREFIX_0)) } } },
   { "movsldup", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "movlpd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { "movddup", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F16_PREFIX_0)) } } },
   { "movshdup", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "movhpd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F1A_PREFIX_0)) } } },
   { "bndcl", { { OP_G, bnd_mode }, { OP_E, v_bnd_mode } } },
   { "bndmov", { { OP_G, bnd_mode }, { OP_E, bnd_mode } } },
   { "bndcu", { { OP_G, bnd_mode }, { OP_E, v_bnd_mode } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F1B_PREFIX_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F1B_PREFIX_1)) } } },
   { "bndmov", { { OP_E, bnd_mode }, { OP_G, bnd_mode } } },
   { "bndcn", { { OP_G, bnd_mode }, { OP_E, v_bnd_mode } } },
  },

  {
   { "cvtpi2ps", { { OP_XMM, 0 }, { OP_EMC, q_mode } } },
   { "cvtsi2ss%LQ", { { OP_XMM, 0 }, { OP_E, v_mode } } },
   { "cvtpi2pd", { { OP_XMM, 0 }, { OP_EMC, q_mode } } },
   { "cvtsi2sd%LQ", { { OP_XMM, 0 }, { OP_E, v_mode } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F2B_PREFIX_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F2B_PREFIX_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F2B_PREFIX_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F2B_PREFIX_3)) } } },
  },

  {
   { "cvttps2pi", { { OP_MXC, 0 }, { OP_EX, q_mode } } },
   { "cvttss2siY", { { OP_G, v_mode }, { OP_EX, d_mode } } },
   { "cvttpd2pi", { { OP_MXC, 0 }, { OP_EX, x_mode } } },
   { "cvttsd2siY", { { OP_G, v_mode }, { OP_EX, q_mode } } },
  },

  {
   { "cvtps2pi", { { OP_MXC, 0 }, { OP_EX, q_mode } } },
   { "cvtss2siY", { { OP_G, v_mode }, { OP_EX, d_mode } } },
   { "cvtpd2pi", { { OP_MXC, 0 }, { OP_EX, x_mode } } },
   { "cvtsd2siY", { { OP_G, v_mode }, { OP_EX, q_mode } } },
  },

  {
   { "ucomiss", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "ucomisd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { "comiss", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "comisd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { "sqrtps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "sqrtss", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
   { "sqrtpd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "sqrtsd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { "rsqrtps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "rsqrtss", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
  },

  {
   { "rcpps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "rcpss", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
  },

  {
   { "addps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "addss", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
   { "addpd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "addsd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { "mulps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "mulss", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
   { "mulpd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "mulsd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { "cvtps2pd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { "cvtss2sd", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
   { "cvtpd2ps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "cvtsd2ss", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { "cvtdq2ps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "cvttps2dq", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "cvtps2dq", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { "subps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "subss", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
   { "subpd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "subsd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { "minps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "minss", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
   { "minpd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "minsd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { "divps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "divss", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
   { "divpd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "divsd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { "maxps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "maxss", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
   { "maxpd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "maxsd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { "punpcklbw", { { OP_MMX, 0 }, { OP_EM, d_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "punpcklbw", { { OP_MMX, 0 }, { OP_EM, x_mode } } },
  },

  {
   { "punpcklwd", { { OP_MMX, 0 }, { OP_EM, d_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "punpcklwd", { { OP_MMX, 0 }, { OP_EM, x_mode } } },
  },

  {
   { "punpckldq", { { OP_MMX, 0 }, { OP_EM, d_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "punpckldq", { { OP_MMX, 0 }, { OP_EM, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "punpcklqdq", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "punpckhqdq", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { "movq", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
   { "movdqu", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "movdqa", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { "pshufw", { { OP_MMX, 0 }, { OP_EM, v_mode }, { OP_I, b_mode } } },
   { "pshufhw", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
   { "pshufd", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
   { "pshuflw", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "psrldq", { { OP_XS, v_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pslldq", { { OP_XS, v_mode }, { OP_I, b_mode } } },
  },

  {
   { "vmread", { { OP_E, m_mode }, { OP_G, m_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "extrq", { { OP_XS, v_mode }, { OP_I, b_mode }, { OP_I, b_mode } } },
   { "insertq",
     { { OP_XMM, 0 },
       { OP_XS, v_mode },
       { OP_I, b_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vmwrite", { { OP_G, m_mode }, { OP_E, m_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "extrq", { { OP_XMM, 0 }, { OP_XS, v_mode } } },
   { "insertq", { { OP_XMM, 0 }, { OP_XS, v_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "haddpd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "haddps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "hsubpd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "hsubps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { "movK", { { OP_E, dq_mode }, { OP_MMX, 0 } } },
   { "movq", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { "movK", { { OP_E, dq_mode }, { OP_XMM, 0 } } },
  },

  {
   { "movq", { { OP_EM, v_swap_mode }, { OP_MMX, 0 } } },
   { "movdqu", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
   { "movdqa", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "rdfsbase", { { OP_E, v_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "rdgsbase", { { OP_E, v_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "wrfsbase", { { OP_E, v_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "wrgsbase", { { OP_E, v_mode } } },
  },

  {
   { "clflush", { { OP_M, b_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "clflushopt", { { OP_M, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "popcntS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  },

  {
   { "bsfS", { { OP_G, v_mode }, { OP_E, v_mode } } },
   { "tzcntS", { { OP_G, v_mode }, { OP_E, v_mode } } },
   { "bsfS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  },

  {
   { "bsrS", { { OP_G, v_mode }, { OP_E, v_mode } } },
   { "lzcntS", { { OP_G, v_mode }, { OP_E, v_mode } } },
   { "bsrS", { { OP_G, v_mode }, { OP_E, v_mode } } },
  },

  {
   { "cmpps", { { OP_XMM, 0 }, { OP_EX, x_mode }, { CMP_Fixup, 0 } } },
   { "cmpss", { { OP_XMM, 0 }, { OP_EX, d_mode }, { CMP_Fixup, 0 } } },
   { "cmppd", { { OP_XMM, 0 }, { OP_EX, x_mode }, { CMP_Fixup, 0 } } },
   { "cmpsd", { { OP_XMM, 0 }, { OP_EX, q_mode }, { CMP_Fixup, 0 } } },
  },

  {
   { "movntiS", { { OP_M, a_mode }, { OP_G, v_mode } } },
  },

  {
   { "vmptrld", { { OP_M, q_mode } } },
   { "vmxon", { { OP_M, q_mode } } },
   { "vmclear", { { OP_M, q_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "addsubpd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "addsubps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "movq2dq", { { OP_XMM, 0 }, { OP_MS, v_mode } } },
   { "movq", { { OP_EX, q_swap_mode }, { OP_XMM, 0 } } },
   { "movdq2q", { { OP_MMX, 0 }, { OP_XS, v_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "cvtdq2pd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { "cvttpd2dq", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
   { "cvtpd2dq", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { "movntq", { { OP_M, q_mode }, { OP_MMX, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0FE7_PREFIX_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0FF0_PREFIX_3)) } } },
  },

  {
   { "maskmovq", { { OP_MMX, 0 }, { OP_MS, v_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "maskmovdqu", { { OP_XMM, 0 }, { OP_XS, v_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pblendvb", { { OP_XMM, 0 }, { OP_EX, x_mode }, { XMM_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "blendvps", { { OP_XMM, 0 }, { OP_EX, x_mode }, { XMM_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "blendvpd", { { OP_XMM, 0 }, { OP_EX, x_mode }, { XMM_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "ptest", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmovsxbw", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmovsxbd", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmovsxbq", { { OP_XMM, 0 }, { OP_EX, w_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmovsxwd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmovsxwq", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmovsxdq", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmuldq", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pcmpeqq", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_0F382A_PREFIX_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "packusdw", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmovzxbw", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmovzxbd", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmovzxbq", { { OP_XMM, 0 }, { OP_EX, w_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmovzxwd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmovzxwq", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmovzxdq", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pcmpgtq", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pminsb", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pminsd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pminuw", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pminud", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmaxsb", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmaxsd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmaxuw", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmaxud", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmulld", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "phminposuw", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "invept", { { OP_G, m_mode }, { OP_M, o_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "invvpid", { { OP_G, m_mode }, { OP_M, o_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "invpcid", { { OP_G, m_mode }, { OP_M, 0 } } },
  },

  {
   { "sha1nexte", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
  },

  {
   { "sha1msg1", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
  },

  {
   { "sha1msg2", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
  },

  {
   { "sha256rnds2", { { OP_XMM, 0 }, { OP_EX, xmm_mode }, { XMM_Fixup, 0 } } },
  },

  {
   { "sha256msg1", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
  },

  {
   { "sha256msg2", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "aesimc", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "aesenc", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "aesenclast", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "aesdec", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "aesdeclast", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { "movbeS", { { OP_G, v_mode }, { MOVBE_Fixup, v_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "movbeS", { { OP_G, v_mode }, { MOVBE_Fixup, v_mode } } },
   { "crc32", { { OP_G, dq_mode }, { CRC32_Fixup, b_mode } } },
  },

  {
   { "movbeS", { { MOVBE_Fixup, v_mode }, { OP_G, v_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "movbeS", { { MOVBE_Fixup, v_mode }, { OP_G, v_mode } } },
   { "crc32", { { OP_G, dq_mode }, { CRC32_Fixup, v_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "adoxS", { { OP_G, dq_mode }, { OP_E, dq_mode } } },
   { "adcxS", { { OP_G, dq_mode }, { OP_E, dq_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "roundps", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "roundpd", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "roundss", { { OP_XMM, 0 }, { OP_EX, d_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "roundsd", { { OP_XMM, 0 }, { OP_EX, q_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "blendps", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "blendpd", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pblendw", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pextrb", { { OP_E, dqb_mode }, { OP_XMM, 0 }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pextrw", { { OP_E, dqw_mode }, { OP_XMM, 0 }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pextrK", { { OP_E, dq_mode }, { OP_XMM, 0 }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "extractps", { { OP_E, dqd_mode }, { OP_XMM, 0 }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pinsrb", { { OP_XMM, 0 }, { OP_E, dqb_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "insertps", { { OP_XMM, 0 }, { OP_EX, d_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pinsrK", { { OP_XMM, 0 }, { OP_E, dq_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "dpps", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "dppd", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "mpsadbw", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pclmulqdq", { { OP_XMM, 0 }, { OP_EX, x_mode }, { PCLMUL_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pcmpestrm", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pcmpestri", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pcmpistrm", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pcmpistri", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { "sha1rnds4", { { OP_XMM, 0 }, { OP_EX, xmm_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "aeskeygenassist",
     { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F10_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F10_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F10_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F10_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F11_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F11_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F11_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F11_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F12_PREFIX_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F12_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F12_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F12_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F16_PREFIX_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F16_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F16_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F2A_P_1)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F2A_P_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F2C_P_1)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F2C_P_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F2D_P_1)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F2D_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F2E_P_0)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F2E_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F2F_P_0)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F2F_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F41_P_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F42_P_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F44_P_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F45_P_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F46_P_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F47_P_0)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F4B_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F51_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F51_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F51_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F51_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F52_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F52_P_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F53_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F53_P_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F58_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F58_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F58_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F58_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F59_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F59_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F59_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F59_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5A_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F5A_P_1)) } } },
   { "vcvtpd2ps%XY", { { OP_XMM, xmm_mode }, { OP_EX, x_mode } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F5A_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5B_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5B_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5B_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5C_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F5C_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5C_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F5C_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5D_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F5D_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5D_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F5D_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5E_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F5E_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5E_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F5E_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5F_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F5F_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5F_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F5F_P_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F60_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F61_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F62_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F63_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F64_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F65_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F66_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F67_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F68_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F69_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F6A_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F6B_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F6C_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F6D_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F6E_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F6F_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F6F_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F70_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F70_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F70_P_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F71_R_2_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F71_R_4_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F71_R_6_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F72_R_2_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F72_R_4_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F72_R_6_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F73_R_2_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F73_R_3_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F73_R_6_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F73_R_7_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F74_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F75_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F76_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F77_P_0)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F7C_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F7C_P_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F7D_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F7D_P_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F7E_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F7E_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F7F_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F7F_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F90_P_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F91_P_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F92_P_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F93_P_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F98_P_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FC2_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FC2_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FC2_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FC2_P_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FC4_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FC5_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FD0_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FD0_P_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FD1_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FD2_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FD3_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FD4_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FD5_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FD6_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0FD7_PREFIX_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FD8_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FD9_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FDA_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FDB_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FDC_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FDD_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FDE_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FDF_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FE0_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FE1_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FE2_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FE3_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FE4_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FE5_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FE6_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FE6_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FE6_P_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0FE7_PREFIX_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FE8_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FE9_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FEA_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FEB_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FEC_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FED_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FEE_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FEF_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0FF0_PREFIX_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FF1_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FF2_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FF3_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FF4_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FF5_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FF6_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FF7_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FF8_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FF9_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FFA_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FFB_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FFC_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FFD_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FFE_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3800_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3801_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3802_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3803_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3804_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3805_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3806_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3807_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3808_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3809_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F380A_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F380B_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F380C_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F380D_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F380E_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F380F_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vcvtph2ps", { { OP_XMM, 0 }, { OP_EX, xmmq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3816_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3817_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3818_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3819_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F381A_PREFIX_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F381C_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F381D_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F381E_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3820_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3821_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3822_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3823_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3824_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3825_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3828_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3829_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F382A_PREFIX_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F382B_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F382C_PREFIX_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F382D_PREFIX_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F382E_PREFIX_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F382F_PREFIX_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3830_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3831_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3832_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3833_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3834_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3835_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3836_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3837_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3838_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3839_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F383A_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F383B_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F383C_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F383D_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F383E_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F383F_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3840_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3841_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpsrlv%LW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3846_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpsllv%LW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3858_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3859_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F385A_PREFIX_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3878_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3879_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F388C_PREFIX_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_VEX_0F388E_PREFIX_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpgatherd%LW",
     { { OP_XMM, 0 }, { OP_M, vex_vsib_d_w_dq_mode }, { OP_VEX, vex_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpgatherq%LW",
     { { OP_XMM, vex_vsib_q_w_dq_mode },
       { OP_M, vex_vsib_q_w_dq_mode },
       { OP_VEX, vex_vsib_q_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vgatherdp%XW",
     { { OP_XMM, 0 }, { OP_M, vex_vsib_d_w_dq_mode }, { OP_VEX, vex_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vgatherqp%XW",
     { { OP_XMM, vex_vsib_q_w_dq_mode },
       { OP_M, vex_vsib_q_w_dq_mode },
       { OP_VEX, vex_vsib_q_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmaddsub132p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsubadd132p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmadd132p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmadd132s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, vex_scalar_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsub132p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsub132s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, vex_scalar_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmadd132p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmadd132s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, vex_scalar_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmsub132p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmsub132s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, vex_scalar_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmaddsub213p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsubadd213p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmadd213p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmadd213s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, vex_scalar_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsub213p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsub213s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, vex_scalar_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmadd213p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmadd213s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, vex_scalar_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmsub213p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmsub213s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, vex_scalar_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmaddsub231p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsubadd231p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmadd231p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmadd231s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, vex_scalar_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsub231p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsub231s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, vex_scalar_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmadd231p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmadd231s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, vex_scalar_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmsub231p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmsub231s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, vex_scalar_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38DB_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38DC_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38DD_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38DE_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38DF_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38F2_P_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38F3_R_1_P_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38F3_R_2_P_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38F3_R_3_P_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38F5_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38F5_P_1)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38F5_P_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38F6_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38F7_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38F7_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38F7_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F38F7_P_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A00_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A01_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A02_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A04_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A05_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A06_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A08_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A09_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A0A_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A0B_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A0C_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A0D_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A0E_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A0F_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A14_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A15_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A16_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A17_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A18_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A19_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vcvtps2ph", { { OP_EX, xmmq_mode }, { OP_XMM, 0 }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A20_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A21_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A22_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A30_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A32_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A38_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A39_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A40_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A41_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A42_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A44_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A46_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A48_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A49_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A4A_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A4B_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A4C_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmaddsubps",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmaddsubpd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsubaddps",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsubaddpd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A60_P_2)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A61_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A62_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A63_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmaddps",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmaddpd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A6A_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A6B_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsubps",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsubpd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A6E_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A6F_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmaddps",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmaddpd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A7A_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A7B_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmsubps",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmsubpd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A7E_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3A7F_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3ADF_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F3AF0_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F10_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_EVEX_0F10_PREFIX_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F10_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_EVEX_0F10_PREFIX_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F11_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_EVEX_0F11_PREFIX_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F11_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_EVEX_0F11_PREFIX_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_EVEX_0F12_PREFIX_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F12_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F12_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F12_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F13_P_0)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F13_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F14_P_0)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F14_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F15_P_0)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F15_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) },
       { ((void *)0), ((MOD_EVEX_0F16_PREFIX_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F16_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F16_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F17_P_0)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F17_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F28_P_0)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F28_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F29_P_0)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F29_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F2A_P_1)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F2A_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F2B_P_0)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F2B_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vcvttss2si",
     { { OP_G, dq_mode },
       { OP_EX, xmm_md_mode },
       { OP_Rounding, evex_sae_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vcvttsd2si",
     { { OP_G, dq_mode },
       { OP_EX, xmm_mq_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vcvtss2si",
     { { OP_G, dq_mode },
       { OP_EX, xmm_md_mode },
       { OP_Rounding, evex_rounding_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vcvtsd2si",
     { { OP_G, dq_mode },
       { OP_EX, xmm_mq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F2E_P_0)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F2E_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F2F_P_0)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F2F_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F51_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F51_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F51_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F51_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F58_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F58_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F58_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F58_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F59_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F59_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F59_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F59_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5A_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5A_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5A_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5A_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5B_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5B_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5B_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5C_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5C_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5C_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5C_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5D_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5D_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5D_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5D_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5E_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5E_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5E_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5E_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5F_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5F_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5F_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F5F_P_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F62_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F66_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F6A_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F6C_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F6D_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F6E_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F6F_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F6F_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F70_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpror%LW",
     { { OP_VEX, vex_mode }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vprol%LW",
     { { OP_VEX, vex_mode }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F72_R_2_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpsra%LW",
     { { OP_VEX, vex_mode }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F72_R_6_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F73_R_2_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F73_R_6_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F76_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F78_P_0)) } } },
   { "vcvttss2usi",
     { { OP_G, dq_mode },
       { OP_EX, xmm_md_mode },
       { OP_Rounding, evex_sae_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vcvttsd2usi",
     { { OP_G, dq_mode },
       { OP_EX, xmm_mq_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F79_P_0)) } } },
   { "vcvtss2usi",
     { { OP_G, dq_mode },
       { OP_EX, xmm_md_mode },
       { OP_Rounding, evex_rounding_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vcvtsd2usi",
     { { OP_G, dq_mode },
       { OP_EX, xmm_mq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F7A_P_1)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F7A_P_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F7B_P_1)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F7B_P_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F7E_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F7E_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F7F_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F7F_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FC2_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FC2_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FC2_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FC2_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FC6_P_0)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FC6_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FD2_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FD3_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FD4_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FD6_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpand%LW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpandn%LW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpsra%LW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, xmm_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FE6_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FE6_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FE6_P_3)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FE7_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpor%LW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpxor%LW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FF2_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FF3_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FF4_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FFA_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FFB_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0FFE_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F380C_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F380D_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3811_P_1)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3812_P_1)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3813_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3813_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3814_P_1)) } } },
   { "vprorv%LW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3815_P_1)) } } },
   { "vprolv%LW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpermp%XW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3818_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3819_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F381A_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F381B_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F381E_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F381F_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3821_P_1)) } } },
   { "vpmovsxbd", { { OP_XMM, 0 }, { OP_EX, xmmqd_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3822_P_1)) } } },
   { "vpmovsxbq", { { OP_XMM, 0 }, { OP_EX, xmmdw_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3823_P_1)) } } },
   { "vpmovsxwd", { { OP_XMM, 0 }, { OP_EX, xmmq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3824_P_1)) } } },
   { "vpmovsxwq", { { OP_XMM, 0 }, { OP_EX, xmmqd_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3825_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3825_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vptestnm%LW",
     { { OP_Mask, mask_mode }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
   { "vptestm%LW",
     { { OP_Mask, mask_mode }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3828_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3829_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F382A_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F382A_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vscalefp%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vscalefs%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3831_P_1)) } } },
   { "vpmovzxbd", { { OP_XMM, 0 }, { OP_EX, xmmqd_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3832_P_1)) } } },
   { "vpmovzxbq", { { OP_XMM, 0 }, { OP_EX, xmmdw_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3833_P_1)) } } },
   { "vpmovzxwd", { { OP_XMM, 0 }, { OP_EX, xmmq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3834_P_1)) } } },
   { "vpmovzxwq", { { OP_XMM, 0 }, { OP_EX, xmmqd_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3835_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3835_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vperm%LW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3837_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpmins%LW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F383A_P_1)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpminu%LW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpmaxs%LW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpmaxu%LW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3840_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vgetexpp%XW",
     { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vgetexps%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vplzcnt%LW", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpsrlv%LW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpsrav%LW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpsllv%LW", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vrcp14p%XW", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vrcp14s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vrsqrt14p%XW", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vrsqrt14s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3858_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3859_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F385A_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F385B_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpblendm%LW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vblendmp%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpermi2%LW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpermi2p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpbroadcast%LW", { { OP_XMM, 0 }, { OP_R, dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpermt2%LW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpermt2p%XW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vexpandp%XW", { { OP_XMM, 0 }, { OP_EX, evex_x_gscat_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpexpand%LW", { { OP_XMM, 0 }, { OP_EX, evex_x_gscat_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vcompressp%XW", { { OP_EX, evex_x_gscat_mode }, { OP_XMM, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpcompress%LW", { { OP_EX, evex_x_gscat_mode }, { OP_XMM, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpgatherd%LW", { { OP_XMM, 0 }, { OP_M, vex_vsib_d_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3891_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vgatherdp%XW", { { OP_XMM, 0 }, { OP_M, vex_vsib_d_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3893_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmaddsub132p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsubadd132p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmadd132p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmadd132s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsub132p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsub132s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmadd132p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmadd132s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmsub132p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmsub132s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpscatterd%LW", { { OP_M, vex_vsib_d_w_dq_mode }, { OP_XMM, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F38A1_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vscatterdp%XW", { { OP_M, vex_vsib_d_w_dq_mode }, { OP_XMM, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F38A3_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmaddsub213p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsubadd213p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmadd213p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmadd213s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsub213p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsub213s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmadd213p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmadd213s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmsub213p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmsub213s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmaddsub231p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsubadd231p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmadd231p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmadd231s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsub231p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfmsub231s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmadd231p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmadd231s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmsub231p%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfnmsub231s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpconflict%LW", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vgatherpf0dp%XW", { { OP_M, vex_vsib_d_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vgatherpf1dp%XW", { { OP_M, vex_vsib_d_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vscatterpf0dp%XW", { { OP_M, vex_vsib_d_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vscatterpf1dp%XW", { { OP_M, vex_vsib_d_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F38C7_R_1_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F38C7_R_2_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F38C7_R_5_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F38C7_R_6_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vexp2p%XW",
     { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vrcp28p%XW",
     { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vrcp28s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vrsqrt28p%XW",
     { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vrsqrt28s%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A00_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A01_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "valign%LW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A04_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A05_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A08_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A09_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A0A_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A0B_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vextractps",
     { { OP_E, dqd_mode }, { OP_XMM, xmm_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A18_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A19_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A1A_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A1B_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A1D_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpcmpu%LW",
     { { OP_Mask, mask_mode },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { VPCMP_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpcmp%LW",
     { { OP_Mask, mask_mode },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { VPCMP_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A21_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A23_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpternlog%LW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vgetmantp%XW",
     { { OP_XMM, 0 },
       { OP_EX, x_mode },
       { OP_Rounding, evex_sae_mode },
       { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vgetmants%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_sae_mode },
       { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A38_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A39_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A3A_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A3B_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F3A43_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfixupimmp%XW",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_sae_mode },
       { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vfixupimms%XW",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mdq_mode },
       { OP_Rounding, evex_sae_mode },
       { OP_I, b_mode } } },
  },

};

static const struct dis386 x86_64_table[][2] = {

  {
   { "pushP", { { OP_REG, es_reg } } },
  },

  {
   { "popP", { { OP_REG, es_reg } } },
  },

  {
   { "pushP", { { OP_REG, cs_reg } } },
  },

  {
   { "pushP", { { OP_REG, ss_reg } } },
  },

  {
   { "popP", { { OP_REG, ss_reg } } },
  },

  {
   { "pushP", { { OP_REG, ds_reg } } },
  },

  {
   { "popP", { { OP_REG, ds_reg } } },
  },

  {
   { "daa", { { ((void *)0), 0 } } },
  },

  {
   { "das", { { ((void *)0), 0 } } },
  },

  {
   { "aaa", { { ((void *)0), 0 } } },
  },

  {
   { "aas", { { ((void *)0), 0 } } },
  },

  {
   { "pushaP", { { ((void *)0), 0 } } },
  },

  {
   { "popaP", { { ((void *)0), 0 } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_62_32BIT)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_EVEX_TABLE) }, { ((void *)0), ((EVEX_0F)) } } },
  },

  {
   { "arpl", { { OP_E, w_mode }, { OP_G, w_mode } } },
   { "movs{lq|xd}", { { OP_G, v_mode }, { OP_E, d_mode } } },
  },

  {
   { "ins{R|}", { { REP_Fixup, eDI_reg }, { OP_IMREG, indir_dx_reg } } },
   { "ins{G|}", { { REP_Fixup, eDI_reg }, { OP_IMREG, indir_dx_reg } } },
  },

  {
   { "outs{R|}", { { REP_Fixup, indir_dx_reg }, { OP_DSreg, eSI_reg } } },
   { "outs{G|}", { { REP_Fixup, indir_dx_reg }, { OP_DSreg, eSI_reg } } },
  },

  {
   { "Jcall{T|}", { { OP_DIR, 0 } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_C4_32BIT)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_C4_TABLE) }, { ((void *)0), ((VEX_0F)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_C5_32BIT)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_C5_TABLE) }, { ((void *)0), ((VEX_0F)) } } },
  },

  {
   { "into", { { ((void *)0), 0 } } },
  },

  {
   { "aam", { { OP_I, b_mode } } },
  },

  {
   { "aad", { { OP_I, b_mode } } },
  },

  {
   { "Jjmp{T|}", { { OP_DIR, 0 } } },
  },

  {
   { "sgdt{Q|IQ}", { { OP_M, 0 } } }, { "sgdt", { { OP_M, 0 } } },
  },

  {
   { "sidt{Q|IQ}", { { OP_M, 0 } } }, { "sidt", { { OP_M, 0 } } },
  },

  {
   { "lgdt{Q|Q}", { { OP_M, 0 } } }, { "lgdt", { { OP_M, 0 } } },
  },

  {
   { "lidt{Q|Q}", { { OP_M, 0 } } }, { "lidt", { { OP_M, 0 } } },
  },
};

static const struct dis386 three_byte_table[][256] = {

  {

   { "pshufb", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
   { "phaddw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
   { "phaddd", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
   { "phaddsw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
   { "pmaddubsw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
   { "phsubw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
   { "phsubd", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
   { "phsubsw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },

   { "psignb", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
   { "psignw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
   { "psignd", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
   { "pmulhrsw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3810)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3814)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3815)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3817)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "pabsb", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
   { "pabsw", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
   { "pabsd", { { OP_MMX, 0 }, { OP_EM, v_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3820)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3821)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3822)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3823)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3824)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3825)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3828)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3829)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F382A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F382B)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3830)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3831)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3832)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3833)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3834)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3835)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3837)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3838)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3839)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F383A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F383B)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F383C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F383D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F383E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F383F)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3840)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3841)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3880)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3881)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3882)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F38C8)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F38C9)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F38CA)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F38CB)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F38CC)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F38CD)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F38DB)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F38DC)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F38DD)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F38DE)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F38DF)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F38F0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F38F1)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F38F6)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A08)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A09)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A0A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A0B)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A0C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A0D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A0E)) } } },
   { "palignr", { { OP_MMX, 0 }, { OP_EM, v_mode }, { OP_I, b_mode } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A14)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A15)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A16)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A17)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A20)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A21)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A22)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A40)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A41)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A42)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A44)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A60)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A61)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A62)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3A63)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3ACC)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F3ADF)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { "ptest", { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { "phaddbw", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { "phaddbd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { "phaddbq", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "phaddwd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { "phaddwq", { { OP_XMM, 0 }, { OP_EX, q_mode } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "phadddq", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { "phaddubw", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { "phaddubd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { "phaddubq", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "phadduwd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { "phadduwq", { { OP_XMM, 0 }, { OP_EX, q_mode } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "phaddudq", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { "phsubbw", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { "phsubbd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { "phsubbq", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },
};

static const struct dis386 xop_table[][256] = {

  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpmacssww",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
   { "vpmacsswd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
   { "vpmacssdql",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpmacssdd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
   { "vpmacssdqh",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpmacsww",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
   { "vpmacswd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
   { "vpmacsdql",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpmacsdd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
   { "vpmacsdqh",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpcmov",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
   { "vpperm",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpmadcsswd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpmadcswd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexW, x_mode },
       { OP_EX_VexW, x_mode },
       { VEXI4_Fixup, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { "vprotb", { { OP_XMM, 0 }, { OP_Vex_2src_1, 0 }, { OP_I, b_mode } } },
   { "vprotw", { { OP_XMM, 0 }, { OP_Vex_2src_1, 0 }, { OP_I, b_mode } } },
   { "vprotd", { { OP_XMM, 0 }, { OP_Vex_2src_1, 0 }, { OP_I, b_mode } } },
   { "vprotq", { { OP_XMM, 0 }, { OP_Vex_2src_1, 0 }, { OP_I, b_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FXOP_08_CC)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FXOP_08_CD)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FXOP_08_CE)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FXOP_08_CF)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FXOP_08_EC)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FXOP_08_ED)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FXOP_08_EE)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FXOP_08_EF)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_REG_TABLE) },
       { ((void *)0), ((REG_XOP_TBM_01)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_REG_TABLE) },
       { ((void *)0), ((REG_XOP_TBM_02)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_REG_TABLE) },
       { ((void *)0), ((REG_XOP_LWPCB)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FXOP_09_80)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FXOP_09_81)) } } },
   { "vfrczss", { { OP_XMM, 0 }, { OP_EX, d_mode } } },
   { "vfrczsd", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { "vprotb", { { OP_XMM, 0 }, { OP_Vex_2src_1, 0 }, { OP_Vex_2src_2, 0 } } },
   { "vprotw", { { OP_XMM, 0 }, { OP_Vex_2src_1, 0 }, { OP_Vex_2src_2, 0 } } },
   { "vprotd", { { OP_XMM, 0 }, { OP_Vex_2src_1, 0 }, { OP_Vex_2src_2, 0 } } },
   { "vprotq", { { OP_XMM, 0 }, { OP_Vex_2src_1, 0 }, { OP_Vex_2src_2, 0 } } },
   { "vpshlb", { { OP_XMM, 0 }, { OP_Vex_2src_1, 0 }, { OP_Vex_2src_2, 0 } } },
   { "vpshlw", { { OP_XMM, 0 }, { OP_Vex_2src_1, 0 }, { OP_Vex_2src_2, 0 } } },
   { "vpshld", { { OP_XMM, 0 }, { OP_Vex_2src_1, 0 }, { OP_Vex_2src_2, 0 } } },
   { "vpshlq", { { OP_XMM, 0 }, { OP_Vex_2src_1, 0 }, { OP_Vex_2src_2, 0 } } },

   { "vpshab", { { OP_XMM, 0 }, { OP_Vex_2src_1, 0 }, { OP_Vex_2src_2, 0 } } },
   { "vpshaw", { { OP_XMM, 0 }, { OP_Vex_2src_1, 0 }, { OP_Vex_2src_2, 0 } } },
   { "vpshad", { { OP_XMM, 0 }, { OP_Vex_2src_1, 0 }, { OP_Vex_2src_2, 0 } } },
   { "vpshaq", { { OP_XMM, 0 }, { OP_Vex_2src_1, 0 }, { OP_Vex_2src_2, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { "vphaddbw", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
   { "vphaddbd", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
   { "vphaddbq", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vphaddwd", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
   { "vphaddwq", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vphadddq", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { "vphaddubw", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
   { "vphaddubd", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
   { "vphaddubq", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vphadduwd", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
   { "vphadduwq", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vphaddudq", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { "vphsubbw", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
   { "vphsubwd", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
   { "vphsubdq", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { "bextr", { { OP_G, v_mode }, { OP_E, v_mode }, { OP_I, q_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_XOP_LWP)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },
};

static const struct dis386 vex_table[][256] = {

  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F10)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F11)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F12)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_VEX_0F13)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) }, { ((void *)0), ((VEX_W_0F14)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) }, { ((void *)0), ((VEX_W_0F15)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F16)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_VEX_0F17)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) }, { ((void *)0), ((VEX_W_0F28)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) }, { ((void *)0), ((VEX_W_0F29)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F2A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_VEX_0F2B)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F2C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F2D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F2E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F2F)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F41)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F42)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F44)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F45)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F46)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F47)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F4B)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_MOD_TABLE) }, { ((void *)0), ((MOD_VEX_0F50)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F51)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F52)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F53)) } } },
   { "vandpX", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
   { "vandnpX", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
   { "vorpX", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
   { "vxorpX", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F58)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F59)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F5A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F5B)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F5C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F5D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F5E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F5F)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F60)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F61)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F62)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F63)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F64)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F65)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F66)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F67)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F68)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F69)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F6A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F6B)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F6C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F6D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F6E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F6F)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F70)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_VEX_0F71)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_VEX_0F72)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_VEX_0F73)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F74)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F75)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F76)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F77)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F7C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F7D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F7E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F7F)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F90)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F91)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F92)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F93)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F98)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_REG_TABLE) }, { ((void *)0), ((REG_VEX_0FAE)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FC2)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FC4)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FC5)) } } },
   { "vshufpX",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FD0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FD1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FD2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FD3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FD4)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FD5)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FD6)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FD7)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FD8)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FD9)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FDA)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FDB)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FDC)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FDD)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FDE)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FDF)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FE0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FE1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FE2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FE3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FE4)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FE5)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FE6)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FE7)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FE8)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FE9)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FEA)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FEB)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FEC)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FED)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FEE)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FEF)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FF0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FF1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FF2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FF3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FF4)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FF5)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FF6)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FF7)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FF8)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FF9)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FFA)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FFB)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FFC)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FFD)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0FFE)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3800)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3801)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3802)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3803)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3804)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3805)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3806)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3807)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3808)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3809)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F380A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F380B)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F380C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F380D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F380E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F380F)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3813)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3816)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3817)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3818)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3819)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F381A)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F381C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F381D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F381E)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3820)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3821)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3822)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3823)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3824)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3825)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3828)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3829)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F382A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F382B)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F382C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F382D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F382E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F382F)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3830)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3831)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3832)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3833)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3834)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3835)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3836)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3837)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3838)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3839)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F383A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F383B)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F383C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F383D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F383E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F383F)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3840)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3841)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3845)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3846)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3847)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3858)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3859)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F385A)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3878)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3879)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F388C)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F388E)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3890)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3891)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3892)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3893)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3896)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3897)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3898)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3899)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F389A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F389B)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F389C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F389D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F389E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F389F)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38A6)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38A7)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38A8)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38A9)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38AA)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38AB)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38AC)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38AD)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38AE)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38AF)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38B6)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38B7)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38B8)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38B9)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38BA)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38BB)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38BC)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38BD)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38BE)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38BF)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38DB)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38DC)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38DD)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38DE)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38DF)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38F2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_REG_TABLE) },
       { ((void *)0), ((REG_VEX_0F38F3)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38F5)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38F6)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F38F7)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A00)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A01)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A02)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A04)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A05)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A06)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A08)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A09)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A0A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A0B)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A0C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A0D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A0E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A0F)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A14)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A15)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A16)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A17)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A18)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A19)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A1D)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A20)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A21)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A22)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A30)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A32)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A38)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A39)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A40)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A41)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A42)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A44)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A46)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A48)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A49)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A4A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A4B)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A4C)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A5C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A5D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A5E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A5F)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A60)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A61)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A62)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A63)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A68)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A69)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A6A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A6B)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A6C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A6D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A6E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A6F)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A78)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A79)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A7A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A7B)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A7C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A7D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A7E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3A7F)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3ADF)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F3AF0)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },
};

static const struct dis386 evex_table[][256] = {

  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F10)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F11)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F12)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F13)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F14)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F15)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F16)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F17)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F28)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F29)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F2A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F2B)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F2C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F2D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F2E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F2F)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F51)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F58)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F59)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F5A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F5B)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F5C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F5D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F5E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F5F)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F62)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F66)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F6A)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F6C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F6D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F6E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F6F)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F70)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_REG_TABLE) },
       { ((void *)0), ((REG_EVEX_0F72)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_REG_TABLE) },
       { ((void *)0), ((REG_EVEX_0F73)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F76)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F78)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F79)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F7A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F7B)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F7E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F7F)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FC2)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FC6)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FD2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FD3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FD4)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FD6)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FDB)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FDF)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FE2)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FE6)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FE7)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FEB)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FEF)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FF2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FF3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FF4)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FFA)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FFB)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0FFE)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F380C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F380D)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3811)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3812)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3813)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3814)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3815)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3816)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3818)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3819)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F381A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F381B)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F381E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F381F)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3821)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3822)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3823)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3824)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3825)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3827)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3828)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3829)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F382A)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F382C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F382D)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3831)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3832)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3833)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3834)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3835)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3836)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3837)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3839)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F383A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F383B)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F383D)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F383F)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3840)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3842)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3843)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3844)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3845)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3846)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3847)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F384C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F384D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F384E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F384F)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3858)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3859)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F385A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F385B)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3864)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3865)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3876)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3877)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F387C)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F387E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F387F)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3888)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3889)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F388A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F388B)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3890)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3891)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3892)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3893)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3896)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3897)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3898)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3899)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F389A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F389B)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F389C)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F389D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F389E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F389F)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38A0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38A1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38A2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38A3)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38A6)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38A7)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38A8)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38A9)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38AA)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38AB)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38AC)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38AD)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38AE)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38AF)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38B6)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38B7)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38B8)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38B9)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38BA)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38BB)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38BC)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38BD)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38BE)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38BF)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38C4)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_REG_TABLE) },
       { ((void *)0), ((REG_EVEX_0F38C6)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_REG_TABLE) },
       { ((void *)0), ((REG_EVEX_0F38C7)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38C8)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38CA)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38CB)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38CC)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38CD)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A00)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A01)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A03)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A04)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A05)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A08)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A09)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A0A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A0B)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A17)) } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A18)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A19)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A1A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A1B)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A1D)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A1E)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A1F)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A21)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A23)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A25)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A26)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A27)) } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A38)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A39)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A3A)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A3B)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A43)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A54)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F3A55)) } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },
};

static const struct dis386 vex_len_table[][2] = {

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F10_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F10_P_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F10_P_3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F10_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F11_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F11_P_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F11_P_3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F11_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F12_P_0_M_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F12_P_0_M_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F12_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F13_M_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F16_P_0_M_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F16_P_0_M_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F16_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F17_M_0)) } } },
  },

  {
   { "vcvtsi2ss%LQ",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_E, v_mode } } },
   { "vcvtsi2ss%LQ",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_E, v_mode } } },
  },

  {
   { "vcvtsi2sd%LQ",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_E, v_mode } } },
   { "vcvtsi2sd%LQ",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_E, v_mode } } },
  },

  {
   { "vcvttss2siY", { { OP_G, v_mode }, { OP_EX, d_scalar_mode } } },
   { "vcvttss2siY", { { OP_G, v_mode }, { OP_EX, d_scalar_mode } } },
  },

  {
   { "vcvttsd2siY", { { OP_G, v_mode }, { OP_EX, q_scalar_mode } } },
   { "vcvttsd2siY", { { OP_G, v_mode }, { OP_EX, q_scalar_mode } } },
  },

  {
   { "vcvtss2siY", { { OP_G, v_mode }, { OP_EX, d_scalar_mode } } },
   { "vcvtss2siY", { { OP_G, v_mode }, { OP_EX, d_scalar_mode } } },
  },

  {
   { "vcvtsd2siY", { { OP_G, v_mode }, { OP_EX, q_scalar_mode } } },
   { "vcvtsd2siY", { { OP_G, v_mode }, { OP_EX, q_scalar_mode } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F2E_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F2E_P_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F2E_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F2E_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F2F_P_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F2F_P_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F2F_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F2F_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F41_P_0_LEN_1)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F42_P_0_LEN_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F44_P_0_LEN_0)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F45_P_0_LEN_1)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F46_P_0_LEN_1)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F47_P_0_LEN_1)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F4B_P_2_LEN_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F51_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F51_P_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F51_P_3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F51_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F52_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F52_P_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F53_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F53_P_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F58_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F58_P_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F58_P_3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F58_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F59_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F59_P_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F59_P_3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F59_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5A_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5A_P_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5A_P_3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5A_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5C_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5C_P_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5C_P_3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5C_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5D_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5D_P_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5D_P_3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5D_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5E_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5E_P_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5E_P_3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5E_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5F_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5F_P_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5F_P_3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F5F_P_3)) } } },
  },

  {
   { "vmovK", { { OP_XMM, scalar_mode }, { OP_E, dq_mode } } },
   { "vmovK", { { OP_XMM, scalar_mode }, { OP_E, dq_mode } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F7E_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F7E_P_1)) } } },
  },

  {
   { "vmovK", { { OP_E, dq_mode }, { OP_XMM, scalar_mode } } },
   { "vmovK", { { OP_E, dq_mode }, { OP_XMM, scalar_mode } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F90_P_0_LEN_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F91_P_0_LEN_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F92_P_0_LEN_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F93_P_0_LEN_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F98_P_0_LEN_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FAE_R_2_M_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FAE_R_3_M_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FC2_P_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FC2_P_1)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FC2_P_3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FC2_P_3)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FC4_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FC5_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FD6_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FD6_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FF7_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3816_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3819_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F381A_P_2_M_0)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3836_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3841_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F385A_P_2_M_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F38DB_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F38DC_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F38DD_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F38DE_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F38DF_P_2)) } } },
  },

  {
   { "andnS", { { OP_G, dq_mode }, { OP_VEX, dq_mode }, { OP_E, dq_mode } } },
  },

  {
   { "blsrS", { { OP_VEX, dq_mode }, { OP_E, dq_mode } } },
  },

  {
   { "blsmskS", { { OP_VEX, dq_mode }, { OP_E, dq_mode } } },
  },

  {
   { "blsiS", { { OP_VEX, dq_mode }, { OP_E, dq_mode } } },
  },

  {
   { "bzhiS", { { OP_G, dq_mode }, { OP_E, dq_mode }, { OP_VEX, dq_mode } } },
  },

  {
   { "pextS", { { OP_G, dq_mode }, { OP_VEX, dq_mode }, { OP_E, dq_mode } } },
  },

  {
   { "pdepS", { { OP_G, dq_mode }, { OP_VEX, dq_mode }, { OP_E, dq_mode } } },
  },

  {
   { "mulxS", { { OP_G, dq_mode }, { OP_VEX, dq_mode }, { OP_E, dq_mode } } },
  },

  {
   { "bextrS", { { OP_G, dq_mode }, { OP_E, dq_mode }, { OP_VEX, dq_mode } } },
  },

  {
   { "sarxS", { { OP_G, dq_mode }, { OP_E, dq_mode }, { OP_VEX, dq_mode } } },
  },

  {
   { "shlxS", { { OP_G, dq_mode }, { OP_E, dq_mode }, { OP_VEX, dq_mode } } },
  },

  {
   { "shrxS", { { OP_G, dq_mode }, { OP_E, dq_mode }, { OP_VEX, dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A00_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A01_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A06_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A0A_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A0A_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A0B_P_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A0B_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A14_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A15_P_2)) } } },
  },

  {
   { "vpextrK", { { OP_E, dq_mode }, { OP_XMM, 0 }, { OP_I, b_mode } } },
  },

  {
   { "vextractps", { { OP_E, dqd_mode }, { OP_XMM, 0 }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A18_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A19_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A20_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A21_P_2)) } } },
  },

  {
   { "vpinsrK",
     { { OP_XMM, 0 },
       { OP_VEX, vex128_mode },
       { OP_E, dq_mode },
       { OP_I, b_mode } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A30_P_2_LEN_0)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A32_P_2_LEN_0)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A38_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A39_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A41_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A44_P_2)) } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A46_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A60_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A61_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A62_P_2)) } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3A63_P_2)) } } },
  },

  {
   { "vfmaddss",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX_VexW, d_mode },
       { OP_EX_VexW, d_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { "vfmaddsd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX_VexW, q_mode },
       { OP_EX_VexW, q_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { "vfmsubss",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX_VexW, d_mode },
       { OP_EX_VexW, d_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { "vfmsubsd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX_VexW, q_mode },
       { OP_EX_VexW, q_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { "vfnmaddss",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX_VexW, d_mode },
       { OP_EX_VexW, d_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { "vfnmaddsd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX_VexW, q_mode },
       { OP_EX_VexW, q_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { "vfnmsubss",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX_VexW, d_mode },
       { OP_EX_VexW, d_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { "vfnmsubsd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX_VexW, q_mode },
       { OP_EX_VexW, q_mode },
       { VEXI4_Fixup, 0 } } },
  },

  {
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F3ADF_P_2)) } } },
  },

  {
   { "rorxS", { { OP_G, dq_mode }, { OP_E, dq_mode }, { OP_I, b_mode } } },
  },

  {
   { "vpcomb",
     { { OP_XMM, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vpcomw",
     { { OP_XMM, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vpcomd",
     { { OP_XMM, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vpcomq",
     { { OP_XMM, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vpcomub",
     { { OP_XMM, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vpcomuw",
     { { OP_XMM, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vpcomud",
     { { OP_XMM, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vpcomuq",
     { { OP_XMM, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vfrczps", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
   { "vfrczps", { { OP_XMM, 0 }, { OP_EX, ymmq_mode } } },
  },

  {
   { "vfrczpd", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
   { "vfrczpd", { { OP_XMM, 0 }, { OP_EX, ymmq_mode } } },
  },
};

static const struct dis386 vex_w_table[][2] = {
  {

   { "vmovups", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vmovss",
     { { OP_XMM_Vex, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, d_scalar_mode } } },
  },
  {

   { "vmovupd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vmovsd",
     { { OP_XMM_Vex, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, q_scalar_mode } } },
  },
  {

   { "vmovups", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
  },
  {

   { "vmovss",
     { { OP_EX_Vex, d_scalar_swap_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_XMM, scalar_mode } } },
  },
  {

   { "vmovupd", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
  },
  {

   { "vmovsd",
     { { OP_EX_Vex, q_scalar_swap_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_XMM, scalar_mode } } },
  },
  {

   { "vmovlps",
     { { OP_XMM, 0 }, { OP_VEX, vex128_mode }, { OP_EX, q_mode } } },
  },
  {

   { "vmovhlps",
     { { OP_XMM, 0 }, { OP_VEX, vex128_mode }, { OP_EX, q_mode } } },
  },
  {

   { "vmovsldup", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vmovlpd",
     { { OP_XMM, 0 }, { OP_VEX, vex128_mode }, { OP_EX, q_mode } } },
  },
  {

   { "vmovddup", { { OP_XMM, 0 }, { OP_EX, ymmq_mode } } },
  },
  {

   { "vmovlpX", { { OP_EX, q_mode }, { OP_XMM, 0 } } },
  },
  {

   { "vunpcklpX", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vunpckhpX", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vmovhps",
     { { OP_XMM, 0 }, { OP_VEX, vex128_mode }, { OP_EX, q_mode } } },
  },
  {

   { "vmovlhps",
     { { OP_XMM, 0 }, { OP_VEX, vex128_mode }, { OP_EX, q_mode } } },
  },
  {

   { "vmovshdup", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vmovhpd",
     { { OP_XMM, 0 }, { OP_VEX, vex128_mode }, { OP_EX, q_mode } } },
  },
  {

   { "vmovhpX", { { OP_EX, q_mode }, { OP_XMM, 0 } } },
  },
  {

   { "vmovapX", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vmovapX", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
  },
  {

   { "vmovntpX", { { OP_M, x_mode }, { OP_XMM, 0 } } },
  },
  {

   { "vucomiss", { { OP_XMM, scalar_mode }, { OP_EX, d_scalar_mode } } },
  },
  {

   { "vucomisd", { { OP_XMM, scalar_mode }, { OP_EX, q_scalar_mode } } },
  },
  {

   { "vcomiss", { { OP_XMM, scalar_mode }, { OP_EX, d_scalar_mode } } },
  },
  {

   { "vcomisd", { { OP_XMM, scalar_mode }, { OP_EX, q_scalar_mode } } },
  },
  {

   { "kandw",
     { { OP_G, mask_mode }, { OP_VEX, mask_mode }, { OP_R, mask_mode } } },
  },
  {

   { "kandnw",
     { { OP_G, mask_mode }, { OP_VEX, mask_mode }, { OP_R, mask_mode } } },
  },
  {

   { "knotw", { { OP_G, mask_mode }, { OP_R, mask_mode } } },
  },
  {

   { "korw",
     { { OP_G, mask_mode }, { OP_VEX, mask_mode }, { OP_R, mask_mode } } },
  },
  {

   { "kxnorw",
     { { OP_G, mask_mode }, { OP_VEX, mask_mode }, { OP_R, mask_mode } } },
  },
  {

   { "kxorw",
     { { OP_G, mask_mode }, { OP_VEX, mask_mode }, { OP_R, mask_mode } } },
  },
  {

   { "kunpckbw",
     { { OP_G, mask_mode }, { OP_VEX, mask_mode }, { OP_R, mask_mode } } },
  },
  {

   { "vmovmskpX", { { OP_G, dq_mode }, { OP_XS, v_mode } } },
  },
  {

   { "vsqrtps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vsqrtss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, d_scalar_mode } } },
  },
  {

   { "vsqrtpd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vsqrtsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, q_scalar_mode } } },
  },
  {

   { "vrsqrtps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vrsqrtss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, d_scalar_mode } } },
  },
  {

   { "vrcpps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vrcpss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, d_scalar_mode } } },
  },
  {

   { "vaddps", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vaddss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, d_scalar_mode } } },
  },
  {

   { "vaddpd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vaddsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, q_scalar_mode } } },
  },
  {

   { "vmulps", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vmulss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, d_scalar_mode } } },
  },
  {

   { "vmulpd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vmulsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, q_scalar_mode } } },
  },
  {

   { "vcvtps2pd", { { OP_XMM, 0 }, { OP_EX, xmmq_mode } } },
  },
  {

   { "vcvtss2sd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, d_scalar_mode } } },
  },
  {

   { "vcvtsd2ss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, q_scalar_mode } } },
  },
  {

   { "vcvtdq2ps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vcvttps2dq", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vcvtps2dq", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vsubps", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vsubss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, d_scalar_mode } } },
  },
  {

   { "vsubpd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vsubsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, q_scalar_mode } } },
  },
  {

   { "vminps", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vminss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, d_scalar_mode } } },
  },
  {

   { "vminpd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vminsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, q_scalar_mode } } },
  },
  {

   { "vdivps", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vdivss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, d_scalar_mode } } },
  },
  {

   { "vdivpd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vdivsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, q_scalar_mode } } },
  },
  {

   { "vmaxps", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vmaxss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, d_scalar_mode } } },
  },
  {

   { "vmaxpd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vmaxsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, q_scalar_mode } } },
  },
  {

   { "vpunpcklbw",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpunpcklwd",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpunpckldq",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpacksswb", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpcmpgtb", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpcmpgtw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpcmpgtd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpackuswb", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpunpckhbw",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpunpckhwd",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpunpckhdq",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpackssdw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpunpcklqdq",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpunpckhqdq",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vmovdqu", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vmovdqa", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vpshufhw", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpshufd", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpshuflw", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpsrlw", { { OP_VEX, vex_mode }, { OP_XS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpsraw", { { OP_VEX, vex_mode }, { OP_XS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpsllw", { { OP_VEX, vex_mode }, { OP_XS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpsrld", { { OP_VEX, vex_mode }, { OP_XS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpsrad", { { OP_VEX, vex_mode }, { OP_XS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpslld", { { OP_VEX, vex_mode }, { OP_XS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpsrlq", { { OP_VEX, vex_mode }, { OP_XS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpsrldq",
     { { OP_VEX, vex_mode }, { OP_XS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpsllq", { { OP_VEX, vex_mode }, { OP_XS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpslldq",
     { { OP_VEX, vex_mode }, { OP_XS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpcmpeqb", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpcmpeqw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpcmpeqd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "", { { VZERO_Fixup, 0 } } },
  },
  {

   { "vhaddpd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vhaddps", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vhsubpd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vhsubps", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vmovq", { { OP_XMM, scalar_mode }, { OP_EX, q_scalar_mode } } },
  },
  {

   { "vmovdqu", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
  },
  {

   { "vmovdqa", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
  },
  {

   { "kmovw", { { OP_G, mask_mode }, { OP_E, mask_mode } } },
  },
  {

   { "kmovw", { { OP_E, w_mode }, { OP_G, mask_mode } } },
  },
  {

   { "kmovw", { { OP_G, mask_mode }, { OP_R, dq_mode } } },
  },
  {

   { "kmovw", { { OP_G, dq_mode }, { OP_R, mask_mode } } },
  },
  {

   { "kortestw", { { OP_G, mask_mode }, { OP_R, mask_mode } } },
  },
  {

   { "vldmxcsr", { { OP_M, d_mode } } },
  },
  {

   { "vstmxcsr", { { OP_M, d_mode } } },
  },
  {

   { "vcmpps",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { VCMP_Fixup, 0 } } },
  },
  {

   { "vcmpss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, d_scalar_mode },
       { VCMP_Fixup, 0 } } },
  },
  {

   { "vcmppd",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { VCMP_Fixup, 0 } } },
  },
  {

   { "vcmpsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, q_scalar_mode },
       { VCMP_Fixup, 0 } } },
  },
  {

   { "vpinsrw",
     { { OP_XMM, 0 },
       { OP_VEX, vex128_mode },
       { OP_E, dqw_mode },
       { OP_I, b_mode } } },
  },
  {

   { "vpextrw", { { OP_G, dq_mode }, { OP_XS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { "vaddsubpd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vaddsubps", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpsrlw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, xmm_mode } } },
  },
  {

   { "vpsrld", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, xmm_mode } } },
  },
  {

   { "vpsrlq", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, xmm_mode } } },
  },
  {

   { "vpaddq", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpmullw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vmovq", { { OP_EX, q_scalar_swap_mode }, { OP_XMM, scalar_mode } } },
  },
  {

   { "vpmovmskb", { { OP_G, dq_mode }, { OP_XS, v_mode } } },
  },
  {

   { "vpsubusb", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpsubusw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpminub", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpand", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpaddusb", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpaddusw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpmaxub", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpandn", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpavgb", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpsraw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, xmm_mode } } },
  },
  {

   { "vpsrad", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, xmm_mode } } },
  },
  {

   { "vpavgw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpmulhuw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpmulhw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vcvtdq2pd", { { OP_XMM, 0 }, { OP_EX, xmmq_mode } } },
  },
  {

   { "vcvttpd2dq%XY", { { OP_XMM, xmm_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vcvtpd2dq%XY", { { OP_XMM, xmm_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vmovntdq", { { OP_M, x_mode }, { OP_XMM, 0 } } },
  },
  {

   { "vpsubsb", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpsubsw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpminsw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpor", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpaddsb", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpaddsw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpmaxsw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpxor", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vlddqu", { { OP_XMM, 0 }, { OP_M, 0 } } },
  },
  {

   { "vpsllw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, xmm_mode } } },
  },
  {

   { "vpslld", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, xmm_mode } } },
  },
  {

   { "vpsllq", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, xmm_mode } } },
  },
  {

   { "vpmuludq", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpmaddwd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpsadbw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vmaskmovdqu", { { OP_XMM, 0 }, { OP_XS, v_mode } } },
  },
  {

   { "vpsubb", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpsubw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpsubd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpsubq", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpaddb", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpaddw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpaddd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpshufb", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vphaddw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vphaddd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vphaddsw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpmaddubsw",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vphsubw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vphsubd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vphsubsw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpsignb", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpsignw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpsignd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpmulhrsw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpermilps", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpermilpd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vtestps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vtestpd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vpermps", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vptest", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vbroadcastss", { { OP_XMM, 0 }, { OP_EX, xmm_md_mode } } },
  },
  {

   { "vbroadcastsd", { { OP_XMM, 0 }, { OP_EX, xmm_mq_mode } } },
  },
  {

   { "vbroadcastf128", { { OP_XMM, 0 }, { OP_M, xmm_mode } } },
  },
  {

   { "vpabsb", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vpabsw", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vpabsd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vpmovsxbw", { { OP_XMM, 0 }, { OP_EX, xmmq_mode } } },
  },
  {

   { "vpmovsxbd", { { OP_XMM, 0 }, { OP_EX, xmmqd_mode } } },
  },
  {

   { "vpmovsxbq", { { OP_XMM, 0 }, { OP_EX, xmmdw_mode } } },
  },
  {

   { "vpmovsxwd", { { OP_XMM, 0 }, { OP_EX, xmmq_mode } } },
  },
  {

   { "vpmovsxwq", { { OP_XMM, 0 }, { OP_EX, xmmqd_mode } } },
  },
  {

   { "vpmovsxdq", { { OP_XMM, 0 }, { OP_EX, xmmq_mode } } },
  },
  {

   { "vpmuldq", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpcmpeqq", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vmovntdqa", { { OP_XMM, 0 }, { OP_M, x_mode } } },
  },
  {

   { "vpackusdw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vmaskmovps", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_M, x_mode } } },
  },
  {

   { "vmaskmovpd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_M, x_mode } } },
  },
  {

   { "vmaskmovps", { { OP_M, x_mode }, { OP_VEX, vex_mode }, { OP_XMM, 0 } } },
  },
  {

   { "vmaskmovpd", { { OP_M, x_mode }, { OP_VEX, vex_mode }, { OP_XMM, 0 } } },
  },
  {

   { "vpmovzxbw", { { OP_XMM, 0 }, { OP_EX, xmmq_mode } } },
  },
  {

   { "vpmovzxbd", { { OP_XMM, 0 }, { OP_EX, xmmqd_mode } } },
  },
  {

   { "vpmovzxbq", { { OP_XMM, 0 }, { OP_EX, xmmdw_mode } } },
  },
  {

   { "vpmovzxwd", { { OP_XMM, 0 }, { OP_EX, xmmq_mode } } },
  },
  {

   { "vpmovzxwq", { { OP_XMM, 0 }, { OP_EX, xmmqd_mode } } },
  },
  {

   { "vpmovzxdq", { { OP_XMM, 0 }, { OP_EX, xmmq_mode } } },
  },
  {

   { "vpermd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpcmpgtq", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpminsb", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpminsd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpminuw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpminud", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpmaxsb", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpmaxsd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpmaxuw", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpmaxud", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpmulld", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vphminposuw", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vpsravd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vpbroadcastd", { { OP_XMM, 0 }, { OP_EX, xmm_md_mode } } },
  },
  {

   { "vpbroadcastq", { { OP_XMM, 0 }, { OP_EX, xmm_mq_mode } } },
  },
  {

   { "vbroadcasti128", { { OP_XMM, 0 }, { OP_M, xmm_mode } } },
  },
  {

   { "vpbroadcastb", { { OP_XMM, 0 }, { OP_EX, xmm_mb_mode } } },
  },
  {

   { "vpbroadcastw", { { OP_XMM, 0 }, { OP_EX, xmm_mw_mode } } },
  },
  {

   { "vaesimc", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },
  {

   { "vaesenc",
     { { OP_XMM, 0 }, { OP_VEX, vex128_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vaesenclast",
     { { OP_XMM, 0 }, { OP_VEX, vex128_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vaesdec",
     { { OP_XMM, 0 }, { OP_VEX, vex128_mode }, { OP_EX, x_mode } } },
  },
  {

   { "vaesdeclast",
     { { OP_XMM, 0 }, { OP_VEX, vex128_mode }, { OP_EX, x_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpermq", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpermpd", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpblendd",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },
  {

   { "vpermilps", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpermilpd", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },
  {

   { "vperm2f128",
     { { OP_XMM, 0 },
       { OP_VEX, vex256_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },
  {

   { "vroundps", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },
  {

   { "vroundpd", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },
  {

   { "vroundss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, d_scalar_mode },
       { OP_I, b_mode } } },
  },
  {

   { "vroundsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, q_scalar_mode },
       { OP_I, b_mode } } },
  },
  {

   { "vblendps",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },
  {

   { "vblendpd",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },
  {

   { "vpblendw",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },
  {

   { "vpalignr",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },
  {

   { "vpextrb", { { OP_E, dqb_mode }, { OP_XMM, 0 }, { OP_I, b_mode } } },
  },
  {

   { "vpextrw", { { OP_E, dqw_mode }, { OP_XMM, 0 }, { OP_I, b_mode } } },
  },
  {

   { "vinsertf128",
     { { OP_XMM, 0 },
       { OP_VEX, vex256_mode },
       { OP_EX, xmm_mode },
       { OP_I, b_mode } } },
  },
  {

   { "vextractf128",
     { { OP_EX, xmm_mode }, { OP_XMM, 0 }, { OP_I, b_mode } } },
  },
  {

   { "vpinsrb",
     { { OP_XMM, 0 },
       { OP_VEX, vex128_mode },
       { OP_E, dqb_mode },
       { OP_I, b_mode } } },
  },
  {

   { "vinsertps",
     { { OP_XMM, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX, d_mode },
       { OP_I, b_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "kshiftrw",
     { { OP_G, mask_mode }, { OP_R, mask_mode }, { OP_I, b_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "kshiftlw",
     { { OP_G, mask_mode }, { OP_R, mask_mode }, { OP_I, b_mode } } },
  },
  {

   { "vinserti128",
     { { OP_XMM, 0 },
       { OP_VEX, vex256_mode },
       { OP_EX, xmm_mode },
       { OP_I, b_mode } } },
  },
  {

   { "vextracti128",
     { { OP_EX, xmm_mode }, { OP_XMM, 0 }, { OP_I, b_mode } } },
  },
  {

   { "vdpps",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },
  {

   { "vdppd",
     { { OP_XMM, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },
  {

   { "vmpsadbw",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },
  {

   { "vpclmulqdq",
     { { OP_XMM, 0 },
       { OP_VEX, vex128_mode },
       { OP_EX, x_mode },
       { PCLMUL_Fixup, 0 } } },
  },
  {

   { "vperm2i128",
     { { OP_XMM, 0 },
       { OP_VEX, vex256_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },
  {

   { "vpermil2ps",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexImmW, x_mode },
       { OP_EX_VexImmW, x_mode },
       { OP_EX_VexImmW, x_mode } } },
   { "vpermil2ps",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexImmW, x_mode },
       { OP_EX_VexImmW, x_mode },
       { OP_EX_VexImmW, x_mode } } },
  },
  {

   { "vpermil2pd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexImmW, x_mode },
       { OP_EX_VexImmW, x_mode },
       { OP_EX_VexImmW, x_mode } } },
   { "vpermil2pd",
     { { OP_XMM_VexW, 0 },
       { OP_VEX, vex_mode },
       { OP_EX_VexImmW, x_mode },
       { OP_EX_VexImmW, x_mode },
       { OP_EX_VexImmW, x_mode } } },
  },
  {

   { "vblendvps",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_REG_VexI4, x_mode } } },
  },
  {

   { "vblendvpd",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_REG_VexI4, x_mode } } },
  },
  {

   { "vpblendvb",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_REG_VexI4, x_mode } } },
  },
  {

   { "vpcmpestrm", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpcmpestri", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpcmpistrm", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },
  {

   { "vpcmpistri", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },
  {

   { "vaeskeygenassist",
     { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { "vmovups", { { OP_XMM, 0 }, { OP_EX, evex_x_nobcst_mode } } },
  },

  {
   { "vmovss", { { OP_XMM, scalar_mode }, { OP_EX, d_scalar_mode } } },
  },

  {
   { "vmovss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmovupd", { { OP_XMM, 0 }, { OP_EX, evex_x_nobcst_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmovsd", { { OP_XMM, scalar_mode }, { OP_EX, q_scalar_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmovsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, x_mode } } },
  },

  {
   { "vmovups", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vmovss", { { OP_EX, d_scalar_swap_mode }, { OP_XMM, scalar_mode } } },
  },

  {
   { "vmovss",
     { { OP_EX, x_swap_mode },
       { OP_VEX, vex_mode },
       { OP_XMM, scalar_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmovupd", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmovsd", { { OP_EX, q_scalar_swap_mode }, { OP_XMM, scalar_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmovsd",
     { { OP_EX, x_swap_mode },
       { OP_VEX, vex_mode },
       { OP_XMM, scalar_mode } } },
  },

  {
   { "vmovlps",
     { { OP_XMM, xmm_mode }, { OP_VEX, vex_mode }, { OP_EX, xmm_mq_mode } } },
  },

  {
   { "vmovhlps",
     { { OP_XMM, xmm_mode }, { OP_VEX, vex_mode }, { OP_EX, xmm_mq_mode } } },
  },

  {
   { "vmovsldup", { { OP_XMM, 0 }, { OP_EX, evex_x_nobcst_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmovlpd",
     { { OP_XMM, xmm_mode }, { OP_VEX, vex_mode }, { OP_EX, xmm_mq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmovddup", { { OP_XMM, 0 }, { OP_EX, ymmq_mode } } },
  },

  {
   { "vmovlps", { { OP_EX, xmm_mq_mode }, { OP_XMM, xmm_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmovlpd", { { OP_EX, xmm_mq_mode }, { OP_XMM, xmm_mode } } },
  },

  {
   { "vunpcklps", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vunpcklpd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { "vunpckhps", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vunpckhpd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { "vmovhps",
     { { OP_XMM, xmm_mode }, { OP_VEX, vex_mode }, { OP_EX, xmm_mq_mode } } },
  },

  {
   { "vmovlhps",
     { { OP_XMM, xmm_mode }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { "vmovshdup", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmovhpd",
     { { OP_XMM, xmm_mode }, { OP_VEX, vex_mode }, { OP_EX, xmm_mq_mode } } },
  },

  {
   { "vmovhps", { { OP_EX, xmm_mq_mode }, { OP_XMM, xmm_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmovhpd", { { OP_EX, xmm_mq_mode }, { OP_XMM, xmm_mode } } },
  },

  {
   { "vmovaps", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmovapd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { "vmovaps", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmovapd", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vcvtsi2ss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_Rounding, evex_rounding_mode },
       { OP_E, d_mode } } },
   { "vcvtsi2ss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_Rounding, evex_rounding_mode },
       { OP_E, q_mode } } },
  },

  {
   { "vcvtsi2sd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_E, d_mode } } },
   { "vcvtsi2sd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_Rounding, evex_rounding_mode },
       { OP_E, q_mode } } },
  },

  {
   { "vmovntps", { { OP_EX, x_mode }, { OP_XMM, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmovntpd", { { OP_EX, x_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vucomiss",
     { { OP_XMM, scalar_mode },
       { OP_EX, xmm_md_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vucomisd",
     { { OP_XMM, scalar_mode },
       { OP_EX, xmm_mq_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { "vcomiss",
     { { OP_XMM, scalar_mode },
       { OP_EX, xmm_md_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vcomisd",
     { { OP_XMM, scalar_mode },
       { OP_EX, xmm_mq_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { "vsqrtps",
     { { OP_XMM, 0 },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { "vsqrtss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_md_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vsqrtpd",
     { { OP_XMM, 0 },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vsqrtsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { "vaddps",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { "vaddss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_md_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vaddpd",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vaddsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { "vmulps",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { "vmulss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_md_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmulpd",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmulsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { "vcvtps2pd",
     { { OP_XMM, 0 },
       { OP_EX, evex_half_bcst_xmmq_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { "vcvtss2sd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_md_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vcvtpd2ps",
     { { OP_XMM, xmmq_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vcvtsd2ss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { "vcvtdq2ps",
     { { OP_XMM, 0 },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { "vcvttps2dq",
     { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_Rounding, evex_sae_mode } } },
  },

  {
   { "vcvtps2dq",
     { { OP_XMM, 0 },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { "vsubps",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { "vsubss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_md_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vsubpd",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vsubsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { "vminps",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { "vminss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_md_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vminpd",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vminsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mq_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { "vdivps",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { "vdivss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_md_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vdivpd",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vdivsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mq_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { "vmaxps",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { "vmaxss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_md_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmaxpd",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmaxsd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mq_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { "vpunpckldq",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { "vpcmpgtd",
     { { OP_Mask, mask_mode }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { "vpunpckhdq",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpunpcklqdq",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpunpckhqdq",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { "vmovd", { { OP_XMM, scalar_mode }, { OP_E, d_mode } } },
   { "vmovq", { { OP_XMM, scalar_mode }, { OP_E, q_mode } } },
  },

  {
   { "vmovdqu32", { { OP_XMM, 0 }, { OP_EX, evex_x_nobcst_mode } } },
   { "vmovdqu64", { { OP_XMM, 0 }, { OP_EX, evex_x_nobcst_mode } } },
  },

  {
   { "vmovdqa32", { { OP_XMM, 0 }, { OP_EX, evex_x_nobcst_mode } } },
   { "vmovdqa64", { { OP_XMM, 0 }, { OP_EX, evex_x_nobcst_mode } } },
  },

  {
   { "vpshufd", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { "vpsrld", { { OP_VEX, vex_mode }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { "vpslld", { { OP_VEX, vex_mode }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpsrlq", { { OP_VEX, vex_mode }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpsllq", { { OP_VEX, vex_mode }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { "vpcmpeqd",
     { { OP_Mask, mask_mode }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { "vcvttps2udq",
     { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_Rounding, evex_sae_mode } } },
   { "vcvttpd2udq",
     { { OP_XMM, xmmq_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { "vcvtps2udq",
     { { OP_XMM, 0 },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
   { "vcvtpd2udq",
     { { OP_XMM, xmmq_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { "vcvtudq2pd", { { OP_XMM, 0 }, { OP_EX, evex_half_bcst_xmmq_mode } } },
  },

  {
   { "vcvtudq2ps",
     { { OP_XMM, 0 },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { "vcvtusi2ss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_Rounding, evex_rounding_mode },
       { OP_E, d_mode } } },
   { "vcvtusi2ss",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_Rounding, evex_rounding_mode },
       { OP_E, q_mode } } },
  },

  {
   { "vcvtusi2sd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_E, d_mode } } },
   { "vcvtusi2sd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_Rounding, evex_rounding_mode },
       { OP_E, q_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmovq", { { OP_XMM, scalar_mode }, { OP_EX, xmm_mq_mode } } },
  },

  {
   { "vmovd", { { OP_E, d_mode }, { OP_XMM, scalar_mode } } },
   { "vmovq", { { OP_E, q_mode }, { OP_XMM, scalar_mode } } },
  },

  {
   { "vmovdqu32", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
   { "vmovdqu64", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vmovdqa32", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
   { "vmovdqa64", { { OP_EX, x_swap_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vcmpps",
     { { OP_Mask, mask_mode },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_sae_mode },
       { VCMP_Fixup, 0 } } },
  },

  {
   { "vcmpss",
     { { OP_Mask, mask_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_md_mode },
       { OP_Rounding, evex_sae_mode },
       { VCMP_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vcmppd",
     { { OP_Mask, mask_mode },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_sae_mode },
       { VCMP_Fixup, 0 } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vcmpsd",
     { { OP_Mask, mask_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mq_mode },
       { OP_Rounding, evex_sae_mode },
       { VCMP_Fixup, 0 } } },
  },

  {
   { "vshufps",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vshufpd",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vpsrld", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, xmm_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpsrlq", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, xmm_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpaddq", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmovq", { { OP_EX, xmm_mq_mode }, { OP_XMM, scalar_mode } } },
  },

  {
   { "vcvtdq2pd", { { OP_XMM, 0 }, { OP_EX, evex_half_bcst_xmmq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vcvttpd2dq",
     { { OP_XMM, xmmq_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_sae_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vcvtpd2dq",
     { { OP_XMM, xmmq_mode },
       { OP_EX, x_mode },
       { OP_Rounding, evex_rounding_mode } } },
  },

  {
   { "vmovntdq", { { OP_EX, evex_x_nobcst_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vpslld", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, xmm_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpsllq", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, xmm_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpmuludq", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { "vpsubd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpsubq", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { "vpaddd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { "vpermilps", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpermilpd", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { "vpmovusdb", { { OP_EX, xmmqd_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vpmovusqb", { { OP_EX, xmmdw_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vpmovusdw", { { OP_EX, xmmq_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vcvtph2ps",
     { { OP_XMM, 0 }, { OP_EX, xmmq_mode }, { OP_Rounding, evex_sae_mode } } },
  },

  {
   { "vpmovusqw", { { OP_EX, xmmqd_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vpmovusqd", { { OP_EX, xmmq_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vbroadcastss", { { OP_XMM, 0 }, { OP_EX, xmm_md_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vbroadcastsd", { { OP_XMM, 0 }, { OP_EX, xmm_mq_mode } } },
  },

  {
   { "vbroadcastf32x4", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vbroadcastf64x4", { { OP_XMM, 0 }, { OP_EX, ymm_mode } } },
  },

  {
   { "vpabsd", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpabsq", { { OP_XMM, 0 }, { OP_EX, x_mode } } },
  },

  {
   { "vpmovsdb", { { OP_EX, xmmqd_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vpmovsqb", { { OP_EX, xmmdw_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vpmovsdw", { { OP_EX, xmmq_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vpmovsqw", { { OP_EX, xmmqd_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vpmovsqd", { { OP_EX, xmmq_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vpmovsxdq", { { OP_XMM, 0 }, { OP_EX, xmmq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpmuldq", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpcmpeqq",
     { { OP_Mask, mask_mode }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpbroadcastmb2q", { { OP_XMM, 0 }, { OP_R, mask_mode } } },
  },

  {
   { "vmovntdqa", { { OP_XMM, 0 }, { OP_EX, evex_x_nobcst_mode } } },
  },

  {
   { "vpmovdb", { { OP_EX, xmmqd_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vpmovqb", { { OP_EX, xmmdw_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vpmovdw", { { OP_EX, xmmq_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vpmovqw", { { OP_EX, xmmqd_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vpmovqd", { { OP_EX, xmmq_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vpmovzxdq", { { OP_XMM, 0 }, { OP_EX, xmmq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpcmpgtq",
     { { OP_Mask, mask_mode }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { "vpbroadcastmw2d", { { OP_XMM, 0 }, { OP_R, mask_mode } } },
  },

  {
   { "vpmulld", { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_EX, x_mode } } },
  },

  {
   { "vpbroadcastd", { { OP_XMM, 0 }, { OP_EX, xmm_md_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpbroadcastq", { { OP_XMM, 0 }, { OP_EX, xmm_mq_mode } } },
  },

  {
   { "vbroadcasti32x4", { { OP_XMM, 0 }, { OP_EX, xmm_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vbroadcasti64x4", { { OP_XMM, 0 }, { OP_EX, ymm_mode } } },
  },

  {
   { "vpgatherqd", { { OP_XMM, xmmq_mode }, { OP_M, vex_vsib_q_w_d_mode } } },
   { "vpgatherqq", { { OP_XMM, 0 }, { OP_M, vex_vsib_q_w_dq_mode } } },
  },

  {
   { "vgatherqps", { { OP_XMM, xmmq_mode }, { OP_M, vex_vsib_q_w_d_mode } } },
   { "vgatherqpd", { { OP_XMM, 0 }, { OP_M, vex_vsib_q_w_dq_mode } } },
  },

  {
   { "vpscatterqd", { { OP_M, vex_vsib_q_w_d_mode }, { OP_XMM, xmmq_mode } } },
   { "vpscatterqq", { { OP_M, vex_vsib_q_w_dq_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vscatterqps", { { OP_M, vex_vsib_q_w_d_mode }, { OP_XMM, xmmq_mode } } },
   { "vscatterqpd", { { OP_M, vex_vsib_q_w_dq_mode }, { OP_XMM, 0 } } },
  },

  {
   { "vgatherpf0qps", { { OP_M, vex_vsib_d_w_d_mode } } },
   { "vgatherpf0qpd", { { OP_M, vex_vsib_q_w_dq_mode } } },
  },

  {
   { "vgatherpf1qps", { { OP_M, vex_vsib_d_w_d_mode } } },
   { "vgatherpf1qpd", { { OP_M, vex_vsib_q_w_dq_mode } } },
  },

  {
   { "vscatterpf0qps", { { OP_M, vex_vsib_d_w_d_mode } } },
   { "vscatterpf0qpd", { { OP_M, vex_vsib_q_w_dq_mode } } },
  },

  {
   { "vscatterpf1qps", { { OP_M, vex_vsib_d_w_d_mode } } },
   { "vscatterpf1qpd", { { OP_M, vex_vsib_q_w_dq_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpermq", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpermpd", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { "vpermilps", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vpermilpd", { { OP_XMM, 0 }, { OP_EX, x_mode }, { OP_I, b_mode } } },
  },

  {
   { "vrndscaleps",
     { { OP_XMM, 0 },
       { OP_EX, x_mode },
       { OP_Rounding, evex_sae_mode },
       { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vrndscalepd",
     { { OP_XMM, 0 },
       { OP_EX, x_mode },
       { OP_Rounding, evex_sae_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vrndscaless",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_md_mode },
       { OP_Rounding, evex_sae_mode },
       { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vrndscalesd",
     { { OP_XMM, scalar_mode },
       { OP_VEX, vex_scalar_mode },
       { OP_EX, xmm_mq_mode },
       { OP_Rounding, evex_sae_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vinsertf32x4",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, xmm_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vextractf32x4",
     { { OP_EX, xmm_mode }, { OP_XMM, 0 }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vinsertf64x4",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, xmmq_mode },
       { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vextractf64x4",
     { { OP_EX, xmmq_mode }, { OP_XMM, 0 }, { OP_I, b_mode } } },
  },

  {
   { "vcvtps2ph",
     { { OP_EX, xmmq_mode },
       { OP_XMM, 0 },
       { OP_Rounding, evex_sae_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vinsertps",
     { { OP_XMM, xmm_mode },
       { OP_VEX, vex_mode },
       { OP_EX, xmm_md_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vshuff32x4",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
   { "vshuff64x2",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vinserti32x4",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, xmm_mode },
       { OP_I, b_mode } } },
  },

  {
   { "vextracti32x4",
     { { OP_EX, xmm_mode }, { OP_XMM, 0 }, { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vinserti64x4",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, xmmq_mode },
       { OP_I, b_mode } } },
  },

  {
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vextracti64x4",
     { { OP_EX, xmmq_mode }, { OP_XMM, 0 }, { OP_I, b_mode } } },
  },

  {
   { "vshufi32x4",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
   { "vshufi64x2",
     { { OP_XMM, 0 },
       { OP_VEX, vex_mode },
       { OP_EX, x_mode },
       { OP_I, b_mode } } },
  },

};

static const struct dis386 mod_table[][2] = {
  {

   { "leaS", { { OP_G, v_mode }, { OP_M, 0 } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_RM_TABLE) }, { ((void *)0), ((RM_C6_REG_7)) } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_RM_TABLE) }, { ((void *)0), ((RM_C7_REG_7)) } } },
  },
  {

   { "Jcall{T|}", { { OP_indirE, f_mode } } },
  },
  {

   { "Jjmp{T|}", { { OP_indirE, f_mode } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_X86_64_TABLE) },
       { ((void *)0), ((X86_64_0F01_REG_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_RM_TABLE) }, { ((void *)0), ((RM_0F01_REG_0)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_X86_64_TABLE) },
       { ((void *)0), ((X86_64_0F01_REG_1)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_RM_TABLE) }, { ((void *)0), ((RM_0F01_REG_1)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_X86_64_TABLE) },
       { ((void *)0), ((X86_64_0F01_REG_2)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_RM_TABLE) }, { ((void *)0), ((RM_0F01_REG_2)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_X86_64_TABLE) },
       { ((void *)0), ((X86_64_0F01_REG_3)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_RM_TABLE) }, { ((void *)0), ((RM_0F01_REG_3)) } } },
  },
  {

   { "invlpg", { { OP_M, b_mode } } },
   { ((void *)0),
     { { ((void *)0), (USE_RM_TABLE) }, { ((void *)0), ((RM_0F01_REG_7)) } } },
  },
  {

   { "movlps", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { "movhlps", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },
  {

   { "movlpX", { { OP_EX, q_mode }, { OP_XMM, 0 } } },
  },
  {

   { "movhps", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
   { "movlhps", { { OP_XMM, 0 }, { OP_EX, q_mode } } },
  },
  {

   { "movhpX", { { OP_EX, q_mode }, { OP_XMM, 0 } } },
  },
  {

   { "prefetchnta", { { OP_M, b_mode } } },
  },
  {

   { "prefetcht0", { { OP_M, b_mode } } },
  },
  {

   { "prefetcht1", { { OP_M, b_mode } } },
  },
  {

   { "prefetcht2", { { OP_M, b_mode } } },
  },
  {

   { "nop/reserved", { { OP_M, b_mode } } },
  },
  {

   { "nop/reserved", { { OP_M, b_mode } } },
  },
  {

   { "nop/reserved", { { OP_M, b_mode } } },
  },
  {

   { "nop/reserved", { { OP_M, b_mode } } },
  },
  {

   { "bndldx", { { OP_G, bnd_mode }, { OP_E, v_bnd_mode } } },
   { "nopQ", { { OP_E, v_mode } } },
  },
  {

   { "bndstx", { { OP_E, v_bnd_mode }, { OP_G, bnd_mode } } },
   { "nopQ", { { OP_E, v_mode } } },
  },
  {

   { "bndmk", { { OP_G, bnd_mode }, { OP_E, v_bnd_mode } } },
   { "nopQ", { { OP_E, v_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "movZ", { { OP_R, m_mode }, { OP_C, m_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "movZ", { { OP_R, m_mode }, { OP_D, m_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "movZ", { { OP_C, m_mode }, { OP_R, m_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "movZ", { { OP_D, m_mode }, { OP_R, m_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "movL", { { OP_R, d_mode }, { OP_T, d_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "movL", { { OP_T, d_mode }, { OP_R, d_mode } } },
  },
  {

   { "movntps", { { OP_M, x_mode }, { OP_XMM, 0 } } },
  },
  {

   { "movntss", { { OP_M, d_mode }, { OP_XMM, 0 } } },
  },
  {

   { "movntpd", { { OP_M, x_mode }, { OP_XMM, 0 } } },
  },
  {

   { "movntsd", { { OP_M, q_mode }, { OP_XMM, 0 } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "movmskpX", { { OP_G, dq_mode }, { OP_XS, v_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "psrlw", { { OP_MS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "psraw", { { OP_MS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "psllw", { { OP_MS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "psrld", { { OP_MS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "psrad", { { OP_MS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "pslld", { { OP_MS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "psrlq", { { OP_MS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F73_REG_3)) } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "psllq", { { OP_MS, v_mode }, { OP_I, b_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0F73_REG_7)) } } },
  },
  {

   { "fxsave", { { FXSAVE_Fixup, 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0FAE_REG_0)) } } },
  },
  {

   { "fxrstor", { { FXSAVE_Fixup, 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0FAE_REG_1)) } } },
  },
  {

   { "ldmxcsr", { { OP_M, d_mode } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0FAE_REG_2)) } } },
  },
  {

   { "stmxcsr", { { OP_M, d_mode } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0FAE_REG_3)) } } },
  },
  {

   { "xsave", { { FXSAVE_Fixup, 0 } } },
  },
  {

   { "xrstor", { { FXSAVE_Fixup, 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_RM_TABLE) }, { ((void *)0), ((RM_0FAE_REG_5)) } } },
  },
  {

   { "xsaveopt", { { FXSAVE_Fixup, 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_RM_TABLE) }, { ((void *)0), ((RM_0FAE_REG_6)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0FAE_REG_7)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_RM_TABLE) }, { ((void *)0), ((RM_0FAE_REG_7)) } } },
  },
  {

   { "lssS", { { OP_G, v_mode }, { OP_M, f_mode } } },
  },
  {

   { "lfsS", { { OP_G, v_mode }, { OP_M, f_mode } } },
  },
  {

   { "lgsS", { { OP_G, v_mode }, { OP_M, f_mode } } },
  },
  {

   { "xrstors", { { FXSAVE_Fixup, 0 } } },
  },
  {

   { "xsavec", { { FXSAVE_Fixup, 0 } } },
  },
  {

   { "xsaves", { { FXSAVE_Fixup, 0 } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_0FC7_REG_6)) } } },
   { "rdrand", { { OP_E, v_mode } } },
  },
  {

   { "vmptrst", { { OP_M, q_mode } } }, { "rdseed", { { OP_E, v_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "pmovmskb", { { OP_G, dq_mode }, { OP_MS, v_mode } } },
  },
  {

   { "movntdq", { { OP_M, x_mode }, { OP_XMM, 0 } } },
  },
  {

   { "lddqu", { { OP_XMM, 0 }, { OP_M, 0 } } },
  },
  {

   { "movntdqa", { { OP_XMM, 0 }, { OP_M, x_mode } } },
  },
  {

   { "bound{S|}", { { OP_G, v_mode }, { OP_M, a_mode } } },
   { ((void *)0),
     { { ((void *)0), (USE_EVEX_TABLE) }, { ((void *)0), ((EVEX_0F)) } } },
  },
  {

   { "lesS", { { OP_G, v_mode }, { OP_M, f_mode } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_C4_TABLE) }, { ((void *)0), ((VEX_0F)) } } },
  },
  {

   { "ldsS", { { OP_G, v_mode }, { OP_M, f_mode } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_C5_TABLE) }, { ((void *)0), ((VEX_0F)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F12_P_0_M_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F12_P_0_M_1)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F13_M_0)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F16_P_0_M_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F16_P_0_M_1)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F17_M_0)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F2B_M_0)) } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F50_M_0)) } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F71_REG_2)) } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F71_REG_4)) } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F71_REG_6)) } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F72_REG_2)) } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F72_REG_4)) } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F72_REG_6)) } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F73_REG_2)) } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F73_REG_3)) } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F73_REG_6)) } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_VEX_0F73_REG_7)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FAE_R_2_M_0)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0FAE_R_3_M_0)) } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FD7_P_2_M_1)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FE7_P_2_M_0)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0FF0_P_3_M_0)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F381A_P_2_M_0)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F382A_P_2_M_0)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F382C_P_2_M_0)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F382D_P_2_M_0)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F382E_P_2_M_0)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((VEX_W_0F382F_P_2_M_0)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_LEN_TABLE) },
       { ((void *)0), ((VEX_LEN_0F385A_P_2_M_0)) } } },
  },
  {

   { "vpmaskmov%LW",
     { { OP_XMM, 0 }, { OP_VEX, vex_mode }, { OP_M, x_mode } } },
  },
  {

   { "vpmaskmov%LW",
     { { OP_M, x_mode }, { OP_VEX, vex_mode }, { OP_XMM, 0 } } },
  },

  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F10_P_1_M_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F10_P_1_M_1)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F10_P_3_M_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F10_P_3_M_1)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F11_P_1_M_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F11_P_1_M_1)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F11_P_3_M_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F11_P_3_M_1)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F12_P_0_M_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F12_P_0_M_1)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F16_P_0_M_0)) } } },
   { ((void *)0),
     { { ((void *)0), (USE_VEX_W_TABLE) },
       { ((void *)0), ((EVEX_W_0F16_P_0_M_1)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38C6_REG_1)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38C6_REG_2)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38C6_REG_5)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38C6_REG_6)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38C7_REG_1)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38C7_REG_2)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38C7_REG_5)) } } },
  },
  {

   { ((void *)0),
     { { ((void *)0), (USE_PREFIX_TABLE) },
       { ((void *)0), ((PREFIX_EVEX_0F38C7_REG_6)) } } },
  },

};

static const struct dis386 rm_table[][8] = {
  {

   { "xabort", { { OP_Skip_MODRM, 0 }, { OP_I, b_mode } } },
  },
  {

   { "xbeginT", { { OP_Skip_MODRM, 0 }, { OP_J, v_mode } } },
  },
  {

   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmcall", { { OP_Skip_MODRM, 0 } } },
   { "vmlaunch", { { OP_Skip_MODRM, 0 } } },
   { "vmresume", { { OP_Skip_MODRM, 0 } } },
   { "vmxoff", { { OP_Skip_MODRM, 0 } } },
  },
  {

   { "monitor", { { OP_Monitor, 0 } } },
   { "mwait", { { OP_Mwait, 0 } } },
   { "clac", { { OP_Skip_MODRM, 0 } } },
   { "stac", { { OP_Skip_MODRM, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "encls", { { OP_Skip_MODRM, 0 } } },
  },
  {

   { "xgetbv", { { OP_Skip_MODRM, 0 } } },
   { "xsetbv", { { OP_Skip_MODRM, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "vmfunc", { { OP_Skip_MODRM, 0 } } },
   { "xend", { { OP_Skip_MODRM, 0 } } },
   { "xtest", { { OP_Skip_MODRM, 0 } } },
   { "enclu", { { OP_Skip_MODRM, 0 } } },
  },
  {

   { "vmrun", { { OP_Skip_MODRM, 0 } } },
   { "vmmcall", { { OP_Skip_MODRM, 0 } } },
   { "vmload", { { OP_Skip_MODRM, 0 } } },
   { "vmsave", { { OP_Skip_MODRM, 0 } } },
   { "stgi", { { OP_Skip_MODRM, 0 } } },
   { "clgi", { { OP_Skip_MODRM, 0 } } },
   { "skinit", { { OP_Skip_MODRM, 0 } } },
   { "invlpga", { { OP_Skip_MODRM, 0 } } },
  },
  {

   { "swapgs", { { OP_Skip_MODRM, 0 } } },
   { "rdtscp", { { OP_Skip_MODRM, 0 } } },
  },
  {

   { "lfence", { { OP_Skip_MODRM, 0 } } },
  },
  {

   { "mfence", { { OP_Skip_MODRM, 0 } } },
  },
  {

   { "sfence", { { OP_Skip_MODRM, 0 } } },
  },
};
static int
ckprefix (void)
{
  int newrex, i, length;
  rex = 0;
  rex_ignored = 0;
  prefixes = 0;
  used_prefixes = 0;
  rex_used = 0;
  last_lock_prefix = -1;
  last_repz_prefix = -1;
  last_repnz_prefix = -1;
  last_data_prefix = -1;
  last_addr_prefix = -1;
  last_rex_prefix = -1;
  last_seg_prefix = -1;
  fwait_prefix = -1;
  active_seg_prefix = 0;
  for (i = 0; i < (int)(sizeof (all_prefixes) / sizeof ((all_prefixes)[0]));
       i++)
    all_prefixes[i] = 0;
  i = 0;
  length = 0;

  while (length < 15 - 1)
    {
      ((codep + 1)
               <= ((struct dis_private *)(the_info->private_data))->max_fetched
           ? 1
           : fetch_data ((the_info), (codep + 1)));
      newrex = 0;
      switch (*codep)
        {

        case 0x40:
        case 0x41:
        case 0x42:
        case 0x43:
        case 0x44:
        case 0x45:
        case 0x46:
        case 0x47:
        case 0x48:
        case 0x49:
        case 0x4a:
        case 0x4b:
        case 0x4c:
        case 0x4d:
        case 0x4e:
        case 0x4f:
          if (address_mode == mode_64bit)
            newrex = *codep;
          else
            return 1;
          last_rex_prefix = i;
          break;
        case 0xf3:
          prefixes |= 1;
          last_repz_prefix = i;
          break;
        case 0xf2:
          prefixes |= 2;
          last_repnz_prefix = i;
          break;
        case 0xf0:
          prefixes |= 4;
          last_lock_prefix = i;
          break;
        case 0x2e:
          prefixes |= 8;
          last_seg_prefix = i;
          active_seg_prefix = 8;
          break;
        case 0x36:
          prefixes |= 0x10;
          last_seg_prefix = i;
          active_seg_prefix = 0x10;
          break;
        case 0x3e:
          prefixes |= 0x20;
          last_seg_prefix = i;
          active_seg_prefix = 0x20;
          break;
        case 0x26:
          prefixes |= 0x40;
          last_seg_prefix = i;
          active_seg_prefix = 0x40;
          break;
        case 0x64:
          prefixes |= 0x80;
          last_seg_prefix = i;
          active_seg_prefix = 0x80;
          break;
        case 0x65:
          prefixes |= 0x100;
          last_seg_prefix = i;
          active_seg_prefix = 0x100;
          break;
        case 0x66:
          prefixes |= 0x200;
          last_data_prefix = i;
          break;
        case 0x67:
          prefixes |= 0x400;
          last_addr_prefix = i;
          break;
        case 0x9b:

          fwait_prefix = i;
          if (prefixes || rex)
            {
              prefixes |= 0x800;
              codep++;

              rex_used = rex;
              return 1;
            }
          prefixes = 0x800;
          break;
        default:
          return 1;
        }

      if (rex)
        {
          rex_used = rex;
          return 1;
        }
      if (*codep != 0x9b)
        all_prefixes[i++] = *codep;
      rex = newrex;
      codep++;
      length++;
    }
  return 0;
}

static const char *
prefix_name (int pref, int sizeflag)
{
  static const char *rexes[16] = {
    "rex",    "rex.B",   "rex.X",   "rex.XB",   "rex.R",  "rex.RB",
    "rex.RX", "rex.RXB", "rex.W",   "rex.WB",   "rex.WX", "rex.WXB",
    "rex.WR", "rex.WRB", "rex.WRX", "rex.WRXB",
  };

  switch (pref)
    {

    case 0x40:
    case 0x41:
    case 0x42:
    case 0x43:
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x48:
    case 0x49:
    case 0x4a:
    case 0x4b:
    case 0x4c:
    case 0x4d:
    case 0x4e:
    case 0x4f:
      return rexes[pref - 0x40];
    case 0xf3:
      return "repz";
    case 0xf2:
      return "repnz";
    case 0xf0:
      return "lock";
    case 0x2e:
      return "cs";
    case 0x36:
      return "ss";
    case 0x3e:
      return "ds";
    case 0x26:
      return "es";
    case 0x64:
      return "fs";
    case 0x65:
      return "gs";
    case 0x66:
      return (sizeflag & 1) ? "data16" : "data32";
    case 0x67:
      if (address_mode == mode_64bit)
        return (sizeflag & 2) ? "addr32" : "addr64";
      else
        return (sizeflag & 2) ? "addr16" : "addr32";
    case 0x9b:
      return "fwait";
    case (0xf3 | 0x100):
      return "rep";
    case (0xf2 | 0x200):
      return "xacquire";
    case (0xf3 | 0x400):
      return "xrelease";
    case (0xf2 | 0x400):
      return "bnd";
    default:
      return ((void *)0);
    }
}

static char op_out[5][100];
static int op_ad, op_index[5];
static int two_source_ops;
static bfd_vma op_address[5];
static bfd_vma op_riprel[5];
static bfd_vma start_pc;
static char intel_syntax;
static char intel_mnemonic = !1;
static char open_char;
static char close_char;
static char separator_char;
static char scale_char;

int
print_insn_i386_att (bfd_vma pc, disassemble_info *info)
{
  intel_syntax = 0;

  return print_insn (pc, info);
}

int
print_insn_i386_intel (bfd_vma pc, disassemble_info *info)
{
  intel_syntax = 1;

  return print_insn (pc, info);
}

int
print_insn_i386 (bfd_vma pc, disassemble_info *info)
{
  intel_syntax = -1;

  return print_insn (pc, info);
}


static const struct dis386 bad_opcode = { "(bad)", { { ((void *)0), 0 } } };

static const struct dis386 *
get_valid_dis386 (const struct dis386 *dp, disassemble_info *info)
{
  int vindex, vex_table_index;

  if (dp->name != ((void *)0))
    return dp;

  switch (dp->op[0].bytemode)
    {
    case USE_REG_TABLE:
      dp = &reg_table[dp->op[1].bytemode][modrm.reg];
      break;

    case USE_MOD_TABLE:
      vindex = modrm.mod == 0x3 ? 1 : 0;
      dp = &mod_table[dp->op[1].bytemode][vindex];
      break;

    case USE_RM_TABLE:
      dp = &rm_table[dp->op[1].bytemode][modrm.rm];
      break;

    case USE_PREFIX_TABLE:
      if (need_vex)
        {

          switch (vex.prefix)
            {
            case 0:
              vindex = 0;
              break;
            case 0xf3:
              vindex = 1;
              break;
            case 0x66:
              vindex = 2;
              break;
            case 0xf2:
              vindex = 3;
              break;
            default:
              abort ();
              break;
            }
        }
      else
        {
          int last_prefix = -1;
          int prefix = 0;
          vindex = 0;

          if ((prefixes & (1 | 2)) != 0)
            {
              if (last_repz_prefix > last_repnz_prefix)
                {
                  vindex = 1;
                  prefix = 1;
                  last_prefix = last_repz_prefix;
                }
              else
                {
                  vindex = 3;
                  prefix = 2;
                  last_prefix = last_repnz_prefix;
                }

              if (!mandatory_prefix
                  && (prefix_table[dp->op[1].bytemode][vindex].name
                      == ((void *)0))
                  && (prefix_table[dp->op[1].bytemode][vindex].op[0].bytemode
                      == 0))
                vindex = 0;
            }

          if (vindex == 0 && (prefixes & 0x200) != 0)
            {
              vindex = 2;
              prefix = 0x200;
              last_prefix = last_data_prefix;
            }

          if (vindex != 0)
            {
              used_prefixes |= prefix;
              all_prefixes[last_prefix] = 0;
            }
        }
      dp = &prefix_table[dp->op[1].bytemode][vindex];
      break;

    case USE_X86_64_TABLE:
      vindex = address_mode == mode_64bit ? 1 : 0;
      dp = &x86_64_table[dp->op[1].bytemode][vindex];
      break;

    case USE_3BYTE_TABLE:
      ((codep + 2) <= ((struct dis_private *)(info->private_data))->max_fetched
           ? 1
           : fetch_data ((info), (codep + 2)));
      vindex = *codep++;
      dp = &three_byte_table[dp->op[1].bytemode][vindex];
      end_codep = codep;
      modrm.mod = (*codep >> 6) & 3;
      modrm.reg = (*codep >> 3) & 7;
      modrm.rm = *codep & 7;
      break;

    case USE_VEX_LEN_TABLE:
      if (!need_vex)
        abort ();

      switch (vex.length)
        {
        case 128:
          vindex = 0;
          break;
        case 256:
          vindex = 1;
          break;
        default:
          abort ();
          break;
        }

      dp = &vex_len_table[dp->op[1].bytemode][vindex];
      break;

    case USE_XOP_8F_TABLE:
      ((codep + 3) <= ((struct dis_private *)(info->private_data))->max_fetched
           ? 1
           : fetch_data ((info), (codep + 3)));

      rex_ignored = rex;
      rex = ~(*codep >> 5) & 0x7;

      switch ((*codep & 0x1f))
        {
        default:
          dp = &bad_opcode;
          return dp;
        case 0x8:
          vex_table_index = XOP_08;
          break;
        case 0x9:
          vex_table_index = XOP_09;
          break;
        case 0xa:
          vex_table_index = XOP_0A;
          break;
        }
      codep++;
      vex.w = *codep & 0x80;
      if (vex.w && address_mode == mode_64bit)
        rex |= 8;

      vex.register_specifier = (~(*codep >> 3)) & 0xf;
      if (address_mode != mode_64bit && vex.register_specifier > 0x7)
        {
          dp = &bad_opcode;
          return dp;
        }

      vex.length = (*codep & 0x4) ? 256 : 128;
      switch ((*codep & 0x3))
        {
        case 0:
          vex.prefix = 0;
          break;
        case 1:
          vex.prefix = 0x66;
          break;
        case 2:
          vex.prefix = 0xf3;
          break;
        case 3:
          vex.prefix = 0xf2;
          break;
        }
      need_vex = 1;
      need_vex_reg = 1;
      codep++;
      vindex = *codep++;
      dp = &xop_table[vex_table_index][vindex];

      end_codep = codep;
      ((codep + 1) <= ((struct dis_private *)(info->private_data))->max_fetched
           ? 1
           : fetch_data ((info), (codep + 1)));
      modrm.mod = (*codep >> 6) & 3;
      modrm.reg = (*codep >> 3) & 7;
      modrm.rm = *codep & 7;
      break;

    case USE_VEX_C4_TABLE:

      ((codep + 3) <= ((struct dis_private *)(info->private_data))->max_fetched
           ? 1
           : fetch_data ((info), (codep + 3)));

      rex_ignored = rex;
      rex = ~(*codep >> 5) & 0x7;
      switch ((*codep & 0x1f))
        {
        default:
          dp = &bad_opcode;
          return dp;
        case 0x1:
          vex_table_index = VEX_0F;
          break;
        case 0x2:
          vex_table_index = VEX_0F38;
          break;
        case 0x3:
          vex_table_index = VEX_0F3A;
          break;
        }
      codep++;
      vex.w = *codep & 0x80;
      if (vex.w && address_mode == mode_64bit)
        rex |= 8;

      vex.register_specifier = (~(*codep >> 3)) & 0xf;
      if (address_mode != mode_64bit && vex.register_specifier > 0x7)
        {
          dp = &bad_opcode;
          return dp;
        }

      vex.length = (*codep & 0x4) ? 256 : 128;
      switch ((*codep & 0x3))
        {
        case 0:
          vex.prefix = 0;
          break;
        case 1:
          vex.prefix = 0x66;
          break;
        case 2:
          vex.prefix = 0xf3;
          break;
        case 3:
          vex.prefix = 0xf2;
          break;
        }
      need_vex = 1;
      need_vex_reg = 1;
      codep++;
      vindex = *codep++;
      dp = &vex_table[vex_table_index][vindex];
      end_codep = codep;

      if (vindex != 0x77 && vindex != 0x82)
        {
          ((codep + 1)
                   <= ((struct dis_private *)(info->private_data))->max_fetched
               ? 1
               : fetch_data ((info), (codep + 1)));
          modrm.mod = (*codep >> 6) & 3;
          modrm.reg = (*codep >> 3) & 7;
          modrm.rm = *codep & 7;
        }
      break;

    case USE_VEX_C5_TABLE:

      ((codep + 2) <= ((struct dis_private *)(info->private_data))->max_fetched
           ? 1
           : fetch_data ((info), (codep + 2)));

      rex_ignored = rex;
      rex = (*codep & 0x80) ? 0 : 4;

      vex.register_specifier = (~(*codep >> 3)) & 0xf;
      if (address_mode != mode_64bit && vex.register_specifier > 0x7)
        {
          dp = &bad_opcode;
          return dp;
        }

      vex.w = 0;

      vex.length = (*codep & 0x4) ? 256 : 128;
      switch ((*codep & 0x3))
        {
        case 0:
          vex.prefix = 0;
          break;
        case 1:
          vex.prefix = 0x66;
          break;
        case 2:
          vex.prefix = 0xf3;
          break;
        case 3:
          vex.prefix = 0xf2;
          break;
        }
      need_vex = 1;
      need_vex_reg = 1;
      codep++;
      vindex = *codep++;
      dp = &vex_table[dp->op[1].bytemode][vindex];
      end_codep = codep;

      if (vindex != 0x77 && vindex != 0x82)
        {
          ((codep + 1)
                   <= ((struct dis_private *)(info->private_data))->max_fetched
               ? 1
               : fetch_data ((info), (codep + 1)));
          modrm.mod = (*codep >> 6) & 3;
          modrm.reg = (*codep >> 3) & 7;
          modrm.rm = *codep & 7;
        }
      break;

    case USE_VEX_W_TABLE:
      if (!need_vex)
        abort ();

      dp = &vex_w_table[dp->op[1].bytemode][vex.w ? 1 : 0];
      break;

    case USE_EVEX_TABLE:
      two_source_ops = 0;

      vex.evex = 1;
      ((codep + 4) <= ((struct dis_private *)(info->private_data))->max_fetched
           ? 1
           : fetch_data ((info), (codep + 4)));

      rex_ignored = rex;

      rex = ~(*codep >> 5) & 0x7;
      vex.r = *codep & 0x10;
      switch ((*codep & 0xf))
        {
        default:
          return &bad_opcode;
        case 0x1:
          vex_table_index = EVEX_0F;
          break;
        case 0x2:
          vex_table_index = EVEX_0F38;
          break;
        case 0x3:
          vex_table_index = EVEX_0F3A;
          break;
        }

      codep++;
      vex.w = *codep & 0x80;
      if (vex.w && address_mode == mode_64bit)
        rex |= 8;

      vex.register_specifier = (~(*codep >> 3)) & 0xf;
      if (address_mode != mode_64bit)
        {

          rex &= ~1;
          vex.r = 1;
          vex.v = 1;
          vex.register_specifier &= 0x7;
        }

      if (!(*codep & 0x4))
        return &bad_opcode;

      switch ((*codep & 0x3))
        {
        case 0:
          vex.prefix = 0;
          break;
        case 1:
          vex.prefix = 0x66;
          break;
        case 2:
          vex.prefix = 0xf3;
          break;
        case 3:
          vex.prefix = 0xf2;
          break;
        }

      codep++;

      vex.ll = (*codep >> 5) & 3;
      vex.b = (*codep & 0x10) != 0;

      vex.v = *codep & 0x8;
      vex.mask_register_specifier = *codep & 0x7;
      vex.zeroing = *codep & 0x80;

      need_vex = 1;
      need_vex_reg = 1;
      codep++;
      vindex = *codep++;
      dp = &evex_table[vex_table_index][vindex];
      end_codep = codep;
      ((codep + 1) <= ((struct dis_private *)(info->private_data))->max_fetched
           ? 1
           : fetch_data ((info), (codep + 1)));
      modrm.mod = (*codep >> 6) & 3;
      modrm.reg = (*codep >> 3) & 7;
      modrm.rm = *codep & 7;

      if (modrm.mod == 3 && vex.b)
        vex.length = 512;
      else
        {
          switch (vex.ll)
            {
            case 0x0:
              vex.length = 128;
              break;
            case 0x1:
              vex.length = 256;
              break;
            case 0x2:
              vex.length = 512;
              break;
            default:
              return &bad_opcode;
            }
        }
      break;

    case 0:
      dp = &bad_opcode;
      break;

    default:
      abort ();
    }

  if (dp->name != ((void *)0))
    return dp;
  else
    return get_valid_dis386 (dp, info);
}

static void
get_sib (disassemble_info *info, int sizeflag)
{

  if (need_modrm && ((sizeflag & 2) || address_mode == mode_64bit)
      && modrm.mod != 3 && modrm.rm == 4)
    {
      ((codep + 2) <= ((struct dis_private *)(info->private_data))->max_fetched
           ? 1
           : fetch_data ((info), (codep + 2)));
      sib.index = (codep[1] >> 3) & 7;
      sib.scale = (codep[1] >> 6) & 3;
      sib.base = codep[1] & 7;
    }
}

static int
print_insn (bfd_vma pc, disassemble_info *info)
{
  const struct dis386 *dp;
  int i;
  char *op_txt[5];
  int needcomma;
  int sizeflag, orig_sizeflag;
  struct dis_private priv;
  int prefix_length;

  priv.orig_sizeflag = 2 | 1;
  address_mode = info->address_mode;


  if (intel_syntax)
    {
      names64 = intel_names64;
      names32 = intel_names32;
      names16 = intel_names16;
      names8 = intel_names8;
      names8rex = intel_names8rex;
      names_seg = intel_names_seg;
      names_mm = intel_names_mm;
      names_bnd = intel_names_bnd;
      names_xmm = intel_names_xmm;
      names_ymm = intel_names_ymm;
      names_zmm = intel_names_zmm;
      index64 = intel_index64;
      index32 = intel_index32;
      names_mask = intel_names_mask;
      index16 = intel_index16;
      open_char = '[';
      close_char = ']';
      separator_char = '+';
      scale_char = '*';
    }
  else
    {
      names64 = att_names64;
      names32 = att_names32;
      names16 = att_names16;
      names8 = att_names8;
      names8rex = att_names8rex;
      names_seg = att_names_seg;
      names_mm = att_names_mm;
      names_bnd = att_names_bnd;
      names_xmm = att_names_xmm;
      names_ymm = att_names_ymm;
      names_zmm = att_names_zmm;
      index64 = att_index64;
      index32 = att_index32;
      names_mask = att_names_mask;
      index16 = att_index16;
      open_char = '(';
      close_char = ')';
      separator_char = ',';
      scale_char = ',';
    }

  info->bytes_per_line = 7;

  info->private_data = &priv;
  priv.max_fetched = priv.the_buffer;
  priv.insn_start = pc;

  obuf[0] = 0;
  for (i = 0; i < 5; ++i)
    {
      op_out[i][0] = 0;
      op_index[i] = -1;
    }

  the_info = info;
  start_pc = pc;
  start_codep = priv.the_buffer;
  codep = priv.the_buffer;

  if (_setjmp (priv.bailout) != 0)
    {
      const char *name;

      if (codep > priv.the_buffer)
        {
          name = prefix_name (priv.the_buffer[0], priv.orig_sizeflag);
          if (name != ((void *)0))
            (*info->fprintf_func)(info->stream, "%s", name);
          else
            {

              (*info->fprintf_func)(info->stream, ".byte 0x%x",
                                    (unsigned int)priv.the_buffer[0]);
            }

          return 1;
        }

      return -1;
    }

  obufp = obuf;
  sizeflag = priv.orig_sizeflag;

  if (!ckprefix () || rex_used)
    {

      for (i = 0; i < (int)(sizeof (all_prefixes) / sizeof ((all_prefixes)[0]))
                      && all_prefixes[i];
           i++)
        (*info->fprintf_func)(info->stream, "%s%s", i == 0 ? "" : " ",
                              prefix_name (all_prefixes[i], sizeflag));
      return i;
    }

  insn_codep = codep;

  ((codep + 1) <= ((struct dis_private *)(info->private_data))->max_fetched
       ? 1
       : fetch_data ((info), (codep + 1)));
  two_source_ops = (*codep == 0x62) || (*codep == 0xc8);

  if (((prefixes & 0x800) && ((*codep < 0xd8) || (*codep > 0xdf))))
    {

      for (i = 0; i < fwait_prefix && all_prefixes[i]; i++)
        (*info->fprintf_func)(info->stream, "%s ",
                              prefix_name (all_prefixes[i], sizeflag));
      (*info->fprintf_func)(info->stream, "fwait");
      return i + 1;
    }

  if (*codep == 0x0f)
    {
      unsigned char threebyte;
      ((codep + 2) <= ((struct dis_private *)(info->private_data))->max_fetched
           ? 1
           : fetch_data ((info), (codep + 2)));
      threebyte = *++codep;
      dp = &dis386_twobyte[threebyte];
      need_modrm = twobyte_has_modrm[*codep];
      mandatory_prefix = twobyte_has_mandatory_prefix[*codep];
      codep++;
    }
  else
    {
      dp = &dis386[*codep];
      need_modrm = onebyte_has_modrm[*codep];
      mandatory_prefix = 0;
      codep++;
    }

  orig_sizeflag = sizeflag;
  if (prefixes & 0x400)
    sizeflag ^= 2;
  if ((prefixes & 0x200))
    sizeflag ^= 1;

  end_codep = codep;
  if (need_modrm)
    {
      ((codep + 1) <= ((struct dis_private *)(info->private_data))->max_fetched
           ? 1
           : fetch_data ((info), (codep + 1)));
      modrm.mod = (*codep >> 6) & 3;
      modrm.reg = (*codep >> 3) & 7;
      modrm.rm = *codep & 7;
    }

  need_vex = 0;
  need_vex_reg = 0;
  vex_w_done = 0;
  vex.evex = 0;

  if (dp->name == ((void *)0) && dp->op[0].bytemode == FLOATCODE)
    {
      get_sib (info, sizeflag);
      dofloat (sizeflag);
    }
  else
    {
      dp = get_valid_dis386 (dp, info);
      if (dp != ((void *)0) && putop (dp->name, sizeflag) == 0)
        {
          get_sib (info, sizeflag);
          for (i = 0; i < 5; ++i)
            {
              obufp = op_out[i];
              op_ad = 5 - 1 - i;
              if (dp->op[i].rtn)
                (*dp->op[i].rtn)(dp->op[i].bytemode, sizeflag);

              if (i == 0 && vex.evex)
                {

                  if (vex.mask_register_specifier)
                    {
                      oappend ("{");
                      oappend (names_mask[vex.mask_register_specifier]);
                      oappend ("}");
                    }
                  if (vex.zeroing)
                    oappend ("{z}");
                }
            }
        }
    }

  if (rex_ignored == 0 && (rex ^ rex_used) == 0 && last_rex_prefix >= 0)
    all_prefixes[last_rex_prefix] = 0;

  if ((prefixes & (8 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100)) != 0
      && (used_prefixes & active_seg_prefix) != 0)
    all_prefixes[last_seg_prefix] = 0;

  if ((prefixes & 0x400) != 0 && (used_prefixes & 0x400) != 0)
    all_prefixes[last_addr_prefix] = 0;

  if ((prefixes & 0x200) != 0 && (used_prefixes & 0x200) != 0)
    all_prefixes[last_data_prefix] = 0;

  prefix_length = 0;
  for (i = 0; i < (int)(sizeof (all_prefixes) / sizeof ((all_prefixes)[0]));
       i++)
    if (all_prefixes[i])
      {
        const char *name;
        name = prefix_name (all_prefixes[i], orig_sizeflag);
        if (name == ((void *)0))
          abort ();
        prefix_length += strlen (name) + 1;
        (*info->fprintf_func)(info->stream, "%s ", name);
      }

  if (mandatory_prefix && dp != &bad_opcode
      && (((prefixes & (1 | 2)) != 0 && (used_prefixes & (1 | 2)) == 0)
          || ((((prefixes & (1 | 2 | 0x200)) == 0x200)
               && (used_prefixes & 0x200) == 0))))
    {
      (*info->fprintf_func)(info->stream, "(bad)");
      return end_codep - priv.the_buffer;
    }

  if ((codep - start_codep) > 15)
    {
      (*info->fprintf_func)(info->stream, "(bad)");
      return 15;
    }

  obufp = mnemonicendp;
  for (i = strlen (obuf) + prefix_length; i < 6; i++)
    oappend (" ");
  oappend (" ");
  (*info->fprintf_func)(info->stream, "%s", obuf);

  if (intel_syntax || two_source_ops)
    {
      bfd_vma riprel;

      for (i = 0; i < 5; ++i)
        op_txt[i] = op_out[i];

      for (i = 0; i < (5 >> 1); ++i)
        {
          op_ad = op_index[i];
          op_index[i] = op_index[5 - 1 - i];
          op_index[5 - 1 - i] = op_ad;
          riprel = op_riprel[i];
          op_riprel[i] = op_riprel[5 - 1 - i];
          op_riprel[5 - 1 - i] = riprel;
        }
    }
  else
    {
      for (i = 0; i < 5; ++i)
        op_txt[5 - 1 - i] = op_out[i];
    }

  needcomma = 0;
  for (i = 0; i < 5; ++i)
    if (*op_txt[i])
      {
        if (needcomma)
          (*info->fprintf_func)(info->stream, ",");
        if (op_index[i] != -1 && !op_riprel[i])
          (*info->print_address_func)((bfd_vma)op_address[op_index[i]], info);
        else
          (*info->fprintf_func)(info->stream, "%s", op_txt[i]);
        needcomma = 1;
      }

  for (i = 0; i < 5; i++)
    if (op_index[i] != -1 && op_riprel[i])
      {
        (*info->fprintf_func)(info->stream, "        # ");
        (*info->print_address_func)((bfd_vma)(start_pc + codep - start_codep
                                              + op_address[op_index[i]]),
                                    info);
        break;
      }
  return codep - priv.the_buffer;
}

static const char *float_mem[] = {

  "fadd{s|}",  "fmul{s|}",    "fcom{s|}",  "fcomp{s|}",
  "fsub{s|}",  "fsubr{s|}",   "fdiv{s|}",  "fdivr{s|}",

  "fld{s|}",   "(bad)",       "fst{s|}",   "fstp{s|}",
  "fldenvIC",  "fldcw",       "fNstenvIC", "fNstcw",

  "fiadd{l|}", "fimul{l|}",   "ficom{l|}", "ficomp{l|}",
  "fisub{l|}", "fisubr{l|}",  "fidiv{l|}", "fidivr{l|}",

  "fild{l|}",  "fisttp{l|}",  "fist{l|}",  "fistp{l|}",
  "(bad)",     "fld{t||t|}",  "(bad)",     "fstp{t||t|}",

  "fadd{l|}",  "fmul{l|}",    "fcom{l|}",  "fcomp{l|}",
  "fsub{l|}",  "fsubr{l|}",   "fdiv{l|}",  "fdivr{l|}",

  "fld{l|}",   "fisttp{ll|}", "fst{l||}",  "fstp{l|}",
  "frstorIC",  "(bad)",       "fNsaveIC",  "fNstsw",

  "fiadd",     "fimul",       "ficom",     "ficomp",
  "fisub",     "fisubr",      "fidiv",     "fidivr",

  "fild",      "fisttp",      "fist",      "fistp",
  "fbld",      "fild{ll|}",   "fbstp",     "fistp{ll|}",
};

static const unsigned char float_mem_mode[] = {

  d_mode, d_mode, d_mode, d_mode, d_mode, d_mode, d_mode, d_mode,

  d_mode, 0,      d_mode, d_mode, 0,      w_mode, 0,      w_mode,

  d_mode, d_mode, d_mode, d_mode, d_mode, d_mode, d_mode, d_mode,

  d_mode, d_mode, d_mode, d_mode, 0,      t_mode, 0,      t_mode,

  q_mode, q_mode, q_mode, q_mode, q_mode, q_mode, q_mode, q_mode,

  q_mode, q_mode, q_mode, q_mode, 0,      0,      0,      w_mode,

  w_mode, w_mode, w_mode, w_mode, w_mode, w_mode, w_mode, w_mode,

  w_mode, w_mode, w_mode, w_mode, t_mode, q_mode, t_mode, q_mode
};
static const struct dis386 float_reg[][8] = {

  {
   { "fadd", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { "fmul", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { "fcom", { { OP_STi, 0 } } },
   { "fcomp", { { OP_STi, 0 } } },
   { "fsub", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { "fsubr", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { "fdiv", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { "fdivr", { { OP_ST, 0 }, { OP_STi, 0 } } },
  },

  {
   { "fld", { { OP_STi, 0 } } },
   { "fxch", { { OP_STi, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 1 } } },
   { ((void *)0), { { ((void *)0), 2 } } },
   { ((void *)0), { { ((void *)0), 3 } } },
   { ((void *)0), { { ((void *)0), 4 } } },
  },

  {
   { "fcmovb", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { "fcmove", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { "fcmovbe", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { "fcmovu", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 5 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {
   { "fcmovnb", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { "fcmovne", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { "fcmovnbe", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { "fcmovnu", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { ((void *)0), { { ((void *)0), 6 } } },
   { "fucomi", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { "fcomi", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {
   { "fadd", { { OP_STi, 0 }, { OP_ST, 0 } } },
   { "fmul", { { OP_STi, 0 }, { OP_ST, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "fsub!M", { { OP_STi, 0 }, { OP_ST, 0 } } },
   { "fsubM", { { OP_STi, 0 }, { OP_ST, 0 } } },
   { "fdiv!M", { { OP_STi, 0 }, { OP_ST, 0 } } },
   { "fdivM", { { OP_STi, 0 }, { OP_ST, 0 } } },
  },

  {
   { "ffree", { { OP_STi, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { "fst", { { OP_STi, 0 } } },
   { "fstp", { { OP_STi, 0 } } },
   { "fucom", { { OP_STi, 0 } } },
   { "fucomp", { { OP_STi, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },

  {
   { "faddp", { { OP_STi, 0 }, { OP_ST, 0 } } },
   { "fmulp", { { OP_STi, 0 }, { OP_ST, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 7 } } },
   { "fsub!Mp", { { OP_STi, 0 }, { OP_ST, 0 } } },
   { "fsubMp", { { OP_STi, 0 }, { OP_ST, 0 } } },
   { "fdiv!Mp", { { OP_STi, 0 }, { OP_ST, 0 } } },
   { "fdivMp", { { OP_STi, 0 }, { OP_ST, 0 } } },
  },

  {
   { "ffreep", { { OP_STi, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
   { ((void *)0), { { ((void *)0), 8 } } },
   { "fucomip", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { "fcomip", { { OP_ST, 0 }, { OP_STi, 0 } } },
   { ((void *)0), { { ((void *)0), 0 } } },
  },
};

static char *fgrps[][8] = {

  {
   "fnop", "(bad)", "(bad)", "(bad)", "(bad)", "(bad)", "(bad)", "(bad)",
  },

  {
   "fchs", "fabs", "(bad)", "(bad)", "ftst", "fxam", "(bad)", "(bad)",
  },

  {
   "fld1", "fldl2t", "fldl2e", "fldpi", "fldlg2", "fldln2", "fldz", "(bad)",
  },

  {
   "f2xm1", "fyl2x", "fptan", "fpatan", "fxtract", "fprem1", "fdecstp",
   "fincstp",
  },

  {
   "fprem", "fyl2xp1", "fsqrt", "fsincos", "frndint", "fscale", "fsin", "fcos",
  },

  {
   "(bad)", "fucompp", "(bad)", "(bad)", "(bad)", "(bad)", "(bad)", "(bad)",
  },

  {
   "fNeni(8087 only)", "fNdisi(8087 only)", "fNclex", "fNinit",
   "fNsetpm(287 only)", "frstpm(287 only)", "(bad)", "(bad)",
  },

  {
   "(bad)", "fcompp", "(bad)", "(bad)", "(bad)", "(bad)", "(bad)", "(bad)",
  },

  {
   "fNstsw", "(bad)", "(bad)", "(bad)", "(bad)", "(bad)", "(bad)", "(bad)",
  },
};

static void
swap_operand (void)
{
  mnemonicendp[0] = '.';
  mnemonicendp[1] = 's';
  mnemonicendp += 2;
}

static void
OP_Skip_MODRM (int bytemode __attribute__ ((__unused__)),
               int sizeflag __attribute__ ((__unused__)))
{

  if (!need_modrm)
    abort ();
  codep++;
}

static void
dofloat (int sizeflag)
{
  const struct dis386 *dp;
  unsigned char floatop;

  floatop = codep[-1];

  if (modrm.mod != 3)
    {
      int fp_indx = (floatop - 0xd8) * 8 + modrm.reg;

      putop (float_mem[fp_indx], sizeflag);
      obufp = op_out[0];
      op_ad = 2;
      OP_E (float_mem_mode[fp_indx], sizeflag);
      return;
    }

  if (!need_modrm)
    abort ();
  codep++;

  dp = &float_reg[floatop - 0xd8][modrm.reg];
  if (dp->name == ((void *)0))
    {
      putop (fgrps[dp->op[0].bytemode][modrm.rm], sizeflag);

      if (floatop == 0xdf && codep[-1] == 0xe0)
        strcpy (op_out[0], names16[0]);
    }
  else
    {
      putop (dp->name, sizeflag);

      obufp = op_out[0];
      op_ad = 2;
      if (dp->op[0].rtn)
        (*dp->op[0].rtn)(dp->op[0].bytemode, sizeflag);

      obufp = op_out[1];
      op_ad = 1;
      if (dp->op[1].rtn)
        (*dp->op[1].rtn)(dp->op[1].bytemode, sizeflag);
    }
}

static void
oappend_maybe_intel (const char *s)
{
  oappend (s + intel_syntax);
}

static void
OP_ST (int bytemode __attribute__ ((__unused__)),
       int sizeflag __attribute__ ((__unused__)))
{
  oappend_maybe_intel ("%st");
}

static void
OP_STi (int bytemode __attribute__ ((__unused__)),
        int sizeflag __attribute__ ((__unused__)))
{
  sprintf (scratchbuf, "%%st(%d)", modrm.rm);
  oappend_maybe_intel (scratchbuf);
}

static int
putop (const char *in_template, int sizeflag)
{
  const char *p;
  int alt = 0;
  int cond = 1;
  unsigned int l = 0, len = 1;
  char last[4];

  for (p = in_template; *p; p++)
    {
      switch (*p)
        {
        default:
          *obufp++ = *p;
          break;
        case '%':
          len++;
          break;
        case '!':
          cond = 0;
          break;
        case '{':
          alt = 0;
          if (intel_syntax)
            {
              while (*++p != '|')
                if (*p == '}' || *p == '\0')
                  abort ();
            }

        case 'I':
          alt = 1;
          continue;
        case '|':
          while (*++p != '}')
            {
              if (*p == '\0')
                abort ();
            }
          break;
        case '}':
          break;
        case 'A':
          if (intel_syntax)
            break;
          if (modrm.mod != 3 || (sizeflag & 4))
            *obufp++ = 'b';
          break;
        case 'B':
          if (l == 0 && len == 1)
            {
            case_B:
              if (intel_syntax)
                break;
              if (sizeflag & 4)
                *obufp++ = 'b';
            }
          else
            {
              if (l != 1 || len != 2 || last[0] != 'L')
                {
                  if (l < len && l < sizeof (last))
                    last[l++] = *p;
                  else
                    abort ();
                  ;
                  break;
                }

              if (address_mode == mode_64bit && !(prefixes & 0x400))
                {
                  *obufp++ = 'a';
                  *obufp++ = 'b';
                  *obufp++ = 's';
                }

              goto case_B;
            }
          break;
        case 'C':
          if (intel_syntax && !alt)
            break;
          if ((prefixes & 0x200) || (sizeflag & 4))
            {
              if (sizeflag & 1)
                *obufp++ = intel_syntax ? 'd' : 'l';
              else
                *obufp++ = intel_syntax ? 'w' : 's';
              used_prefixes |= (prefixes & 0x200);
            }
          break;
        case 'D':
          if (intel_syntax || !(sizeflag & 4))
            break;
          {
            if (8)
              {
                if ((rex & 8))
                  rex_used |= (8) | 0x40;
              }
            else
              rex_used |= 0x40;
          };
          if (modrm.mod == 3)
            {
              if (rex & 8)
                *obufp++ = 'q';
              else
                {
                  if (sizeflag & 1)
                    *obufp++ = intel_syntax ? 'd' : 'l';
                  else
                    *obufp++ = 'w';
                  used_prefixes |= (prefixes & 0x200);
                }
            }
          else
            *obufp++ = 'w';
          break;
        case 'E':
          if (address_mode == mode_64bit)
            {
              if (sizeflag & 2)
                *obufp++ = 'r';
              else
                *obufp++ = 'e';
            }
          else if (sizeflag & 2)
            *obufp++ = 'e';
          used_prefixes |= (prefixes & 0x400);
          break;
        case 'F':
          if (intel_syntax)
            break;
          if ((prefixes & 0x400) || (sizeflag & 4))
            {
              if (sizeflag & 2)
                *obufp++ = address_mode == mode_64bit ? 'q' : 'l';
              else
                *obufp++ = address_mode == mode_64bit ? 'l' : 'w';
              used_prefixes |= (prefixes & 0x400);
            }
          break;
        case 'G':
          if (intel_syntax || (obufp[-1] != 's' && !(sizeflag & 4)))
            break;
          if ((rex & 8) || (sizeflag & 1))
            *obufp++ = 'l';
          else
            *obufp++ = 'w';
          if (!(rex & 8))
            used_prefixes |= (prefixes & 0x200);
          break;
        case 'H':
          if (intel_syntax)
            break;
          if ((prefixes & (8 | 0x20)) == 8 || (prefixes & (8 | 0x20)) == 0x20)
            {
              used_prefixes |= prefixes & (8 | 0x20);
              *obufp++ = ',';
              *obufp++ = 'p';
              if (prefixes & 0x20)
                *obufp++ = 't';
              else
                *obufp++ = 'n';
            }
          break;
        case 'J':
          if (intel_syntax)
            break;
          *obufp++ = 'l';
          break;
        case 'K':
          {
            if (8)
              {
                if ((rex & 8))
                  rex_used |= (8) | 0x40;
              }
            else
              rex_used |= 0x40;
          };
          if (rex & 8)
            *obufp++ = 'q';
          else
            *obufp++ = 'd';
          break;
        case 'Z':
          if (intel_syntax)
            break;
          if (address_mode == mode_64bit && (sizeflag & 4))
            {
              *obufp++ = 'q';
              break;
            }

          goto case_L;
        case 'L':
          if (l != 0 || len != 1)
            {
              if (l < len && l < sizeof (last))
                last[l++] = *p;
              else
                abort ();
              ;
              break;
            }
        case_L:
          if (intel_syntax)
            break;
          if (sizeflag & 4)
            *obufp++ = 'l';
          break;
        case 'M':
          if (intel_mnemonic != cond)
            *obufp++ = 'r';
          break;
        case 'N':
          if ((prefixes & 0x800) == 0)
            *obufp++ = 'n';
          else
            used_prefixes |= 0x800;
          break;
        case 'O':
          {
            if (8)
              {
                if ((rex & 8))
                  rex_used |= (8) | 0x40;
              }
            else
              rex_used |= 0x40;
          };
          if (rex & 8)
            *obufp++ = 'o';
          else if (intel_syntax && (sizeflag & 1))
            *obufp++ = 'q';
          else
            *obufp++ = 'd';
          if (!(rex & 8))
            used_prefixes |= (prefixes & 0x200);
          break;
        case 'T':
          if (!intel_syntax && address_mode == mode_64bit
              && ((sizeflag & 1) || (rex & 8)))
            {
              *obufp++ = 'q';
              break;
            }

        case 'P':
          if (intel_syntax)
            {
              if ((rex & 8) == 0 && (prefixes & 0x200))
                {
                  if ((sizeflag & 1) == 0)
                    *obufp++ = 'w';
                  used_prefixes |= (prefixes & 0x200);
                }
              break;
            }
          if ((prefixes & 0x200) || (rex & 8) || (sizeflag & 4))
            {
              {
                if (8)
                  {
                    if ((rex & 8))
                      rex_used |= (8) | 0x40;
                  }
                else
                  rex_used |= 0x40;
              };
              if (rex & 8)
                *obufp++ = 'q';
              else
                {
                  if (sizeflag & 1)
                    *obufp++ = 'l';
                  else
                    *obufp++ = 'w';
                  used_prefixes |= (prefixes & 0x200);
                }
            }
          break;
        case 'U':
          if (intel_syntax)
            break;
          if (address_mode == mode_64bit && ((sizeflag & 1) || (rex & 8)))
            {
              if (modrm.mod != 3 || (sizeflag & 4))
                *obufp++ = 'q';
              break;
            }

          goto case_Q;
        case 'Q':
          if (l == 0 && len == 1)
            {
            case_Q:
              if (intel_syntax && !alt)
                break;
              {
                if (8)
                  {
                    if ((rex & 8))
                      rex_used |= (8) | 0x40;
                  }
                else
                  rex_used |= 0x40;
              };
              if (modrm.mod != 3 || (sizeflag & 4))
                {
                  if (rex & 8)
                    *obufp++ = 'q';
                  else
                    {
                      if (sizeflag & 1)
                        *obufp++ = intel_syntax ? 'd' : 'l';
                      else
                        *obufp++ = 'w';
                      used_prefixes |= (prefixes & 0x200);
                    }
                }
            }
          else
            {
              if (l != 1 || len != 2 || last[0] != 'L')
                {
                  if (l < len && l < sizeof (last))
                    last[l++] = *p;
                  else
                    abort ();
                  ;
                  break;
                }
              if (intel_syntax || (modrm.mod == 3 && !(sizeflag & 4)))
                break;
              if ((rex & 8))
                {
                  {
                    if (8)
                      {
                        if ((rex & 8))
                          rex_used |= (8) | 0x40;
                      }
                    else
                      rex_used |= 0x40;
                  };
                  *obufp++ = 'q';
                }
              else
                *obufp++ = 'l';
            }
          break;
        case 'R':
          {
            if (8)
              {
                if ((rex & 8))
                  rex_used |= (8) | 0x40;
              }
            else
              rex_used |= 0x40;
          };
          if (rex & 8)
            *obufp++ = 'q';
          else if (sizeflag & 1)
            {
              if (intel_syntax)
                *obufp++ = 'd';
              else
                *obufp++ = 'l';
            }
          else
            *obufp++ = 'w';
          if (intel_syntax && !p[1] && ((rex & 8) || (sizeflag & 1)))
            *obufp++ = 'e';
          if (!(rex & 8))
            used_prefixes |= (prefixes & 0x200);
          break;
        case 'V':
          if (l == 0 && len == 1)
            {
              if (intel_syntax)
                break;
              if (address_mode == mode_64bit && ((sizeflag & 1) || (rex & 8)))
                {
                  if (sizeflag & 4)
                    *obufp++ = 'q';
                  break;
                }
            }
          else
            {
              if (l != 1 || len != 2 || last[0] != 'L')
                {
                  if (l < len && l < sizeof (last))
                    last[l++] = *p;
                  else
                    abort ();
                  ;
                  break;
                }

              if (rex & 8)
                {
                  *obufp++ = 'a';
                  *obufp++ = 'b';
                  *obufp++ = 's';
                }
            }

          goto case_S;
        case 'S':
          if (l == 0 && len == 1)
            {
            case_S:
              if (intel_syntax)
                break;
              if (sizeflag & 4)
                {
                  if (rex & 8)
                    *obufp++ = 'q';
                  else
                    {
                      if (sizeflag & 1)
                        *obufp++ = 'l';
                      else
                        *obufp++ = 'w';
                      used_prefixes |= (prefixes & 0x200);
                    }
                }
            }
          else
            {
              if (l != 1 || len != 2 || last[0] != 'L')
                {
                  if (l < len && l < sizeof (last))
                    last[l++] = *p;
                  else
                    abort ();
                  ;
                  break;
                }

              if (address_mode == mode_64bit && !(prefixes & 0x400))
                {
                  *obufp++ = 'a';
                  *obufp++ = 'b';
                  *obufp++ = 's';
                }

              goto case_S;
            }
          break;
        case 'X':
          if (l != 0 || len != 1)
            {
              if (l < len && l < sizeof (last))
                last[l++] = *p;
              else
                abort ();
              ;
              break;
            }
          if (need_vex && vex.prefix)
            {
              if (vex.prefix == 0x66)
                *obufp++ = 'd';
              else
                *obufp++ = 's';
            }
          else
            {
              if (prefixes & 0x200)
                *obufp++ = 'd';
              else
                *obufp++ = 's';
              used_prefixes |= (prefixes & 0x200);
            }
          break;
        case 'Y':
          if (l == 0 && len == 1)
            {
              if (intel_syntax || !(sizeflag & 4))
                break;
              if (rex & 8)
                {
                  {
                    if (8)
                      {
                        if ((rex & 8))
                          rex_used |= (8) | 0x40;
                      }
                    else
                      rex_used |= 0x40;
                  };
                  *obufp++ = 'q';
                }
              break;
            }
          else
            {
              if (l != 1 || len != 2 || last[0] != 'X')
                {
                  if (l < len && l < sizeof (last))
                    last[l++] = *p;
                  else
                    abort ();
                  ;
                  break;
                }
              if (!need_vex)
                abort ();
              if (intel_syntax || (modrm.mod == 3 && !(sizeflag & 4)))
                break;
              switch (vex.length)
                {
                case 128:
                  *obufp++ = 'x';
                  break;
                case 256:
                  *obufp++ = 'y';
                  break;
                default:
                  abort ();
                }
            }
          break;
        case 'W':
          if (l == 0 && len == 1)
            {

              {
                if (8)
                  {
                    if ((rex & 8))
                      rex_used |= (8) | 0x40;
                  }
                else
                  rex_used |= 0x40;
              };
              if (rex & 8)
                {
                  if (intel_syntax)
                    *obufp++ = 'd';
                  else
                    *obufp++ = 'l';
                }
              else if (sizeflag & 1)
                *obufp++ = 'w';
              else
                *obufp++ = 'b';
              if (!(rex & 8))
                used_prefixes |= (prefixes & 0x200);
            }
          else
            {
              if (l != 1 || len != 2 || (last[0] != 'X' && last[0] != 'L'))
                {
                  if (l < len && l < sizeof (last))
                    last[l++] = *p;
                  else
                    abort ();
                  ;
                  break;
                }
              if (!need_vex)
                abort ();
              if (last[0] == 'X')
                *obufp++ = vex.w ? 'd' : 's';
              else
                *obufp++ = vex.w ? 'q' : 'd';
            }
          break;
        }
      alt = 0;
    }
  *obufp = 0;
  mnemonicendp = obufp;
  return 0;
}

static void
oappend (const char *s)
{
  obufp = stpcpy (obufp, s);
}

static void
append_seg (void)
{

  if (!active_seg_prefix)
    return;

  used_prefixes |= active_seg_prefix;
  switch (active_seg_prefix)
    {
    case 8:
      oappend_maybe_intel ("%cs:");
      break;
    case 0x20:
      oappend_maybe_intel ("%ds:");
      break;
    case 0x10:
      oappend_maybe_intel ("%ss:");
      break;
    case 0x40:
      oappend_maybe_intel ("%es:");
      break;
    case 0x80:
      oappend_maybe_intel ("%fs:");
      break;
    case 0x100:
      oappend_maybe_intel ("%gs:");
      break;
    default:
      break;
    }
}

static void
OP_indirE (int bytemode, int sizeflag)
{
  if (!intel_syntax)
    oappend ("*");
  OP_E (bytemode, sizeflag);
}

static void
print_operand_value (char *buf, int hex, bfd_vma disp)
{
  if (address_mode == mode_64bit)
    {
      if (hex)
        {
          char tmp[30];
          int i;
          buf[0] = '0';
          buf[1] = 'x';
          sprintf (tmp, "%016"
                        "l"
                        "x",
                   disp);
          for (i = 0; tmp[i] == '0' && tmp[i + 1]; i++)
            ;
          strcpy (buf + 2, tmp + i);
        }
      else
        {
          bfd_signed_vma v = disp;
          char tmp[30];
          int i;
          if (v < 0)
            {
              *(buf++) = '-';
              v = -disp;

              if (v < 0)
                {
                  strcpy (buf, "9223372036854775808");
                  return;
                }
            }
          if (!v)
            {
              strcpy (buf, "0");
              return;
            }

          i = 0;
          tmp[29] = 0;
          while (v)
            {
              tmp[28 - i] = (v % 10) + '0';
              v /= 10;
              i++;
            }
          strcpy (buf, tmp + 29 - i);
        }
    }
  else
    {
      if (hex)
        sprintf (buf, "0x%x", (unsigned int)disp);
      else
        sprintf (buf, "%d", (int)disp);
    }
}

static void
print_displacement (char *buf, bfd_vma disp)
{
  bfd_signed_vma val = disp;
  char tmp[30];
  int i, j = 0;

  if (val < 0)
    {
      buf[j++] = '-';
      val = -disp;

      if (val < 0)
        {
          switch (address_mode)
            {
            case mode_64bit:
              strcpy (buf + j, "0x8000000000000000");
              break;
            case mode_32bit:
              strcpy (buf + j, "0x80000000");
              break;
            case mode_16bit:
              strcpy (buf + j, "0x8000");
              break;
            }
          return;
        }
    }

  buf[j++] = '0';
  buf[j++] = 'x';

  sprintf (tmp, "%016"
                "l"
                "x",
           (bfd_vma)val);
  for (i = 0; tmp[i] == '0'; i++)
    continue;
  if (tmp[i] == '\0')
    i--;
  strcpy (buf + j, tmp + i);
}

static void
intel_operand_size (int bytemode, int sizeflag)
{
  if (vex.evex && vex.b
      && (bytemode == x_mode || bytemode == evex_half_bcst_xmmq_mode))
    {
      if (vex.w)
        oappend ("QWORD PTR ");
      else
        oappend ("DWORD PTR ");
      return;
    }
  switch (bytemode)
    {
    case b_mode:
    case b_swap_mode:
    case dqb_mode:
      oappend ("BYTE PTR ");
      break;
    case w_mode:
    case dqw_mode:
      oappend ("WORD PTR ");
      break;
    case stack_v_mode:
      if (address_mode == mode_64bit && ((sizeflag & 1) || (rex & 8)))
        {
          oappend ("QWORD PTR ");
          break;
        }

    case v_mode:
    case v_swap_mode:
    case dq_mode:
      {
        if (8)
          {
            if ((rex & 8))
              rex_used |= (8) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if (rex & 8)
        oappend ("QWORD PTR ");
      else
        {
          if ((sizeflag & 1) || bytemode == dq_mode)
            oappend ("DWORD PTR ");
          else
            oappend ("WORD PTR ");
          used_prefixes |= (prefixes & 0x200);
        }
      break;
    case z_mode:
      if ((rex & 8) || (sizeflag & 1))
        *obufp++ = 'D';
      oappend ("WORD PTR ");
      if (!(rex & 8))
        used_prefixes |= (prefixes & 0x200);
      break;
    case a_mode:
      if (sizeflag & 1)
        oappend ("QWORD PTR ");
      else
        oappend ("DWORD PTR ");
      used_prefixes |= (prefixes & 0x200);
      break;
    case d_mode:
    case d_scalar_mode:
    case d_scalar_swap_mode:
    case d_swap_mode:
    case dqd_mode:
      oappend ("DWORD PTR ");
      break;
    case q_mode:
    case q_scalar_mode:
    case q_scalar_swap_mode:
    case q_swap_mode:
      oappend ("QWORD PTR ");
      break;
    case m_mode:
      if (address_mode == mode_64bit)
        oappend ("QWORD PTR ");
      else
        oappend ("DWORD PTR ");
      break;
    case f_mode:
      if (sizeflag & 1)
        oappend ("FWORD PTR ");
      else
        oappend ("DWORD PTR ");
      used_prefixes |= (prefixes & 0x200);
      break;
    case t_mode:
      oappend ("TBYTE PTR ");
      break;
    case x_mode:
    case x_swap_mode:
    case evex_x_gscat_mode:
    case evex_x_nobcst_mode:
      if (need_vex)
        {
          switch (vex.length)
            {
            case 128:
              oappend ("XMMWORD PTR ");
              break;
            case 256:
              oappend ("YMMWORD PTR ");
              break;
            case 512:
              oappend ("ZMMWORD PTR ");
              break;
            default:
              abort ();
            }
        }
      else
        oappend ("XMMWORD PTR ");
      break;
    case xmm_mode:
      oappend ("XMMWORD PTR ");
      break;
    case ymm_mode:
      oappend ("YMMWORD PTR ");
      break;
    case xmmq_mode:
    case evex_half_bcst_xmmq_mode:
      if (!need_vex)
        abort ();

      switch (vex.length)
        {
        case 128:
          oappend ("QWORD PTR ");
          break;
        case 256:
          oappend ("XMMWORD PTR ");
          break;
        case 512:
          oappend ("YMMWORD PTR ");
          break;
        default:
          abort ();
        }
      break;
    case xmm_mb_mode:
      if (!need_vex)
        abort ();

      switch (vex.length)
        {
        case 128:
        case 256:
        case 512:
          oappend ("BYTE PTR ");
          break;
        default:
          abort ();
        }
      break;
    case xmm_mw_mode:
      if (!need_vex)
        abort ();

      switch (vex.length)
        {
        case 128:
        case 256:
        case 512:
          oappend ("WORD PTR ");
          break;
        default:
          abort ();
        }
      break;
    case xmm_md_mode:
      if (!need_vex)
        abort ();

      switch (vex.length)
        {
        case 128:
        case 256:
        case 512:
          oappend ("DWORD PTR ");
          break;
        default:
          abort ();
        }
      break;
    case xmm_mq_mode:
      if (!need_vex)
        abort ();

      switch (vex.length)
        {
        case 128:
        case 256:
        case 512:
          oappend ("QWORD PTR ");
          break;
        default:
          abort ();
        }
      break;
    case xmmdw_mode:
      if (!need_vex)
        abort ();

      switch (vex.length)
        {
        case 128:
          oappend ("WORD PTR ");
          break;
        case 256:
          oappend ("DWORD PTR ");
          break;
        case 512:
          oappend ("QWORD PTR ");
          break;
        default:
          abort ();
        }
      break;
    case xmmqd_mode:
      if (!need_vex)
        abort ();

      switch (vex.length)
        {
        case 128:
          oappend ("DWORD PTR ");
          break;
        case 256:
          oappend ("QWORD PTR ");
          break;
        case 512:
          oappend ("XMMWORD PTR ");
          break;
        default:
          abort ();
        }
      break;
    case ymmq_mode:
      if (!need_vex)
        abort ();

      switch (vex.length)
        {
        case 128:
          oappend ("QWORD PTR ");
          break;
        case 256:
          oappend ("YMMWORD PTR ");
          break;
        case 512:
          oappend ("ZMMWORD PTR ");
          break;
        default:
          abort ();
        }
      break;
    case ymmxmm_mode:
      if (!need_vex)
        abort ();

      switch (vex.length)
        {
        case 128:
        case 256:
          oappend ("XMMWORD PTR ");
          break;
        default:
          abort ();
        }
      break;
    case o_mode:
      oappend ("OWORD PTR ");
      break;
    case xmm_mdq_mode:
    case vex_w_dq_mode:
    case vex_scalar_w_dq_mode:
      if (!need_vex)
        abort ();

      if (vex.w)
        oappend ("QWORD PTR ");
      else
        oappend ("DWORD PTR ");
      break;
    case vex_vsib_d_w_dq_mode:
    case vex_vsib_q_w_dq_mode:
      if (!need_vex)
        abort ();

      if (!vex.evex)
        {
          if (vex.w)
            oappend ("QWORD PTR ");
          else
            oappend ("DWORD PTR ");
        }
      else
        {
          if (vex.length != 512)
            abort ();
          oappend ("ZMMWORD PTR ");
        }
      break;
    case vex_vsib_q_w_d_mode:
    case vex_vsib_d_w_d_mode:
      if (!need_vex || !vex.evex || vex.length != 512)
        abort ();

      oappend ("YMMWORD PTR ");

      break;
    case mask_mode:
      if (!need_vex)
        abort ();

      if (vex.w || vex.length != 128)
        abort ();
      oappend ("WORD PTR ");
      break;
    case v_bnd_mode:
    default:
      break;
    }
}

static void
OP_E_register (int bytemode, int sizeflag)
{
  int reg = modrm.rm;
  const char **names;

  {
    if (1)
      {
        if ((rex & 1))
          rex_used |= (1) | 0x40;
      }
    else
      rex_used |= 0x40;
  };
  if ((rex & 1))
    reg += 8;

  if ((sizeflag & 4) && (bytemode == b_swap_mode || bytemode == v_swap_mode))
    swap_operand ();

  switch (bytemode)
    {
    case b_mode:
    case b_swap_mode:
      {
        if (0)
          {
            if ((rex & 0))
              rex_used |= (0) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if (rex)
        names = names8rex;
      else
        names = names8;
      break;
    case w_mode:
      names = names16;
      break;
    case d_mode:
      names = names32;
      break;
    case q_mode:
      names = names64;
      break;
    case m_mode:
    case v_bnd_mode:
      names = address_mode == mode_64bit ? names64 : names32;
      break;
    case bnd_mode:
      names = names_bnd;
      break;
    case stack_v_mode:
      if (address_mode == mode_64bit && ((sizeflag & 1) || (rex & 8)))
        {
          names = names64;
          break;
        }
      bytemode = v_mode;

    case v_mode:
    case v_swap_mode:
    case dq_mode:
    case dqb_mode:
    case dqd_mode:
    case dqw_mode:
      {
        if (8)
          {
            if ((rex & 8))
              rex_used |= (8) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if (rex & 8)
        names = names64;
      else
        {
          if ((sizeflag & 1)
              || (bytemode != v_mode && bytemode != v_swap_mode))
            names = names32;
          else
            names = names16;
          used_prefixes |= (prefixes & 0x200);
        }
      break;
    case mask_mode:
      names = names_mask;
      break;
    case 0:
      return;
    default:
      oappend (dcgettext ("bfd", "<internal disassembler error>", 5));
      return;
    }
  oappend (names[reg]);
}

static void
OP_E_memory (int bytemode, int sizeflag)
{
  bfd_vma disp = 0;
  int add = (rex & 1) ? 8 : 0;
  int riprel = 0;
  int shift;

  if (vex.evex)
    {

      if (vex.b && bytemode != x_mode && bytemode != evex_half_bcst_xmmq_mode)
        {
          BadOp ();
          return;
        }
      switch (bytemode)
        {
        case vex_vsib_d_w_dq_mode:
        case vex_vsib_d_w_d_mode:
        case vex_vsib_q_w_dq_mode:
        case vex_vsib_q_w_d_mode:
        case evex_x_gscat_mode:
        case xmm_mdq_mode:
          shift = vex.w ? 3 : 2;
          break;
        case x_mode:
        case evex_half_bcst_xmmq_mode:
          if (vex.b)
            {
              shift = vex.w ? 3 : 2;
              break;
            }

        case xmmqd_mode:
        case xmmdw_mode:
        case xmmq_mode:
        case ymmq_mode:
        case evex_x_nobcst_mode:
        case x_swap_mode:
          switch (vex.length)
            {
            case 128:
              shift = 4;
              break;
            case 256:
              shift = 5;
              break;
            case 512:
              shift = 6;
              break;
            default:
              abort ();
            }
          break;
        case ymm_mode:
          shift = 5;
          break;
        case xmm_mode:
          shift = 4;
          break;
        case xmm_mq_mode:
        case q_mode:
        case q_scalar_mode:
        case q_swap_mode:
        case q_scalar_swap_mode:
          shift = 3;
          break;
        case dqd_mode:
        case xmm_md_mode:
        case d_mode:
        case d_scalar_mode:
        case d_swap_mode:
        case d_scalar_swap_mode:
          shift = 2;
          break;
        case xmm_mw_mode:
          shift = 1;
          break;
        case xmm_mb_mode:
          shift = 0;
          break;
        default:
          abort ();
        }

      if (bytemode == xmmq_mode
          || (bytemode == evex_half_bcst_xmmq_mode && !vex.b))
        shift -= 1;
      else if (bytemode == xmmqd_mode)
        shift -= 2;
      else if (bytemode == xmmdw_mode)
        shift -= 3;
    }
  else
    shift = 0;

  {
    if (1)
      {
        if ((rex & 1))
          rex_used |= (1) | 0x40;
      }
    else
      rex_used |= 0x40;
  };
  if (intel_syntax)
    intel_operand_size (bytemode, sizeflag);
  append_seg ();

  if ((sizeflag & 2) || address_mode == mode_64bit)
    {

      int havedisp;
      int havesib;
      int havebase;
      int haveindex;
      int needindex;
      int base, rbase;
      int vindex = 0;
      int scale = 0;
      int addr32flag = !((sizeflag & 2) || bytemode == v_bnd_mode
                         || bytemode == bnd_mode);
      const char **indexes64 = names64;
      const char **indexes32 = names32;

      havesib = 0;
      havebase = 1;
      haveindex = 0;
      base = modrm.rm;

      if (base == 4)
        {
          havesib = 1;
          vindex = sib.index;
          {
            if (2)
              {
                if ((rex & 2))
                  rex_used |= (2) | 0x40;
              }
            else
              rex_used |= 0x40;
          };
          if (rex & 2)
            vindex += 8;
          switch (bytemode)
            {
            case vex_vsib_d_w_dq_mode:
            case vex_vsib_d_w_d_mode:
            case vex_vsib_q_w_dq_mode:
            case vex_vsib_q_w_d_mode:
              if (!need_vex)
                abort ();
              if (vex.evex)
                {
                  if (!vex.v)
                    vindex += 16;
                }

              haveindex = 1;
              switch (vex.length)
                {
                case 128:
                  indexes64 = indexes32 = names_xmm;
                  break;
                case 256:
                  if (!vex.w || bytemode == vex_vsib_q_w_dq_mode
                      || bytemode == vex_vsib_q_w_d_mode)
                    indexes64 = indexes32 = names_ymm;
                  else
                    indexes64 = indexes32 = names_xmm;
                  break;
                case 512:
                  if (!vex.w || bytemode == vex_vsib_q_w_dq_mode
                      || bytemode == vex_vsib_q_w_d_mode)
                    indexes64 = indexes32 = names_zmm;
                  else
                    indexes64 = indexes32 = names_ymm;
                  break;
                default:
                  abort ();
                }
              break;
            default:
              haveindex = vindex != 4;
              break;
            }
          scale = sib.scale;
          base = sib.base;
          codep++;
        }
      rbase = base + add;

      switch (modrm.mod)
        {
        case 0:
          if (base == 5)
            {
              havebase = 0;
              if (address_mode == mode_64bit && !havesib)
                riprel = 1;
              disp = get32s ();
            }
          break;
        case 1:
          ((codep + 1) <= ((struct dis_private *)(the_info->private_data))
                              ->max_fetched
               ? 1
               : fetch_data ((the_info), (codep + 1)));
          disp = *codep++;
          if ((disp & 0x80) != 0)
            disp -= 0x100;
          if (vex.evex && shift > 0)
            disp <<= shift;
          break;
        case 2:
          disp = get32s ();
          break;
        }

      needindex
          = (havesib && !havebase && !haveindex && address_mode == mode_32bit);
      havedisp
          = (havebase || needindex || (havesib && (haveindex || scale != 0)));

      if (!intel_syntax)
        if (modrm.mod != 0 || base == 5)
          {
            if (havedisp || riprel)
              print_displacement (scratchbuf, disp);
            else
              print_operand_value (scratchbuf, 1, disp);
            oappend (scratchbuf);
            if (riprel)
              {
                set_op (disp, 1);
                oappend (sizeflag & 2 ? "(%rip)" : "(%eip)");
              }
          }

      if ((havebase || haveindex || riprel) && (bytemode != v_bnd_mode)
          && (bytemode != bnd_mode))
        used_prefixes |= 0x400;

      if (havedisp || (intel_syntax && riprel))
        {
          *obufp++ = open_char;
          if (intel_syntax && riprel)
            {
              set_op (disp, 1);
              oappend (sizeflag & 2 ? "rip" : "eip");
            }
          *obufp = '\0';
          if (havebase)
            oappend (address_mode == mode_64bit && !addr32flag
                         ? names64[rbase]
                         : names32[rbase]);
          if (havesib)
            {

              if (scale != 0 || needindex || haveindex
                  || (havebase && base != 4))
                {
                  if (!intel_syntax || havebase)
                    {
                      *obufp++ = separator_char;
                      *obufp = '\0';
                    }
                  if (haveindex)
                    oappend (address_mode == mode_64bit && !addr32flag
                                 ? indexes64[vindex]
                                 : indexes32[vindex]);
                  else
                    oappend (address_mode == mode_64bit && !addr32flag
                                 ? index64
                                 : index32);

                  *obufp++ = scale_char;
                  *obufp = '\0';
                  sprintf (scratchbuf, "%d", 1 << scale);
                  oappend (scratchbuf);
                }
            }
          if (intel_syntax && (disp || modrm.mod != 0 || base == 5))
            {
              if (!havedisp || (bfd_signed_vma)disp >= 0)
                {
                  *obufp++ = '+';
                  *obufp = '\0';
                }
              else if (modrm.mod != 1 && disp != -disp)
                {
                  *obufp++ = '-';
                  *obufp = '\0';
                  disp = -(bfd_signed_vma)disp;
                }

              if (havedisp)
                print_displacement (scratchbuf, disp);
              else
                print_operand_value (scratchbuf, 1, disp);
              oappend (scratchbuf);
            }

          *obufp++ = close_char;
          *obufp = '\0';
        }
      else if (intel_syntax)
        {
          if (modrm.mod != 0 || base == 5)
            {
              if (!active_seg_prefix)
                {
                  oappend (names_seg[ds_reg - es_reg]);
                  oappend (":");
                }
              print_operand_value (scratchbuf, 1, disp);
              oappend (scratchbuf);
            }
        }
    }
  else
    {

      used_prefixes |= prefixes & 0x400;
      switch (modrm.mod)
        {
        case 0:
          if (modrm.rm == 6)
            {
              disp = get16 ();
              if ((disp & 0x8000) != 0)
                disp -= 0x10000;
            }
          break;
        case 1:
          ((codep + 1) <= ((struct dis_private *)(the_info->private_data))
                              ->max_fetched
               ? 1
               : fetch_data ((the_info), (codep + 1)));
          disp = *codep++;
          if ((disp & 0x80) != 0)
            disp -= 0x100;
          break;
        case 2:
          disp = get16 ();
          if ((disp & 0x8000) != 0)
            disp -= 0x10000;
          break;
        }

      if (!intel_syntax)
        if (modrm.mod != 0 || modrm.rm == 6)
          {
            print_displacement (scratchbuf, disp);
            oappend (scratchbuf);
          }

      if (modrm.mod != 0 || modrm.rm != 6)
        {
          *obufp++ = open_char;
          *obufp = '\0';
          oappend (index16[modrm.rm]);
          if (intel_syntax && (disp || modrm.mod != 0 || modrm.rm == 6))
            {
              if ((bfd_signed_vma)disp >= 0)
                {
                  *obufp++ = '+';
                  *obufp = '\0';
                }
              else if (modrm.mod != 1)
                {
                  *obufp++ = '-';
                  *obufp = '\0';
                  disp = -(bfd_signed_vma)disp;
                }

              print_displacement (scratchbuf, disp);
              oappend (scratchbuf);
            }

          *obufp++ = close_char;
          *obufp = '\0';
        }
      else if (intel_syntax)
        {
          if (!active_seg_prefix)
            {
              oappend (names_seg[ds_reg - es_reg]);
              oappend (":");
            }
          print_operand_value (scratchbuf, 1, disp & 0xffff);
          oappend (scratchbuf);
        }
    }
  if (vex.evex && vex.b
      && (bytemode == x_mode || bytemode == evex_half_bcst_xmmq_mode))
    {
      if (vex.w || bytemode == evex_half_bcst_xmmq_mode)
        oappend ("{1to8}");
      else
        oappend ("{1to16}");
    }
}

static void
OP_E (int bytemode, int sizeflag)
{

  if (!need_modrm)
    abort ();
  codep++;

  if (modrm.mod == 3)
    OP_E_register (bytemode, sizeflag);
  else
    OP_E_memory (bytemode, sizeflag);
}

static void
OP_G (int bytemode, int sizeflag)
{
  int add = 0;
  {
    if (4)
      {
        if ((rex & 4))
          rex_used |= (4) | 0x40;
      }
    else
      rex_used |= 0x40;
  };
  if (rex & 4)
    add += 8;
  switch (bytemode)
    {
    case b_mode:
      {
        if (0)
          {
            if ((rex & 0))
              rex_used |= (0) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if (rex)
        oappend (names8rex[modrm.reg + add]);
      else
        oappend (names8[modrm.reg + add]);
      break;
    case w_mode:
      oappend (names16[modrm.reg + add]);
      break;
    case d_mode:
      oappend (names32[modrm.reg + add]);
      break;
    case q_mode:
      oappend (names64[modrm.reg + add]);
      break;
    case bnd_mode:
      oappend (names_bnd[modrm.reg]);
      break;
    case v_mode:
    case dq_mode:
    case dqb_mode:
    case dqd_mode:
    case dqw_mode:
      {
        if (8)
          {
            if ((rex & 8))
              rex_used |= (8) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if (rex & 8)
        oappend (names64[modrm.reg + add]);
      else
        {
          if ((sizeflag & 1) || bytemode != v_mode)
            oappend (names32[modrm.reg + add]);
          else
            oappend (names16[modrm.reg + add]);
          used_prefixes |= (prefixes & 0x200);
        }
      break;
    case m_mode:
      if (address_mode == mode_64bit)
        oappend (names64[modrm.reg + add]);
      else
        oappend (names32[modrm.reg + add]);
      break;
    case mask_mode:
      oappend (names_mask[modrm.reg + add]);
      break;
    default:
      oappend (dcgettext ("bfd", "<internal disassembler error>", 5));
      break;
    }
}

static bfd_vma
get64 (void)
{
  bfd_vma x;

  unsigned int a;
  unsigned int b;

  ((codep + 8) <= ((struct dis_private *)(the_info->private_data))->max_fetched
       ? 1
       : fetch_data ((the_info), (codep + 8)));
  a = *codep++ & 0xff;
  a |= (*codep++ & 0xff) << 8;
  a |= (*codep++ & 0xff) << 16;
  a |= (*codep++ & 0xff) << 24;
  b = *codep++ & 0xff;
  b |= (*codep++ & 0xff) << 8;
  b |= (*codep++ & 0xff) << 16;
  b |= (*codep++ & 0xff) << 24;
  x = a + ((bfd_vma)b << 32);

  return x;
}

static bfd_signed_vma
get32 (void)
{
  bfd_signed_vma x = 0;

  ((codep + 4) <= ((struct dis_private *)(the_info->private_data))->max_fetched
       ? 1
       : fetch_data ((the_info), (codep + 4)));
  x = *codep++ & (bfd_signed_vma)0xff;
  x |= (*codep++ & (bfd_signed_vma)0xff) << 8;
  x |= (*codep++ & (bfd_signed_vma)0xff) << 16;
  x |= (*codep++ & (bfd_signed_vma)0xff) << 24;
  return x;
}

static bfd_signed_vma
get32s (void)
{
  bfd_signed_vma x = 0;

  ((codep + 4) <= ((struct dis_private *)(the_info->private_data))->max_fetched
       ? 1
       : fetch_data ((the_info), (codep + 4)));
  x = *codep++ & (bfd_signed_vma)0xff;
  x |= (*codep++ & (bfd_signed_vma)0xff) << 8;
  x |= (*codep++ & (bfd_signed_vma)0xff) << 16;
  x |= (*codep++ & (bfd_signed_vma)0xff) << 24;

  x = (x ^ ((bfd_signed_vma)1 << 31)) - ((bfd_signed_vma)1 << 31);

  return x;
}

static int
get16 (void)
{
  int x = 0;

  ((codep + 2) <= ((struct dis_private *)(the_info->private_data))->max_fetched
       ? 1
       : fetch_data ((the_info), (codep + 2)));
  x = *codep++ & 0xff;
  x |= (*codep++ & 0xff) << 8;
  return x;
}

static void
set_op (bfd_vma op, int riprel)
{
  op_index[op_ad] = op_ad;
  if (address_mode == mode_64bit)
    {
      op_address[op_ad] = op;
      op_riprel[op_ad] = riprel;
    }
  else
    {

      op_address[op_ad] = op & 0xffffffff;
      op_riprel[op_ad] = riprel & 0xffffffff;
    }
}

static void
OP_REG (int code, int sizeflag)
{
  const char *s;
  int add;

  switch (code)
    {
    case es_reg:
    case ss_reg:
    case cs_reg:
    case ds_reg:
    case fs_reg:
    case gs_reg:
      oappend (names_seg[code - es_reg]);
      return;
    }

  {
    if (1)
      {
        if ((rex & 1))
          rex_used |= (1) | 0x40;
      }
    else
      rex_used |= 0x40;
  };
  if (rex & 1)
    add = 8;
  else
    add = 0;

  switch (code)
    {
    case ax_reg:
    case cx_reg:
    case dx_reg:
    case bx_reg:
    case sp_reg:
    case bp_reg:
    case si_reg:
    case di_reg:
      s = names16[code - ax_reg + add];
      break;
    case al_reg:
    case ah_reg:
    case cl_reg:
    case ch_reg:
    case dl_reg:
    case dh_reg:
    case bl_reg:
    case bh_reg:
      {
        if (0)
          {
            if ((rex & 0))
              rex_used |= (0) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if (rex)
        s = names8rex[code - al_reg + add];
      else
        s = names8[code - al_reg];
      break;
    case rAX_reg:
    case rCX_reg:
    case rDX_reg:
    case rBX_reg:
    case rSP_reg:
    case rBP_reg:
    case rSI_reg:
    case rDI_reg:
      if (address_mode == mode_64bit && ((sizeflag & 1) || (rex & 8)))
        {
          s = names64[code - rAX_reg + add];
          break;
        }
      code += eAX_reg - rAX_reg;

    case eAX_reg:
    case eCX_reg:
    case eDX_reg:
    case eBX_reg:
    case eSP_reg:
    case eBP_reg:
    case eSI_reg:
    case eDI_reg:
      {
        if (8)
          {
            if ((rex & 8))
              rex_used |= (8) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if (rex & 8)
        s = names64[code - eAX_reg + add];
      else
        {
          if (sizeflag & 1)
            s = names32[code - eAX_reg + add];
          else
            s = names16[code - eAX_reg + add];
          used_prefixes |= (prefixes & 0x200);
        }
      break;
    default:
      s = dcgettext ("bfd", "<internal disassembler error>", 5);
      break;
    }
  oappend (s);
}

static void
OP_IMREG (int code, int sizeflag)
{
  const char *s;

  switch (code)
    {
    case indir_dx_reg:
      if (intel_syntax)
        s = "dx";
      else
        s = "(%dx)";
      break;
    case ax_reg:
    case cx_reg:
    case dx_reg:
    case bx_reg:
    case sp_reg:
    case bp_reg:
    case si_reg:
    case di_reg:
      s = names16[code - ax_reg];
      break;
    case es_reg:
    case ss_reg:
    case cs_reg:
    case ds_reg:
    case fs_reg:
    case gs_reg:
      s = names_seg[code - es_reg];
      break;
    case al_reg:
    case ah_reg:
    case cl_reg:
    case ch_reg:
    case dl_reg:
    case dh_reg:
    case bl_reg:
    case bh_reg:
      {
        if (0)
          {
            if ((rex & 0))
              rex_used |= (0) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if (rex)
        s = names8rex[code - al_reg];
      else
        s = names8[code - al_reg];
      break;
    case eAX_reg:
    case eCX_reg:
    case eDX_reg:
    case eBX_reg:
    case eSP_reg:
    case eBP_reg:
    case eSI_reg:
    case eDI_reg:
      {
        if (8)
          {
            if ((rex & 8))
              rex_used |= (8) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if (rex & 8)
        s = names64[code - eAX_reg];
      else
        {
          if (sizeflag & 1)
            s = names32[code - eAX_reg];
          else
            s = names16[code - eAX_reg];
          used_prefixes |= (prefixes & 0x200);
        }
      break;
    case z_mode_ax_reg:
      if ((rex & 8) || (sizeflag & 1))
        s = *names32;
      else
        s = *names16;
      if (!(rex & 8))
        used_prefixes |= (prefixes & 0x200);
      break;
    default:
      s = dcgettext ("bfd", "<internal disassembler error>", 5);
      break;
    }
  oappend (s);
}

static void
OP_I (int bytemode, int sizeflag)
{
  bfd_signed_vma op;
  bfd_signed_vma mask = -1;

  switch (bytemode)
    {
    case b_mode:
      ((codep + 1)
               <= ((struct dis_private *)(the_info->private_data))->max_fetched
           ? 1
           : fetch_data ((the_info), (codep + 1)));
      op = *codep++;
      mask = 0xff;
      break;
    case q_mode:
      if (address_mode == mode_64bit)
        {
          op = get32s ();
          break;
        }

    case v_mode:
      {
        if (8)
          {
            if ((rex & 8))
              rex_used |= (8) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if (rex & 8)
        op = get32s ();
      else
        {
          if (sizeflag & 1)
            {
              op = get32 ();
              mask = 0xffffffff;
            }
          else
            {
              op = get16 ();
              mask = 0xfffff;
            }
          used_prefixes |= (prefixes & 0x200);
        }
      break;
    case w_mode:
      mask = 0xfffff;
      op = get16 ();
      break;
    case const_1_mode:
      if (intel_syntax)
        oappend ("1");
      return;
    default:
      oappend (dcgettext ("bfd", "<internal disassembler error>", 5));
      return;
    }

  op &= mask;
  scratchbuf[0] = '$';
  print_operand_value (scratchbuf + 1, 1, op);
  oappend_maybe_intel (scratchbuf);
  scratchbuf[0] = '\0';
}

static void
OP_I64 (int bytemode, int sizeflag)
{
  bfd_signed_vma op;
  bfd_signed_vma mask = -1;

  if (address_mode != mode_64bit)
    {
      OP_I (bytemode, sizeflag);
      return;
    }

  switch (bytemode)
    {
    case b_mode:
      ((codep + 1)
               <= ((struct dis_private *)(the_info->private_data))->max_fetched
           ? 1
           : fetch_data ((the_info), (codep + 1)));
      op = *codep++;
      mask = 0xff;
      break;
    case v_mode:
      {
        if (8)
          {
            if ((rex & 8))
              rex_used |= (8) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if (rex & 8)
        op = get64 ();
      else
        {
          if (sizeflag & 1)
            {
              op = get32 ();
              mask = 0xffffffff;
            }
          else
            {
              op = get16 ();
              mask = 0xfffff;
            }
          used_prefixes |= (prefixes & 0x200);
        }
      break;
    case w_mode:
      mask = 0xfffff;
      op = get16 ();
      break;
    default:
      oappend (dcgettext ("bfd", "<internal disassembler error>", 5));
      return;
    }

  op &= mask;
  scratchbuf[0] = '$';
  print_operand_value (scratchbuf + 1, 1, op);
  oappend_maybe_intel (scratchbuf);
  scratchbuf[0] = '\0';
}

static void
OP_sI (int bytemode, int sizeflag)
{
  bfd_signed_vma op;

  switch (bytemode)
    {
    case b_mode:
    case b_T_mode:
      ((codep + 1)
               <= ((struct dis_private *)(the_info->private_data))->max_fetched
           ? 1
           : fetch_data ((the_info), (codep + 1)));
      op = *codep++;
      if ((op & 0x80) != 0)
        op -= 0x100;
      if (bytemode == b_T_mode)
        {
          if (address_mode != mode_64bit || !((sizeflag & 1) || (rex & 8)))
            {

              if ((sizeflag & 1) || (rex & 8))
                op &= 0xffffffff;
              else
                op &= 0xffff;
            }
        }
      else
        {
          if (!(rex & 8))
            {
              if (sizeflag & 1)
                op &= 0xffffffff;
              else
                op &= 0xffff;
            }
        }
      break;
    case v_mode:

      if ((sizeflag & 1) || (rex & 8))
        op = get32s ();
      else
        op = get16 ();
      break;
    default:
      oappend (dcgettext ("bfd", "<internal disassembler error>", 5));
      return;
    }

  scratchbuf[0] = '$';
  print_operand_value (scratchbuf + 1, 1, op);
  oappend_maybe_intel (scratchbuf);
}

static void
OP_J (int bytemode, int sizeflag)
{
  bfd_vma disp;
  bfd_vma mask = -1;
  bfd_vma segment = 0;

  switch (bytemode)
    {
    case b_mode:
      ((codep + 1)
               <= ((struct dis_private *)(the_info->private_data))->max_fetched
           ? 1
           : fetch_data ((the_info), (codep + 1)));
      disp = *codep++;
      if ((disp & 0x80) != 0)
        disp -= 0x100;
      break;
    case v_mode:
      {
        if (8)
          {
            if ((rex & 8))
              rex_used |= (8) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if ((sizeflag & 1) || (rex & 8))
        disp = get32s ();
      else
        {
          disp = get16 ();
          if ((disp & 0x8000) != 0)
            disp -= 0x10000;

          mask = 0xffff;
          if ((prefixes & 0x200) == 0)
            segment = ((start_pc + codep - start_codep) & ~((bfd_vma)0xffff));
        }
      if (!(rex & 8))
        used_prefixes |= (prefixes & 0x200);
      break;
    default:
      oappend (dcgettext ("bfd", "<internal disassembler error>", 5));
      return;
    }
  disp = ((start_pc + (codep - start_codep) + disp) & mask) | segment;
  set_op (disp, 0);
  print_operand_value (scratchbuf, 1, disp);
  oappend (scratchbuf);
}

static void
OP_SEG (int bytemode, int sizeflag)
{
  if (bytemode == w_mode)
    oappend (names_seg[modrm.reg]);
  else
    OP_E (modrm.mod == 3 ? bytemode : w_mode, sizeflag);
}

static void
OP_DIR (int dummy __attribute__ ((__unused__)), int sizeflag)
{
  int seg, offset;

  if (sizeflag & 1)
    {
      offset = get32 ();
      seg = get16 ();
    }
  else
    {
      offset = get16 ();
      seg = get16 ();
    }
  used_prefixes |= (prefixes & 0x200);
  if (intel_syntax)
    sprintf (scratchbuf, "0x%x:0x%x", seg, offset);
  else
    sprintf (scratchbuf, "$0x%x,$0x%x", seg, offset);
  oappend (scratchbuf);
}

static void
OP_OFF (int bytemode, int sizeflag)
{
  bfd_vma off;

  if (intel_syntax && (sizeflag & 4))
    intel_operand_size (bytemode, sizeflag);
  append_seg ();

  if ((sizeflag & 2) || address_mode == mode_64bit)
    off = get32 ();
  else
    off = get16 ();

  if (intel_syntax)
    {
      if (!active_seg_prefix)
        {
          oappend (names_seg[ds_reg - es_reg]);
          oappend (":");
        }
    }
  print_operand_value (scratchbuf, 1, off);
  oappend (scratchbuf);
}

static void
OP_OFF64 (int bytemode, int sizeflag)
{
  bfd_vma off;

  if (address_mode != mode_64bit || (prefixes & 0x400))
    {
      OP_OFF (bytemode, sizeflag);
      return;
    }

  if (intel_syntax && (sizeflag & 4))
    intel_operand_size (bytemode, sizeflag);
  append_seg ();

  off = get64 ();

  if (intel_syntax)
    {
      if (!active_seg_prefix)
        {
          oappend (names_seg[ds_reg - es_reg]);
          oappend (":");
        }
    }
  print_operand_value (scratchbuf, 1, off);
  oappend (scratchbuf);
}

static void
ptr_reg (int code, int sizeflag)
{
  const char *s;

  *obufp++ = open_char;
  used_prefixes |= (prefixes & 0x400);
  if (address_mode == mode_64bit)
    {
      if (!(sizeflag & 2))
        s = names32[code - eAX_reg];
      else
        s = names64[code - eAX_reg];
    }
  else if (sizeflag & 2)
    s = names32[code - eAX_reg];
  else
    s = names16[code - eAX_reg];
  oappend (s);
  *obufp++ = close_char;
  *obufp = 0;
}

static void
OP_ESreg (int code, int sizeflag)
{
  if (intel_syntax)
    {
      switch (codep[-1])
        {
        case 0x6d:
          intel_operand_size (z_mode, sizeflag);
          break;
        case 0xa5:
        case 0xa7:
        case 0xab:
        case 0xaf:
          intel_operand_size (v_mode, sizeflag);
          break;
        default:
          intel_operand_size (b_mode, sizeflag);
        }
    }
  oappend_maybe_intel ("%es:");
  ptr_reg (code, sizeflag);
}

static void
OP_DSreg (int code, int sizeflag)
{
  if (intel_syntax)
    {
      switch (codep[-1])
        {
        case 0x6f:
          intel_operand_size (z_mode, sizeflag);
          break;
        case 0xa5:
        case 0xa7:
        case 0xad:
          intel_operand_size (v_mode, sizeflag);
          break;
        default:
          intel_operand_size (b_mode, sizeflag);
        }
    }

  if (!active_seg_prefix)
    active_seg_prefix = 0x20;
  append_seg ();
  ptr_reg (code, sizeflag);
}

static void
OP_C (int dummy __attribute__ ((__unused__)),
      int sizeflag __attribute__ ((__unused__)))
{
  int add;
  if (rex & 4)
    {
      {
        if (4)
          {
            if ((rex & 4))
              rex_used |= (4) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      add = 8;
    }
  else if (address_mode != mode_64bit && (prefixes & 4))
    {
      all_prefixes[last_lock_prefix] = 0;
      used_prefixes |= 4;
      add = 8;
    }
  else
    add = 0;
  sprintf (scratchbuf, "%%cr%d", modrm.reg + add);
  oappend_maybe_intel (scratchbuf);
}

static void
OP_D (int dummy __attribute__ ((__unused__)),
      int sizeflag __attribute__ ((__unused__)))
{
  int add;
  {
    if (4)
      {
        if ((rex & 4))
          rex_used |= (4) | 0x40;
      }
    else
      rex_used |= 0x40;
  };
  if (rex & 4)
    add = 8;
  else
    add = 0;
  if (intel_syntax)
    sprintf (scratchbuf, "db%d", modrm.reg + add);
  else
    sprintf (scratchbuf, "%%db%d", modrm.reg + add);
  oappend (scratchbuf);
}

static void
OP_T (int dummy __attribute__ ((__unused__)),
      int sizeflag __attribute__ ((__unused__)))
{
  sprintf (scratchbuf, "%%tr%d", modrm.reg);
  oappend_maybe_intel (scratchbuf);
}

static void
OP_R (int bytemode, int sizeflag)
{
  if (modrm.mod == 3)
    OP_E (bytemode, sizeflag);
  else
    BadOp ();
}

static void
OP_MMX (int bytemode __attribute__ ((__unused__)),
        int sizeflag __attribute__ ((__unused__)))
{
  int reg = modrm.reg;
  const char **names;

  used_prefixes |= (prefixes & 0x200);
  if (prefixes & 0x200)
    {
      names = names_xmm;
      {
        if (4)
          {
            if ((rex & 4))
              rex_used |= (4) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if (rex & 4)
        reg += 8;
    }
  else
    names = names_mm;
  oappend (names[reg]);
}

static void
OP_XMM (int bytemode, int sizeflag __attribute__ ((__unused__)))
{
  int reg = modrm.reg;
  const char **names;

  {
    if (4)
      {
        if ((rex & 4))
          rex_used |= (4) | 0x40;
      }
    else
      rex_used |= 0x40;
  };
  if (rex & 4)
    reg += 8;
  if (vex.evex)
    {
      if (!vex.r)
        reg += 16;
    }

  if (need_vex && bytemode != xmm_mode && bytemode != xmmq_mode
      && bytemode != evex_half_bcst_xmmq_mode && bytemode != ymm_mode
      && bytemode != scalar_mode)
    {
      switch (vex.length)
        {
        case 128:
          names = names_xmm;
          break;
        case 256:
          if (vex.w || (bytemode != vex_vsib_q_w_dq_mode
                        && bytemode != vex_vsib_q_w_d_mode))
            names = names_ymm;
          else
            names = names_xmm;
          break;
        case 512:
          names = names_zmm;
          break;
        default:
          abort ();
        }
    }
  else if (bytemode == xmmq_mode || bytemode == evex_half_bcst_xmmq_mode)
    {
      switch (vex.length)
        {
        case 128:
        case 256:
          names = names_xmm;
          break;
        case 512:
          names = names_ymm;
          break;
        default:
          abort ();
        }
    }
  else if (bytemode == ymm_mode)
    names = names_ymm;
  else
    names = names_xmm;
  oappend (names[reg]);
}

static void
OP_EM (int bytemode, int sizeflag)
{
  int reg;
  const char **names;

  if (modrm.mod != 3)
    {
      if (intel_syntax && (bytemode == v_mode || bytemode == v_swap_mode))
        {
          bytemode = (prefixes & 0x200) ? x_mode : q_mode;
          used_prefixes |= (prefixes & 0x200);
        }
      OP_E (bytemode, sizeflag);
      return;
    }

  if ((sizeflag & 4) && bytemode == v_swap_mode)
    swap_operand ();

  if (!need_modrm)
    abort ();
  codep++;
  used_prefixes |= (prefixes & 0x200);
  reg = modrm.rm;
  if (prefixes & 0x200)
    {
      names = names_xmm;
      {
        if (1)
          {
            if ((rex & 1))
              rex_used |= (1) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if (rex & 1)
        reg += 8;
    }
  else
    names = names_mm;
  oappend (names[reg]);
}

static void
OP_EMC (int bytemode, int sizeflag)
{
  if (modrm.mod != 3)
    {
      if (intel_syntax && bytemode == v_mode)
        {
          bytemode = (prefixes & 0x200) ? x_mode : q_mode;
          used_prefixes |= (prefixes & 0x200);
        }
      OP_E (bytemode, sizeflag);
      return;
    }

  if (!need_modrm)
    abort ();
  codep++;
  used_prefixes |= (prefixes & 0x200);
  oappend (names_mm[modrm.rm]);
}

static void
OP_MXC (int bytemode __attribute__ ((__unused__)),
        int sizeflag __attribute__ ((__unused__)))
{
  used_prefixes |= (prefixes & 0x200);
  oappend (names_mm[modrm.reg]);
}

static void
OP_EX (int bytemode, int sizeflag)
{
  int reg;
  const char **names;

  if (!need_modrm)
    abort ();
  codep++;

  if (modrm.mod != 3)
    {
      OP_E_memory (bytemode, sizeflag);
      return;
    }

  reg = modrm.rm;
  {
    if (1)
      {
        if ((rex & 1))
          rex_used |= (1) | 0x40;
      }
    else
      rex_used |= 0x40;
  };
  if (rex & 1)
    reg += 8;
  if (vex.evex)
    {
      {
        if (2)
          {
            if ((rex & 2))
              rex_used |= (2) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if ((rex & 2))
        reg += 16;
    }

  if ((sizeflag & 4)
      && (bytemode == x_swap_mode || bytemode == d_swap_mode
          || bytemode == d_scalar_swap_mode || bytemode == q_swap_mode
          || bytemode == q_scalar_swap_mode))
    swap_operand ();

  if (need_vex && bytemode != xmm_mode && bytemode != xmmdw_mode
      && bytemode != xmmqd_mode && bytemode != xmm_mb_mode
      && bytemode != xmm_mw_mode && bytemode != xmm_md_mode
      && bytemode != xmm_mq_mode && bytemode != xmm_mdq_mode
      && bytemode != xmmq_mode && bytemode != evex_half_bcst_xmmq_mode
      && bytemode != ymm_mode && bytemode != d_scalar_mode
      && bytemode != d_scalar_swap_mode && bytemode != q_scalar_mode
      && bytemode != q_scalar_swap_mode && bytemode != vex_scalar_w_dq_mode)
    {
      switch (vex.length)
        {
        case 128:
          names = names_xmm;
          break;
        case 256:
          names = names_ymm;
          break;
        case 512:
          names = names_zmm;
          break;
        default:
          abort ();
        }
    }
  else if (bytemode == xmmq_mode || bytemode == evex_half_bcst_xmmq_mode)
    {
      switch (vex.length)
        {
        case 128:
        case 256:
          names = names_xmm;
          break;
        case 512:
          names = names_ymm;
          break;
        default:
          abort ();
        }
    }
  else if (bytemode == ymm_mode)
    names = names_ymm;
  else
    names = names_xmm;
  oappend (names[reg]);
}

static void
OP_MS (int bytemode, int sizeflag)
{
  if (modrm.mod == 3)
    OP_EM (bytemode, sizeflag);
  else
    BadOp ();
}

static void
OP_XS (int bytemode, int sizeflag)
{
  if (modrm.mod == 3)
    OP_EX (bytemode, sizeflag);
  else
    BadOp ();
}

static void
OP_M (int bytemode, int sizeflag)
{
  if (modrm.mod == 3)

    BadOp ();
  else
    OP_E (bytemode, sizeflag);
}

static void
OP_0f07 (int bytemode, int sizeflag)
{
  if (modrm.mod != 3 || modrm.rm != 0)
    BadOp ();
  else
    OP_E (bytemode, sizeflag);
}

static void
NOP_Fixup1 (int bytemode, int sizeflag)
{
  if ((prefixes & 0x200) != 0
      || (rex != 0 && rex != 0x48 && address_mode == mode_64bit))
    OP_REG (bytemode, sizeflag);
  else
    strcpy (obuf, "nop");
}

static void
NOP_Fixup2 (int bytemode, int sizeflag)
{
  if ((prefixes & 0x200) != 0
      || (rex != 0 && rex != 0x48 && address_mode == mode_64bit))
    OP_IMREG (bytemode, sizeflag);
}

static const char *const Suffix3DNow[] = {
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  "pi2fw",     "pi2fd",     ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), "pf2iw",     "pf2id",
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  "pfnacc",    ((void *)0), ((void *)0), ((void *)0), "pfpnacc",   ((void *)0),
  "pfcmpge",   ((void *)0), ((void *)0), ((void *)0), "pfmin",     ((void *)0),
  "pfrcp",     "pfrsqrt",   ((void *)0), ((void *)0), "pfsub",     ((void *)0),
  ((void *)0), ((void *)0), "pfadd",     ((void *)0), "pfcmpgt",   ((void *)0),
  ((void *)0), ((void *)0), "pfmax",     ((void *)0), "pfrcpit1",  "pfrsqit1",
  ((void *)0), ((void *)0), "pfsubr",    ((void *)0), ((void *)0), ((void *)0),
  "pfacc",     ((void *)0), "pfcmpeq",   ((void *)0), ((void *)0), ((void *)0),
  "pfmul",     ((void *)0), "pfrcpit2",  "pmulhrw",   ((void *)0), ((void *)0),
  ((void *)0), "pswapd",    ((void *)0), ((void *)0), ((void *)0), "pavgusb",
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0), ((void *)0),
  ((void *)0), ((void *)0), ((void *)0), ((void *)0),
};

static void
OP_3DNowSuffix (int bytemode __attribute__ ((__unused__)),
                int sizeflag __attribute__ ((__unused__)))
{
  const char *mnemonic;

  ((codep + 1) <= ((struct dis_private *)(the_info->private_data))->max_fetched
       ? 1
       : fetch_data ((the_info), (codep + 1)));

  obufp = mnemonicendp;
  mnemonic = Suffix3DNow[*codep++ & 0xff];
  if (mnemonic)
    oappend (mnemonic);
  else
    {

      op_out[0][0] = '\0';
      op_out[1][0] = '\0';
      BadOp ();
    }
  mnemonicendp = obufp;
}

static struct op simd_cmp_op[] = { { ("eq"), (sizeof ("eq") - 1) },
                                   { ("lt"), (sizeof ("lt") - 1) },
                                   { ("le"), (sizeof ("le") - 1) },
                                   { ("unord"), (sizeof ("unord") - 1) },
                                   { ("neq"), (sizeof ("neq") - 1) },
                                   { ("nlt"), (sizeof ("nlt") - 1) },
                                   { ("nle"), (sizeof ("nle") - 1) },
                                   { ("ord"), (sizeof ("ord") - 1) } };

static void
CMP_Fixup (int bytemode __attribute__ ((__unused__)),
           int sizeflag __attribute__ ((__unused__)))
{
  unsigned int cmp_type;

  ((codep + 1) <= ((struct dis_private *)(the_info->private_data))->max_fetched
       ? 1
       : fetch_data ((the_info), (codep + 1)));
  cmp_type = *codep++ & 0xff;
  if (cmp_type < (sizeof (simd_cmp_op) / sizeof ((simd_cmp_op)[0])))
    {
      char suffix[3];
      char *p = mnemonicendp - 2;
      suffix[0] = p[0];
      suffix[1] = p[1];
      suffix[2] = '\0';
      sprintf (p, "%s%s", simd_cmp_op[cmp_type].name, suffix);
      mnemonicendp += simd_cmp_op[cmp_type].len;
    }
  else
    {

      scratchbuf[0] = '$';
      print_operand_value (scratchbuf + 1, 1, cmp_type);
      oappend_maybe_intel (scratchbuf);
      scratchbuf[0] = '\0';
    }
}

static void
OP_Mwait (int bytemode __attribute__ ((__unused__)),
          int sizeflag __attribute__ ((__unused__)))
{

  if (!intel_syntax)
    {
      const char **names = (address_mode == mode_64bit ? names64 : names32);
      strcpy (op_out[0], names[0]);
      strcpy (op_out[1], names[1]);
      two_source_ops = 1;
    }

  if (!need_modrm)
    abort ();
  codep++;
}

static void
OP_Monitor (int bytemode __attribute__ ((__unused__)),
            int sizeflag __attribute__ ((__unused__)))
{

  if (!intel_syntax)
    {
      const char **op1_names;
      const char **names = (address_mode == mode_64bit ? names64 : names32);

      if (!(prefixes & 0x400))
        op1_names = (address_mode == mode_16bit ? names16 : names);
      else
        {

          all_prefixes[last_addr_prefix] = 0;
          op1_names = (address_mode != mode_32bit ? names32 : names16);
          used_prefixes |= 0x400;
        }
      strcpy (op_out[0], op1_names[0]);
      strcpy (op_out[1], names[1]);
      strcpy (op_out[2], names[2]);
      two_source_ops = 1;
    }

  if (!need_modrm)
    abort ();
  codep++;
}

static void
BadOp (void)
{

  codep = insn_codep + 1;
  oappend ("(bad)");
}

static void
REP_Fixup (int bytemode, int sizeflag)
{

  if (prefixes & 1)
    all_prefixes[last_repz_prefix] = (0xf3 | 0x100);

  switch (bytemode)
    {
    case al_reg:
    case eAX_reg:
    case indir_dx_reg:
      OP_IMREG (bytemode, sizeflag);
      break;
    case eDI_reg:
      OP_ESreg (bytemode, sizeflag);
      break;
    case eSI_reg:
      OP_DSreg (bytemode, sizeflag);
      break;
    default:
      abort ();
      break;
    }
}

static void
BND_Fixup (int bytemode __attribute__ ((__unused__)),
           int sizeflag __attribute__ ((__unused__)))
{
  if (prefixes & 2)
    all_prefixes[last_repnz_prefix] = (0xf2 | 0x400);
}

static void
HLE_Fixup1 (int bytemode, int sizeflag)
{
  if (modrm.mod != 3 && (prefixes & 4) != 0)
    {
      if (prefixes & 1)
        all_prefixes[last_repz_prefix] = (0xf3 | 0x400);
      if (prefixes & 2)
        all_prefixes[last_repnz_prefix] = (0xf2 | 0x200);
    }

  OP_E (bytemode, sizeflag);
}

static void
HLE_Fixup2 (int bytemode, int sizeflag)
{
  if (modrm.mod != 3)
    {
      if (prefixes & 1)
        all_prefixes[last_repz_prefix] = (0xf3 | 0x400);
      if (prefixes & 2)
        all_prefixes[last_repnz_prefix] = (0xf2 | 0x200);
    }

  OP_E (bytemode, sizeflag);
}

static void
HLE_Fixup3 (int bytemode, int sizeflag)
{
  if (modrm.mod != 3 && last_repz_prefix > last_repnz_prefix
      && (prefixes & 1) != 0)
    all_prefixes[last_repz_prefix] = (0xf3 | 0x400);

  OP_E (bytemode, sizeflag);
}

static void
CMPXCHG8B_Fixup (int bytemode, int sizeflag)
{
  {
    if (8)
      {
        if ((rex & 8))
          rex_used |= (8) | 0x40;
      }
    else
      rex_used |= 0x40;
  };
  if (rex & 8)
    {

      char *p = mnemonicendp - 2;
      mnemonicendp = stpcpy (p, "16b");
      bytemode = o_mode;
    }
  else if ((prefixes & 4) != 0)
    {
      if (prefixes & 1)
        all_prefixes[last_repz_prefix] = (0xf3 | 0x400);
      if (prefixes & 2)
        all_prefixes[last_repnz_prefix] = (0xf2 | 0x200);
    }

  OP_M (bytemode, sizeflag);
}

static void
XMM_Fixup (int reg, int sizeflag __attribute__ ((__unused__)))
{
  const char **names;

  if (need_vex)
    {
      switch (vex.length)
        {
        case 128:
          names = names_xmm;
          break;
        case 256:
          names = names_ymm;
          break;
        default:
          abort ();
        }
    }
  else
    names = names_xmm;
  oappend (names[reg]);
}

static void
CRC32_Fixup (int bytemode, int sizeflag)
{

  char *p = mnemonicendp;

  switch (bytemode)
    {
    case b_mode:
      if (intel_syntax)
        goto skip;

      *p++ = 'b';
      break;
    case v_mode:
      if (intel_syntax)
        goto skip;

      {
        if (8)
          {
            if ((rex & 8))
              rex_used |= (8) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if (rex & 8)
        *p++ = 'q';
      else
        {
          if (sizeflag & 1)
            *p++ = 'l';
          else
            *p++ = 'w';
          used_prefixes |= (prefixes & 0x200);
        }
      break;
    default:
      oappend (dcgettext ("bfd", "<internal disassembler error>", 5));
      break;
    }
  mnemonicendp = p;
  *p = '\0';

skip:
  if (modrm.mod == 3)
    {
      int add;

      if (!need_modrm)
        abort ();
      codep++;

      {
        if (1)
          {
            if ((rex & 1))
              rex_used |= (1) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      add = (rex & 1) ? 8 : 0;
      if (bytemode == b_mode)
        {
          {
            if (0)
              {
                if ((rex & 0))
                  rex_used |= (0) | 0x40;
              }
            else
              rex_used |= 0x40;
          };
          if (rex)
            oappend (names8rex[modrm.rm + add]);
          else
            oappend (names8[modrm.rm + add]);
        }
      else
        {
          {
            if (8)
              {
                if ((rex & 8))
                  rex_used |= (8) | 0x40;
              }
            else
              rex_used |= 0x40;
          };
          if (rex & 8)
            oappend (names64[modrm.rm + add]);
          else if ((prefixes & 0x200))
            oappend (names16[modrm.rm + add]);
          else
            oappend (names32[modrm.rm + add]);
        }
    }
  else
    OP_E (bytemode, sizeflag);
}

static void
FXSAVE_Fixup (int bytemode, int sizeflag)
{

  {
    if (8)
      {
        if ((rex & 8))
          rex_used |= (8) | 0x40;
      }
    else
      rex_used |= 0x40;
  };
  if (rex & 8)
    {
      char *p = mnemonicendp;
      *p++ = '6';
      *p++ = '4';
      *p = '\0';
      mnemonicendp = p;
    }
  OP_M (bytemode, sizeflag);
}

static void
OP_VEX (int bytemode, int sizeflag __attribute__ ((__unused__)))
{
  int reg;
  const char **names;

  if (!need_vex)
    abort ();

  if (!need_vex_reg)
    return;

  reg = vex.register_specifier;
  if (vex.evex)
    {
      if (!vex.v)
        reg += 16;
    }

  if (bytemode == vex_scalar_mode)
    {
      oappend (names_xmm[reg]);
      return;
    }

  switch (vex.length)
    {
    case 128:
      switch (bytemode)
        {
        case vex_mode:
        case vex128_mode:
        case vex_vsib_q_w_dq_mode:
        case vex_vsib_q_w_d_mode:
          names = names_xmm;
          break;
        case dq_mode:
          if (vex.w)
            names = names64;
          else
            names = names32;
          break;
        case mask_mode:
          names = names_mask;
          break;
        default:
          abort ();
          return;
        }
      break;
    case 256:
      switch (bytemode)
        {
        case vex_mode:
        case vex256_mode:
          names = names_ymm;
          break;
        case vex_vsib_q_w_dq_mode:
        case vex_vsib_q_w_d_mode:
          names = vex.w ? names_ymm : names_xmm;
          break;
        case mask_mode:
          names = names_mask;
          break;
        default:
          abort ();
          return;
        }
      break;
    case 512:
      names = names_zmm;
      break;
    default:
      abort ();
      break;
    }
  oappend (names[reg]);
}

static unsigned char
get_vex_imm8 (int sizeflag, int opnum)
{
  int bytes_before_imm = 0;

  if (modrm.mod != 3)
    {

      if ((sizeflag & 2) || address_mode == mode_64bit)
        {

          int base = modrm.rm;

          if (base == 4)
            {
              ((codep + 1) <= ((struct dis_private *)(the_info->private_data))
                                  ->max_fetched
                   ? 1
                   : fetch_data ((the_info), (codep + 1)));
              base = *codep & 7;

              if (opnum == 0)
                bytes_before_imm++;
            }

          if (opnum == 0)
            {
              switch (modrm.mod)
                {
                case 0:

                  if (base != 5)

                    break;
                case 2:

                  bytes_before_imm += 4;
                  break;
                case 1:

                  bytes_before_imm++;
                  break;
                }
            }
        }
      else
        {

          if (opnum == 0)
            {
              switch (modrm.mod)
                {
                case 0:

                  if (modrm.rm != 6)

                    break;
                case 2:

                  bytes_before_imm += 2;
                  break;
                case 1:

                  if (opnum == 0)
                    bytes_before_imm++;

                  break;
                }
            }
        }
    }

  ((codep + bytes_before_imm + 1)
           <= ((struct dis_private *)(the_info->private_data))->max_fetched
       ? 1
       : fetch_data ((the_info), (codep + bytes_before_imm + 1)));
  return codep[bytes_before_imm];
}

static void
OP_EX_VexReg (int bytemode, int sizeflag, int reg)
{
  const char **names;

  if (reg == -1 && modrm.mod != 3)
    {
      OP_E_memory (bytemode, sizeflag);
      return;
    }
  else
    {
      if (reg == -1)
        {
          reg = modrm.rm;
          {
            if (1)
              {
                if ((rex & 1))
                  rex_used |= (1) | 0x40;
              }
            else
              rex_used |= 0x40;
          };
          if (rex & 1)
            reg += 8;
        }
      else if (reg > 7 && address_mode != mode_64bit)
        BadOp ();
    }

  switch (vex.length)
    {
    case 128:
      names = names_xmm;
      break;
    case 256:
      names = names_ymm;
      break;
    default:
      abort ();
    }
  oappend (names[reg]);
}

static void
OP_EX_VexImmW (int bytemode, int sizeflag)
{
  int reg = -1;
  static unsigned char vex_imm8;

  if (vex_w_done == 0)
    {
      vex_w_done = 1;

      if (!need_modrm)
        abort ();
      codep++;

      vex_imm8 = get_vex_imm8 (sizeflag, 0);

      if (vex.w)
        reg = vex_imm8 >> 4;

      OP_EX_VexReg (bytemode, sizeflag, reg);
    }
  else if (vex_w_done == 1)
    {
      vex_w_done = 2;

      if (!vex.w)
        reg = vex_imm8 >> 4;

      OP_EX_VexReg (bytemode, sizeflag, reg);
    }
  else
    {

      scratchbuf[0] = '$';
      print_operand_value (scratchbuf + 1, 1, vex_imm8 & 0xf);
      oappend_maybe_intel (scratchbuf);
      scratchbuf[0] = '\0';
      codep++;
    }
}

static void
OP_Vex_2src (int bytemode, int sizeflag)
{
  if (modrm.mod == 3)
    {
      int reg = modrm.rm;
      {
        if (1)
          {
            if ((rex & 1))
              rex_used |= (1) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if (rex & 1)
        reg += 8;
      oappend (names_xmm[reg]);
    }
  else
    {
      if (intel_syntax && (bytemode == v_mode || bytemode == v_swap_mode))
        {
          bytemode = (prefixes & 0x200) ? x_mode : q_mode;
          used_prefixes |= (prefixes & 0x200);
        }
      OP_E (bytemode, sizeflag);
    }
}

static void
OP_Vex_2src_1 (int bytemode, int sizeflag)
{
  if (modrm.mod == 3)
    {

      if (!need_modrm)
        abort ();
      codep++;
    }

  if (vex.w)
    oappend (names_xmm[vex.register_specifier]);
  else
    OP_Vex_2src (bytemode, sizeflag);
}

static void
OP_Vex_2src_2 (int bytemode, int sizeflag)
{
  if (vex.w)
    OP_Vex_2src (bytemode, sizeflag);
  else
    oappend (names_xmm[vex.register_specifier]);
}

static void
OP_EX_VexW (int bytemode, int sizeflag)
{
  int reg = -1;

  if (!vex_w_done)
    {
      vex_w_done = 1;

      if (!need_modrm)
        abort ();
      codep++;

      if (vex.w)
        reg = get_vex_imm8 (sizeflag, 0) >> 4;
    }
  else
    {
      if (!vex.w)
        reg = get_vex_imm8 (sizeflag, 1) >> 4;
    }

  OP_EX_VexReg (bytemode, sizeflag, reg);
}

static void
VEXI4_Fixup (int bytemode __attribute__ ((__unused__)),
             int sizeflag __attribute__ ((__unused__)))
{

  ((codep + 1) <= ((struct dis_private *)(the_info->private_data))->max_fetched
       ? 1
       : fetch_data ((the_info), (codep + 1)));
  if (*codep++ & 0xf)
    BadOp ();
}

static void
OP_REG_VexI4 (int bytemode, int sizeflag __attribute__ ((__unused__)))
{
  int reg;
  const char **names;

  ((codep + 1) <= ((struct dis_private *)(the_info->private_data))->max_fetched
       ? 1
       : fetch_data ((the_info), (codep + 1)));
  reg = *codep++;

  if (bytemode != x_mode)
    abort ();

  if (reg & 0xf)
    BadOp ();

  reg >>= 4;
  if (reg > 7 && address_mode != mode_64bit)
    BadOp ();

  switch (vex.length)
    {
    case 128:
      names = names_xmm;
      break;
    case 256:
      names = names_ymm;
      break;
    default:
      abort ();
    }
  oappend (names[reg]);
}

static void
OP_XMM_VexW (int bytemode, int sizeflag)
{

  rex &= ~8;
  OP_XMM (bytemode, sizeflag);
}

static void
OP_EX_Vex (int bytemode, int sizeflag)
{
  if (modrm.mod != 3)
    {
      if (vex.register_specifier != 0)
        BadOp ();
      need_vex_reg = 0;
    }
  OP_EX (bytemode, sizeflag);
}

static void
OP_XMM_Vex (int bytemode, int sizeflag)
{
  if (modrm.mod != 3)
    {
      if (vex.register_specifier != 0)
        BadOp ();
      need_vex_reg = 0;
    }
  OP_XMM (bytemode, sizeflag);
}

static void
VZERO_Fixup (int bytemode __attribute__ ((__unused__)),
             int sizeflag __attribute__ ((__unused__)))
{
  switch (vex.length)
    {
    case 128:
      mnemonicendp = stpcpy (obuf, "vzeroupper");
      break;
    case 256:
      mnemonicendp = stpcpy (obuf, "vzeroall");
      break;
    default:
      abort ();
    }
}

static struct op vex_cmp_op[] = {
  { ("eq"), (sizeof ("eq") - 1) },
  { ("lt"), (sizeof ("lt") - 1) },
  { ("le"), (sizeof ("le") - 1) },
  { ("unord"), (sizeof ("unord") - 1) },
  { ("neq"), (sizeof ("neq") - 1) },
  { ("nlt"), (sizeof ("nlt") - 1) },
  { ("nle"), (sizeof ("nle") - 1) },
  { ("ord"), (sizeof ("ord") - 1) },
  { ("eq_uq"), (sizeof ("eq_uq") - 1) },
  { ("nge"), (sizeof ("nge") - 1) },
  { ("ngt"), (sizeof ("ngt") - 1) },
  { ("false"), (sizeof ("false") - 1) },
  { ("neq_oq"), (sizeof ("neq_oq") - 1) },
  { ("ge"), (sizeof ("ge") - 1) },
  { ("gt"), (sizeof ("gt") - 1) },
  { ("true"), (sizeof ("true") - 1) },
  { ("eq_os"), (sizeof ("eq_os") - 1) },
  { ("lt_oq"), (sizeof ("lt_oq") - 1) },
  { ("le_oq"), (sizeof ("le_oq") - 1) },
  { ("unord_s"), (sizeof ("unord_s") - 1) },
  { ("neq_us"), (sizeof ("neq_us") - 1) },
  { ("nlt_uq"), (sizeof ("nlt_uq") - 1) },
  { ("nle_uq"), (sizeof ("nle_uq") - 1) },
  { ("ord_s"), (sizeof ("ord_s") - 1) },
  { ("eq_us"), (sizeof ("eq_us") - 1) },
  { ("nge_uq"), (sizeof ("nge_uq") - 1) },
  { ("ngt_uq"), (sizeof ("ngt_uq") - 1) },
  { ("false_os"), (sizeof ("false_os") - 1) },
  { ("neq_os"), (sizeof ("neq_os") - 1) },
  { ("ge_oq"), (sizeof ("ge_oq") - 1) },
  { ("gt_oq"), (sizeof ("gt_oq") - 1) },
  { ("true_us"), (sizeof ("true_us") - 1) },
};

static void
VCMP_Fixup (int bytemode __attribute__ ((__unused__)),
            int sizeflag __attribute__ ((__unused__)))
{
  unsigned int cmp_type;

  ((codep + 1) <= ((struct dis_private *)(the_info->private_data))->max_fetched
       ? 1
       : fetch_data ((the_info), (codep + 1)));
  cmp_type = *codep++ & 0xff;
  if (cmp_type < (sizeof (vex_cmp_op) / sizeof ((vex_cmp_op)[0])))
    {
      char suffix[3];
      char *p = mnemonicendp - 2;
      suffix[0] = p[0];
      suffix[1] = p[1];
      suffix[2] = '\0';
      sprintf (p, "%s%s", vex_cmp_op[cmp_type].name, suffix);
      mnemonicendp += vex_cmp_op[cmp_type].len;
    }
  else
    {

      scratchbuf[0] = '$';
      print_operand_value (scratchbuf + 1, 1, cmp_type);
      oappend_maybe_intel (scratchbuf);
      scratchbuf[0] = '\0';
    }
}

static void
VPCMP_Fixup (int bytemode __attribute__ ((__unused__)),
             int sizeflag __attribute__ ((__unused__)))
{
  unsigned int cmp_type;

  if (!vex.evex)
    abort ();

  ((codep + 1) <= ((struct dis_private *)(the_info->private_data))->max_fetched
       ? 1
       : fetch_data ((the_info), (codep + 1)));
  cmp_type = *codep++ & 0xff;

  if (cmp_type < (sizeof (simd_cmp_op) / sizeof ((simd_cmp_op)[0]))
      && cmp_type != 3 && cmp_type != 7)
    {
      char suffix[3];
      char *p = mnemonicendp - 2;

      if (p[0] == 'p')
        {
          p++;
          suffix[0] = p[0];
          suffix[1] = '\0';
        }
      else
        {
          suffix[0] = p[0];
          suffix[1] = p[1];
          suffix[2] = '\0';
        }

      sprintf (p, "%s%s", simd_cmp_op[cmp_type].name, suffix);
      mnemonicendp += simd_cmp_op[cmp_type].len;
    }
  else
    {

      scratchbuf[0] = '$';
      print_operand_value (scratchbuf + 1, 1, cmp_type);
      oappend_maybe_intel (scratchbuf);
      scratchbuf[0] = '\0';
    }
}

static const struct op pclmul_op[] = { { ("lql"), (sizeof ("lql") - 1) },
                                       { ("hql"), (sizeof ("hql") - 1) },
                                       { ("lqh"), (sizeof ("lqh") - 1) },
                                       { ("hqh"), (sizeof ("hqh") - 1) } };

static void
PCLMUL_Fixup (int bytemode __attribute__ ((__unused__)),
              int sizeflag __attribute__ ((__unused__)))
{
  unsigned int pclmul_type;

  ((codep + 1) <= ((struct dis_private *)(the_info->private_data))->max_fetched
       ? 1
       : fetch_data ((the_info), (codep + 1)));
  pclmul_type = *codep++ & 0xff;
  switch (pclmul_type)
    {
    case 0x10:
      pclmul_type = 2;
      break;
    case 0x11:
      pclmul_type = 3;
      break;
    default:
      break;
    }
  if (pclmul_type < (sizeof (pclmul_op) / sizeof ((pclmul_op)[0])))
    {
      char suffix[4];
      char *p = mnemonicendp - 3;
      suffix[0] = p[0];
      suffix[1] = p[1];
      suffix[2] = p[2];
      suffix[3] = '\0';
      sprintf (p, "%s%s", pclmul_op[pclmul_type].name, suffix);
      mnemonicendp += pclmul_op[pclmul_type].len;
    }
  else
    {

      scratchbuf[0] = '$';
      print_operand_value (scratchbuf + 1, 1, pclmul_type);
      oappend_maybe_intel (scratchbuf);
      scratchbuf[0] = '\0';
    }
}

static void
MOVBE_Fixup (int bytemode, int sizeflag)
{

  char *p = mnemonicendp;

  switch (bytemode)
    {
    case v_mode:
      if (intel_syntax)
        goto skip;

      {
        if (8)
          {
            if ((rex & 8))
              rex_used |= (8) | 0x40;
          }
        else
          rex_used |= 0x40;
      };
      if (sizeflag & 4)
        {
          if (rex & 8)
            *p++ = 'q';
          else
            {
              if (sizeflag & 1)
                *p++ = 'l';
              else
                *p++ = 'w';
              used_prefixes |= (prefixes & 0x200);
            }
        }
      break;
    default:
      oappend (dcgettext ("bfd", "<internal disassembler error>", 5));
      break;
    }
  mnemonicendp = p;
  *p = '\0';

skip:
  OP_M (bytemode, sizeflag);
}

static void
OP_LWPCB_E (int bytemode __attribute__ ((__unused__)),
            int sizeflag __attribute__ ((__unused__)))
{
  int reg;
  const char **names;

  if (!need_modrm)
    abort ();
  codep++;

  if (vex.w)
    names = names64;
  else
    names = names32;

  reg = modrm.rm;
  {
    if (1)
      {
        if ((rex & 1))
          rex_used |= (1) | 0x40;
      }
    else
      rex_used |= 0x40;
  };
  if (rex & 1)
    reg += 8;

  oappend (names[reg]);
}

static void
OP_LWP_E (int bytemode __attribute__ ((__unused__)),
          int sizeflag __attribute__ ((__unused__)))
{
  const char **names;

  if (vex.w)
    names = names64;
  else
    names = names32;

  oappend (names[vex.register_specifier]);
}

static void
OP_Mask (int bytemode, int sizeflag __attribute__ ((__unused__)))
{
  if (!vex.evex || bytemode != mask_mode)
    abort ();

  {
    if (4)
      {
        if ((rex & 4))
          rex_used |= (4) | 0x40;
      }
    else
      rex_used |= 0x40;
  };
  if ((rex & 4) != 0 || !vex.r)
    {
      BadOp ();
      return;
    }

  oappend (names_mask[modrm.reg]);
}

static void
OP_Rounding (int bytemode, int sizeflag __attribute__ ((__unused__)))
{
  if (!vex.evex
      || (bytemode != evex_rounding_mode && bytemode != evex_sae_mode))
    abort ();
  if (modrm.mod == 3 && vex.b)
    switch (bytemode)
      {
      case evex_rounding_mode:
        oappend (names_rounding[vex.ll]);
        break;
      case evex_sae_mode:
        oappend ("{sae}");
        break;
      default:
        break;
      }
}
