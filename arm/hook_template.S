#8 byte align stack.
.syntax unified
.arch armv7-a
.align  2
.global template_for_hook
.thumb
.thumb_func
.type	template_for_hook, %function
.Lname:
  .space 4
.Lhook_function:
  .space 4
.Ljump_back:
  .space 4
.Lret_jump:
  .space 4
template_for_hook:
 #14 * 4, 8 byte aligned
  push.w {r0-r12, lr}
# save lr to r0
  ldr r0, [sp, $13 * 4]
  # minus 7 to ensure we are thumb mode.
  mov r1, .Lret - .Lload_ret - 3
.Lload_ret:
  add r1, pc, r1
  str r1, [sp, $13 * 4]
  ldr r1, .Lname
  ldr ip, .Lhook_function
  blx ip
  # determine the target code is arm or thum.
  ldr ip, .Ljump_back
  tst ip, #1
  ittt eq
  moveq ip, .Larm_switch - .Lload_arm_switch - 4
.Lload_arm_switch:
  addeq ip, pc
  bxeq ip
  pop.w {r0-r12, lr}
.Lorigin_code:
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
.global template_for_hook_thumb_ret
.thumb
.thumb_func
.type	template_for_hook_thumb_ret, %function
template_for_hook_thumb_ret:
  ldr pc, .Ljump_back 
  nop
.Larm_switch:
  .arm
  pop {r0-r12, lr}
  nop
  nop
  nop
  nop
.global template_for_hook_arm_ret
.type	template_for_hook_arm_ret, %function
template_for_hook_arm_ret:
  ldr pc, .Ljump_back 
.thumb
.Lret:
  push {r0-r3}
  ldr ip, .Lret_jump
  blx ip
  mov ip, r0
  pop {r0-r3}
  bx ip
