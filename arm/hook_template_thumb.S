#8 byte align stack.
.syntax unified
.arch armv7-a
.align  2
.global template_for_hook_thumb
.hidden template_for_hook_thumb
.thumb
.thumb_func
.type	template_for_hook_thumb, %function
.Lname:
  .space 4
.Lhook_function:
  .space 4
.Ljump_back:
  .space 4
.Lret_jump:
  .space 4
template_for_hook_thumb:
 #14 * 4, 8 byte aligned
  push.w {r0-r12, lr}
# save lr to r0
  mov.w r1, .Lret - .Lload_ret - 4
  add r1, #1
.Lload_ret:
  add r1, pc, r1
  ldr r0, [sp, $13 * 4]
  str r1, [sp, $13 * 4]
  ldr r1, .Lname
  ldr ip, .Lhook_function
  blx ip
  pop.w {r0-r12, lr}
  b template_for_hook_thumb_end
.Lret:
  push {r0-r3}
  ldr ip, .Lret_jump
  ldr r0, .Lname
  blx ip
  mov ip, r0
  pop {r0-r3}
  bx ip
.global template_for_hook_thumb_end
.hidden template_for_hook_thumb_end
.type template_for_hook_thumb_end, %function
template_for_hook_thumb_end:
