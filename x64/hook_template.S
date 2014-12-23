.text
.globl template_for_hook
.hidden template_for_hook
.type template_for_hook, @function
.Lname:
  .zero 8
.Lhook_function:
  .zero 8
.Ljump_back:
  .zero 8
.Lret_jump:
  .zero 8
template_for_hook:
  # return point -8
  pushq (%rsp) # -16
  pushq %rdi # -24
  pushq %rsi # -32
  pushq %rdx # -40
  pushq %rcx # -48
  pushq %r8 # -56
  pushq %r9 # -64
  # override the return point.
  leaq .Lret_point(%rip), %rax
  movq %rax, 56(%rsp)
  # build the function argument.
  movq 48(%rsp), %rdi #the caller.
  movq .Lname(%rip), %rsi #the name of function, make char *.
  movq .Lhook_function(%rip) , %rax
  callq *%rax # gogogogo
  popq %r9
  popq %r8
  popq %rcx
  popq %rdx
  popq %rsi
  popq %rdi
  add $8, %rsp
  # place holder
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
.globl template_for_hook2
.hidden template_for_hook2
.type template_for_hook2, @function
template_for_hook2:
  movq .Ljump_back(%rip), %r15
  jmpq *%r15
.Lret_point:
  pushq %rax
  pushq %rdx
  pushq %rdi
  pushq %rsi
  movq .Lret_jump(%rip), %rax
  callq *%rax
  movq %rax, %rcx # real return point goes to rax
  popq %rsi
  popq %rdi
  popq %rdx
  popq %rax
  jmpq *%rcx

.globl template_for_hook_end
.hidden template_for_hook_end
.type template_for_hook_end, @function
template_for_hook_end:
  nop
