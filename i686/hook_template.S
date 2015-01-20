.text
.globl template_for_hook
.hidden template_for_hook
.type template_for_hook, @function
.Lname:
  .zero 4
.Lhook_function:
  .zero 4
.Ljump_back:
  .zero 4
.Lret_jump:
  .zero 4
template_for_hook:
  # return point -4
  pushl (%esp) # -8
  pushl %edi # -12
  pushl %esi # -16
  pushl %edx # -20
  pushl %ecx # -24
  pushl %eax # -28
  pushl %ebx # -32
  # override the return point.
  call .Lpop_eax
.Lpop_eax:
  popl %eax
  movl %eax, %ebx
  leal (.Lret_point - .Lpop_eax)(%eax), %eax
  movl %eax, 28(%esp)
  # build the function argument.
  movl 24(%esp), %eax #the caller.
  movl %eax, -16(%esp)
  movl %ebx, %eax
  leal (.Lname - .Lpop_eax)(%eax), %eax
  movl (%eax), %eax
  movl %eax, -12(%esp) #the name of function, make char *.
  subl $16, %esp
  leal (.Lhook_function - .Lpop_eax)(%ebx), %ebx
  call *(%ebx) # gogogogo
  add $16, %esp
  popl %ebx
  popl %eax
  popl %ecx
  popl %edx
  popl %esi
  popl %edi
  addl $4, %esp
  jmp template_for_hook_end
.Lret_point:
  pushl %eax
  pushl %edx
  pushl %edi
  pushl %esi
  call .Lpop_eax2
.Lpop_eax2:
  popl %eax
  movl %eax, %edx
  leal (.Lname - .Lpop_eax2)(%eax), %eax
  movl %eax, -16(%esp)
  movl %edx, %eax
  leal (.Lret_jump - .Lpop_eax2)(%eax), %eax
  subl $16, %esp
  call *(%eax)
  add $16, %esp
  movl %eax, -4(%esp)
  popl %esi
  popl %edi
  popl %edx
  popl %eax
  jmpl *-20(%esp)
.globl template_for_hook_end
.hidden template_for_hook_end
.type template_for_hook_end, @function
template_for_hook_end:
