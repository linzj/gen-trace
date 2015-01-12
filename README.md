gen-trace runtime version
=========

##GOAL

I want to generate a trace file that chrome://tracing understands, with only
symbols of the elfs, including share libraries and executable on
Linux platform.

##Usage

### Generate A Config File
The very first step. You need to identify which elfs want to trace, and where 
they are.  Then run the script act_on_elf.sh. It accept at least 3 arguments.
The first is the log file, which can be empty string like "". The second is the
seconds pausing before code modification actually take action. The third and so
is the elfs you want to trace. An example is shown below:
```
./act_on_elf.sh "" 10 libBrowserShell_UC.so
```

### Run on Linux Desktop Distribution
The only Linux Desktop Distribution supported is a X86_64 version. So you need
a 64 bit Ubuntu or Fedora.  You need to compile the sources first. It is easy.
Just cd to the source directory and make. The output is libtrace.so.
Run your target program like this.
```
LD_PRELOAD=xxxx/libtrace.so your program
```
**DON'T FORGET THE PUT THE trace.config FILE TO CURRENT WORKING DIRECTORY.**

### Running on Android ARM
The compile command is make -f Makefile.arm. But before that, you need to
export environment variable to the shell.
```
export NDK_PATH=<your ndk>
```

Then libtrace.so need to be pushed to /data/local/tmp/, and trace.config
need to be pushed to /sdcard/. The location of trace.config can be changed in
the source entry.cpp.  But I think it's a suitable location.
You app needs to be run with a wrapper. **So make sure your device is rooted.**
A wrapper is like this:
```
LD_LIBRARY_PATH=/data/local/tmp:$LD_LIBRARY_PATH \
LD_PRELOAD=libtrace.so \
exec $@
```
Assuming your wrapper is located in /data/local/tmp:
Change your wrapper permission:
```
chmod 755 /data/local/tmp/wrapper
```
Then connect the wrapper with you app:
```
setprop wrap.you.app.package.name /data/local/tmp/wrapper
```
####CAVEATS
1.On Android 5.0 or above, you also need to shutdown SELinux:
```
setenforce 0
```
2.The second argument of setprop can not exceed 32 char long. So you need to
truncate that argument to 32 chars.

3.The generated .json file is not put an end mark into. And needed to post
process. So you needs to do the following:
```
python post_process.py <generated json> >trace.json
```
And the post processed json file here is trace.json.

4.To maximum the precision, I use nanosecond as unit. But chrome uses
microseconds. So the output graph may looks 1000 times longer.

##Design
The main design is runtime code modification and trampoline generation.

###Code Modification
A jump instruction will overwrite the targeting code point, which is specify
in trace.config. A targeting code point is very beginning of a function.
Before overwrite, original instructions will be checked if they are suitable
to get modified.

####Checking Code
The sequence of the original instructions is fine to get modified, only when
they are pc context free. That means no pc register involved. That includes
all load, store instructions with pc register, and all the jump instructions.
The second constraint is the rest code of the function will not reference the
code modified. For example, the rest of the function may jump back to the code
 modified.

####The Selection Of Jumping Instruction

#####X86_64 Version
I have selected 5 bytes jump for minimize the instruction needed to be modified
But this selection will make it only jump 32bit around the rip.
So the virtual method of x64_target_client use_target_code_point_as_hint
returns true. So that the code_manager_impl walk slowly around the target
code point to find an unmapped vm. Then use mmap with MAP_FIXED to allocate
the trampoline code.

#####ARM Version
I have selected 10 bytes, for thumb mode jump, and 12 byte, for arm mode jump.
Both use movt, movw pattern to move the 32bit address constant in place.
Virtual method of arm_target_client use_target_code_point_as_hint returns
false, for hints are actually a performance damager.

####Memory Modification
I use fork and ptrace to parent resort to do the actual modification.
I do this for 2 consideration:
1. When doing the modification, the modifiee is stopped. That includes all the
threads of the modifiee, aka, Stop the world operation is achieved.
2. I don't have to flush the code of the modifiee, the Linux kernel scheduler
will do that for me. For all the threads of modifiee are stopped, the Linux
kernel will operate an try to wake up action, and the switch operation will
flush the code cache.
