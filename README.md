gen-trace runtime version
=========

##GOAL

I want to generate a trace file that chrome://tracing understands, with only symobols of the elfs,
including share libraries and executable on Linux platform.

##Usage

### Generate A Config File
The very first step. You need to identify which elfs want to trace, and where they are.
Then run the script act_on_elf.sh. It accept at least 3 arguments. The first is the log file,
which can be empty string like "". The second is the seconds pausing before code modification
actully take action. The third and so is the elfs you want to trace. An example is shown below:
```
./act_on_elf.sh "" 10 libBrowserShell_UC.so
```

### Run on Linux Desktop Distribution
The only Linux Desktop Distribution supported is a X86_64 version. So you need a 64 bit Ubuntu or Fedora.
You need to compile the sources first. It is easy. Just cd to the source directory and make. The output is
libtrace.so.
Run your target program like this.
```
LD_PRELOAD=xxxx/libtrace.so your program
```
DON'T FORGET THE PUT THE trace.config FILE TO CURRENT WORKING DIRECTORY.

### Runing on Android ARM
The compile command is make -f Makefile.arm. But before that, you need to export
environment variable to the shell.
```
export NDK_PATH=<your ndk>
```

Then libtrace.so need to be pushed to /data/local/tmp/, and trace.config need to be
pushed to /sdcard/. The location of trace.config can be changed in the source entry.cpp.
But I think it's a suitable location.
You app needs to be run with a wrapper. So make sure your device is rooted.
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
2.The second argument of setprop can not exceed 32 char long. So you need to truncate that arugument to 32 chars.

##Design
The main design is runtime code modification and trampoline generation.



