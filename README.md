Profiler Based On GCC & Chrome
======
What it output
===
![enter image description here][1]

How to use
===

 1. Compile my plugin.

    Like this:
```    
    g++ -I <where your plugin includes reside> -fno-rtti -fPIC -shared -o gentrace.so plugin.cpp
```
 2. Compile the runtime.
 Currently the runtime is test on android machines. So you may define your own output path.
```
 g++ -fPIC -fno-rtti -fno-exceptions -O2 -g3 -DCTRACE_FILE_NAME=<your output path including name> -c runtime_sigprof.cpp
```
 3. Compile your source using this plugin.
 Like this:
```
    gcc -fplugin=./gentrace.so xxx.c
```
 4. Link your program with the runtime
```
 gcc -o <your program> xxx.o runtime_sigprof.o
```

**Just Enjoy It**.


  [1]: https://lh3.googleusercontent.com/EaD0cec65HdzaiCCoM5bJ0NfmM_EbcMpYEiPwi3cpIo=s0 "2014-09-15 15:33:21 的截屏.png"
