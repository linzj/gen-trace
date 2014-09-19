Profiler Based On GCC & Chrome
======
Goal
===
To provide a tracer and a profiler based on the Chromium browser. Using the feature "chrome://tracing" of the browser as the view of tracer/profiler, this project aims to collect the data feeding the browser in a fairly easy way.

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
To find where the plugin includes reside, you needs to install the dev header of your GCC. This plugin requires the header of GCC 4.9. To do that on Ubuntu:
```
apt-get install gcc-4.9-plugin-dev
```
But 4.9 may not in the apt of Ubuntu, so you may still need to download the source and compile GCC. After make install phase, you will get all the plugin headers that required.
 2. Compile the runtime of the profiler.
 Currently the runtime is tested on android machines. So you may define your own output path.
```
 g++ -fPIC -fno-rtti -fno-exceptions -O2 -g3 -DCTRACE_FILE_NAME=<your output path including file name> -c runtime_sigprof.cpp
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
5. Run your program until it ends. Collect the output file from <your output path including file name>. Open chrome://tracing, and press the "Load" button to load the file. You may see the result.

Why GCC plugin
===
Well, no one wants to add a C++ auto variable with constructor/destructor to collect data, especially a big project will thousands of functions may need to trace/profile. And there may be C source file that you can't use this technique.
The plugin approach is an automatic resort to add start/end point. It does not require to change the source. Moreover it is exception safe.

FAQ
===
1. Q: Why not just use -finstrument-functions option, and implement __cyg_profile_func_enter/__cyg_profile_func_exit?
   A: I need to collect the function name without having to query the symbol files.
2. Q: Can I collect the result without waiting for the termination of my program.
   A: Yes. Just copy yout file back, and complete the file:
```
    echo ']}' >> <yout file>
```
3.

**Just Enjoy It**.


  [1]: https://lh3.googleusercontent.com/EaD0cec65HdzaiCCoM5bJ0NfmM_EbcMpYEiPwi3cpIo=s0 "2014-09-15 15:33:21 的截屏.png"
