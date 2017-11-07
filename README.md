1. Download valgrind 3.10.0
2. Patch valgrind so that the build system build gen-trace. The patch file is patch-for-valgrind-3.10.
3. The usual way to use is like this:
LD_BIND_NOW=1  ~/src/valgrind-3.10.0/built/bin/valgrind  --tool=gentrace --use-estimated-time=yes  --max-stack=200 --min-interval=600 xxx
