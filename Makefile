.PHONY: all test
all:
test: code_manager_impl_test mem_modify_test \
	code_modify_test \
	dis_x64_test \
	hook_template_test

OBJS := log.o \
		mem_modify.o \
		code_manager_impl.o \
		code_modify.o \
		\
		mem_modify_test.o \
		code_modify_test.o \
		code_manager_impl_test.o \
		\
		x64/dis.o \
		x64/hook_template.o \
		\
		x64/dis_test.o \
		x64/hook_template_test.o

CFLAGS := -O0 -g -Wall -I.

-include $(OBJS:.o=.d)

%.o: %.cpp
	g++ $(CFLAGS) -c $*.cpp -o $*.o
	g++ -MM $(CFLAGS) $*.cpp > $*.d

%.o: %.S
	g++ $(CFLAGS) -c $*.S -o $*.o
	g++ -MM $(CFLAGS) $*.S > $*.d

mem_modify_test: mem_modify_test.o log.o mem_modify.o
	g++ -o $@ $^

code_manager_impl_test: code_manager_impl.o log.o code_manager_impl_test.o
	g++ -o $@ $^

code_modify_test: code_modify_test.o log.o code_manager_impl.o code_modify.o mem_modify.o
	g++ -o $@ $^

dis_x64_test: x64/dis.o x64/dis_test.o log.o
	g++ -o $@ $^

hook_template_test: x64/hook_template_test.o x64/hook_template.o log.o
	g++ -o $@ $^

clean:
	rm *.o *.d
