.PHONY: all test
all:
TESTS := code_manager_impl_test mem_modify_test \
	code_modify_test \
	dis_x64_test \
	hook_template_test \
	x64_target_client_test

test: $(TESTS)

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
		x64/x64_target_client.o \
		\
		x64/dis_test.o \
		x64/hook_template_test.o \
		x64/x64_target_client_test.o

CFLAGS := -O0 -g -Wall -I. -fPIC

LDFLAGS := -pie

-include $(OBJS:.o=.d)

%.o: %.cpp
	g++ $(CFLAGS) -c $*.cpp -o $*.o
	g++ -MM $(CFLAGS) $*.cpp > $*.d

%.o: %.S
	g++ $(CFLAGS) -c $*.S -o $*.o
	g++ -MM $(CFLAGS) $*.S > $*.d

mem_modify_test: mem_modify_test.o log.o mem_modify.o
	g++ $(LDFLAGS) -o $@ $^

code_manager_impl_test: code_manager_impl.o log.o code_manager_impl_test.o
	g++ $(LDFLAGS) -o $@ $^

code_modify_test: code_modify_test.o log.o code_manager_impl.o code_modify.o mem_modify.o
	g++ $(LDFLAGS) -o $@ $^

dis_x64_test: x64/dis.o x64/dis_test.o log.o
	g++ $(LDFLAGS) -o $@ $^

hook_template_test: x64/hook_template_test.o x64/hook_template.o log.o
	g++ $(LDFLAGS) -o $@ $^
x64_target_client_test: x64/hook_template.o x64/dis.o x64/x64_target_client.o x64/x64_target_client_test.o code_manager_impl.o log.o code_modify.o mem_modify.o
	g++ $(LDFLAGS) -o $@ $^

clean:
	rm *.o *.d **/*.o **/*.d
test_all: $(TESTS)
	$(foreach test, $^, $(info./$(test)))