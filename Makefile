.PHONY: all test
all:libtrace.so
TESTS := code_manager_impl_test mem_modify_test \
	code_modify_test \
	dis_x64_test \
	hook_template_test \
	x64_target_client_test \
	config_reader_test \
	base_controller_test \

test: $(TESTS)
MAIN_OBJS := log.o \
		mem_modify.o \
		code_manager_impl.o \
		code_modify.o \
		config_reader.o \
		base_controller.o \
		runtime_stack.o \
		entry.o \
		base_target_client.o \
		dis_client.o \
		disassembler.o

MAIN_TEST_OBJS :=  \
				  mem_modify_test.o \
				  code_modify_test.o \
				  code_manager_impl_test.o \
				  config_reader_test.o \
				  base_controller_test.o \
				  base_controller_test_lib.o \

X64_MAIN_OBJS := \
				  x64/dis.o \
				  x64/hook_template.o \
				  x64/x64_target_client.o \
				  x64/dis_gnu.o \

X64_TEST_OBJS := \
				  x64/dis_test.o \
				  x64/hook_template_test.o \
				  x64/x64_target_client_test.o


OBJS := $(MAIN_OBJS) \
		\
		$(MAIN_TEST_OBJS) \
		\
		$(X64_MAIN_OBJS) \
		\
		$(X64_TEST_OBJS)

CFLAGS := -O0 -g -Wall -I. -fPIC -fvisibility=hidden -std=c++11

LDFLAGS := -pie
LDLIBS := -lpthread -lrt

-include $(OBJS:.o=.d)

%.o: %.c
	gcc $(CFLAGS) -c $*.c -o $*.o
	gcc -MM -MT $*.o $(CFLAGS) $*.c > $*.d

%.o: %.cpp
	g++ $(CFLAGS) -c $*.cpp -o $*.o
	g++ -MM -MT $*.o $(CFLAGS) $*.cpp > $*.d

%.o: %.S
	g++ $(CFLAGS) -c $*.S -o $*.o
	g++ -MM -MT $*.o $(CFLAGS) $*.S > $*.d

mem_modify_test: mem_modify_test.o log.o mem_modify.o
	g++ $(LDFLAGS) -o $@ $^ $(LDLIBS)

code_manager_impl_test: code_manager_impl.o log.o code_manager_impl_test.o
	g++ $(LDFLAGS) -o $@ $^ $(LDLIBS)

code_modify_test: code_modify_test.o log.o code_manager_impl.o code_modify.o mem_modify.o
	g++ $(LDFLAGS) -o $@ $^ $(LDLIBS)

dis_x64_test: x64/dis.o x64/dis_test.o x64/dis_gnu.o log.o disassembler.o dis_client.o
	g++ $(LDFLAGS) -o $@ $^ $(LDLIBS)

hook_template_test: x64/hook_template_test.o x64/hook_template.o log.o
	g++ $(LDFLAGS) -o $@ $^ $(LDLIBS)
x64_target_client_test: x64/hook_template.o x64/dis.o x64/dis_gnu.o x64/x64_target_client.o x64/x64_target_client_test.o code_manager_impl.o log.o code_modify.o mem_modify.o disassembler.o dis_client.o base_target_client.o
	g++ $(LDFLAGS) -o $@ $^ $(LDLIBS)
config_reader_test: config_reader.o config_reader_test.o log.o
	g++ $(LDFLAGS) -o $@ $^ $(LDLIBS)

libbase_controller_test_lib.so: base_controller_test_lib.o log.o
	g++ -shared -o $@ $^ $(LDLIBS)

base_controller_test: config_reader.o  base_controller.o code_manager_impl.o log.o code_modify.o mem_modify.o x64/hook_template.o x64/dis.o x64/dis_gnu.o x64/x64_target_client.o base_controller_test.o libbase_controller_test_lib.so disassembler.o dis_client.o base_target_client.o
	g++ $(LDFLAGS) -o $@ $(filter %.o, $^) $(LDLIBS) -ldl $(LDLIBS)

clean:
	rm *.o *.d **/*.o **/*.d
test_all: $(TESTS)
	$(foreach test, $^, $(info ./$(test)))

libtrace.so: $(MAIN_OBJS) $(X64_MAIN_OBJS)
	g++ $(LDFLAGS) -Wl,--no-undefined -shared -o $@ $^ $(LDLIBS)
