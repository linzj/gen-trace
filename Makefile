.PHONY: all test
all: test
test: code_manager_impl_test mem_modify_test

OBJS := log.o \
		mem_modify.o \
		mem_modify_test.o \
		code_manager_impl.o \
		code_manager_impl_test.o

CFLAGS := -O0 -g

-include $(OBJS:.o=.d)

%.o: %.cpp
	g++ $(CFLAGS) -c $*.cpp -o $*.o
	g++ -MM $(CFLAGS) $*.cpp > $*.d

mem_modify_test: mem_modify_test.o log.o mem_modify.o
	g++ -o $@ $^

code_manager_impl_test: code_manager_impl.o log.o code_manager_impl_test.o
	g++ -o $@ $^

clean:
	rm *.o *.d
