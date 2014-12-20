.PHONY: all
all: test_mem_modify

OBJS := log.o \
		mem_modify.o \
		test_mem_modify.o

CFLAGS := -O0 -g

-include $(OBJS:.o=.d)

%.o: %.cpp
	g++ $(CFLAGS) -c $*.cpp -o $*.o
	g++ -MM $(CFLAGS) $*.cpp > $*.d

test_mem_modify: test_mem_modify.o log.o mem_modify.o
	g++ -o $@ $^


clean:
	rm *.o *.d
