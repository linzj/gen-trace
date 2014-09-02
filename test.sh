#!/bin/sh
g++ -O2 -c main.cpp
g++ -O2 -c test1.cpp
g++ -O2 -o test1 test1.o main.o
./test1
mv trace.json test1.json

g++ -O2 -c test2.cpp
g++ -O2 -o test2 test2.o main.o
./test2
mv trace.json test2.json

