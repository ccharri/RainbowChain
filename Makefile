# Compiler stuff
CXX 		 = g++
CXXFLAGS = -std=c++11 -Wall -O3


# The files we'll be compiling
HDRS = $(wildcard *.h)
SRCS = $(wildcard *.cpp)
OBJS = $(SRCS:.cpp=.o) $(SRCS_SLN:.cpp=.o)
LIBS = -lssl -lcrypto


# Change flags to ignore the deprecated SHA functions if compiling
UNAME = $(shell uname -s)

ifneq ($(UNAME),Darwin)
  CXXFLAGS += -Werror
endif


# Rules
rtable: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

.PHONY: clean
clean: 
	-rm -f -r $(OBJS) *.o *~ *core* rtable 
