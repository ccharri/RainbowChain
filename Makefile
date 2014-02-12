# Compiler stuff
CXX 		 = g++
CXXFLAGS = -std=c++11 -Wall 


# The files we'll be compiling
HDRS = Rainbow_table.h
SRCS = main.cpp
OBJS = $(SRCS:.cpp=.o) $(SRCS_SLN:.cpp=.o)
LIBS = -lssl -lcrypto


# Change flags to ignore the deprecated SHA functions if compiling
UNAME = $(shell uname -s)

ifneq ($(UNAME),Darwin)
  CXXFLAGS += -Werror
  LIBS     += -lGL -lGLU -lglut
else
  LIBS     += -framework OpenGL -framework GLUT -lc
endif


# Rules
rtable: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

.PHONY: clean
clean: 
	-rm -f -r $(OBJS) *.o *~ *core* rtable 
