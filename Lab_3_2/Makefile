.PHONY: all debug release clean

Compiler = g++
RELEASE_FLAGS = -O2 -Wall -DNDEBUG -Iheaders 
DEBUG_FLAGS   = -g -O0 -Wall -Iheaders
RELEASE_EXEC  = lab22
DEBUG_EXEC    = lab22-dbg 
SOURCES       = main.cpp modCipherBeta.cpp
Library       = -lUnitTest++
all: debug release

debug: $(DEBUG_EXEC)

$(DEBUG_EXEC): $(SOURCES)
	$(Compiler) $(DEBUG_FLAGS) $(SOURCES) -o $(DEBUG_EXEC) $(Library)

release: $(RELEASE_EXEC)

$(RELEASE_EXEC): $(SOURCES)
	$(Compiler) $(RELEASE_FLAGS) $(SOURCES) -o $(RELEASE_EXEC) $(Library)

clean:
	rm -f $(RELEASE_EXEC) $(DEBUG_EXEC)
