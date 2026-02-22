CFLAGS = -W -Wall -Wextra -fPIC -O2
LDFLAGS = -ldl -lpthread -luring

io_tester:
	g++ $(CFLAGS) $(INCLUDE) mix_io_tester.cpp $(LDFLAGS) -o mix_io_tester

clean:
	$(RM) mix_io_tester
	$(RM) *.o
	$(RM) *.so
