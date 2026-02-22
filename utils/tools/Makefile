CFLAGS = -W -Wall -Wextra -fPIC -O2
LDFLAGS = -ldl

config_nap:
	gcc $(CFLAGS) $(INCLUDE) config_nap.c $(LDFLAGS) -o config_nap

clean:
	$(RM) *.o
	$(RM) *.so
