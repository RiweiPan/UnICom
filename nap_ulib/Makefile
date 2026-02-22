CFLAGS = -W -Wall -Wextra -fPIC -O2
LDFLAGS = -ldl
RKDB_MODE ?= $(RKDB)
NAP_POLL_MODE ?= $(NAP_POLL)

ifeq ($(RKDB_MODE),1)
CFLAGS += -DFIX_ROCKSDB_ISSUE
$(info Using rocksdb settings)
else
$(info Using normal settings)
endif

ifeq ($(NAP_POLL_MODE),1)
CFLAGS += -DNAP_USE_NAP_POLL
$(info Using nap_poll settings)
else
$(info Using pure_poll settings)
endif

.PHONY: debug release tests

release: napshim

napshim: ulib_shim.o ulib.o
	gcc $(CFLAGS) $(INCLUDE) $^ $(LDFLAGS) -shared -o libnapshim.so


%.o: %.c 
	gcc $(CFLAGS) $(INCLUDE) -c $<

clean:
	$(RM) *.o
	$(RM) *.so
