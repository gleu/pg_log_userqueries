# pg_log_userqueries/Makefile

MODULE_big = pg_log_userqueries
OBJS = pg_log_userqueries.o

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
