# contrib/bgworker_cgroups/Makefile

MODULE_big = extrema
OBJS = \
	$(WIN32RES) \
	extrema.o

EXTENSION = extrema
DATA = extrema--1.0.sql


ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/extrema
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
