TARGET      = rlm_remotedb
SRCS        = rlm_remotedb.c
RLM_CFLAGS  = --std=c99
RLM_LIBS    = -lcurl -ljson --std=c99

include ../rules.mak
