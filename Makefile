TARGET      = rlm_remotedb
SRCS        = rlm_remotedb.c
RLM_CFLAGS  = 
RLM_LIBS    = -lcurl -ljson

include ../rules.mak
