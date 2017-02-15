_DUMMY_ := $(shell jni/genC.sh)

APP_ABI ?= all

APP_PLATFORM := android-14

APP_CFLAGS += -std=c99 

ifeq ($(NDK_DEBUG),0) 
  _DEBUG_ := 0
  APP_CFLAGS += -D_DEBUG_=0
else
  _DEBUG_ := 1
  APP_CFLAGS += -D_DEBUG_=1
endif

