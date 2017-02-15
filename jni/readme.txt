release build command:
1. ndk-build -j8 NDK_DEBUG=0

debug build command for log:
1. ndk-build -j8 NDK_DEBUG=1 "LOCAL_CFLAGS += -D_DEBUG_" "LOCAL_LDLIBS :=  -llog"

only for arm cpu:
1. ndk-build -j8 NDK_DEBUG=1 APP_ABI=armeabi "LOCAL_CFLAGS += -D_DEBUG_" "LOCAL_LDLIBS :=  -llog"