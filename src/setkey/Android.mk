LOCAL_PATH:= $(call my-dir)

# Build setkey utility.

L_CFLAGS += -O3 -DANDROID_CHANGES -DHAVE_CONFIG_H


EXE_SRC_FILES := setkey.c parse.c token.c

EXE_LIBS := libcutils libcrypto libssl

common_C_INCLUDES += \
	$(LOCAL_PATH)/../..

L_CFLAGS += -include $(LOCAL_PATH)/../../src/include-glibc/glibc-bugs.h \
  -I$(LOCAL_PATH)/../../src/include-glibc -I$(LOCAL_PATH)/../../src/libipsec \
  -Iexternal/openssl/include -I bionic/libc/private \
  -DSYSCONFDIR=\"/etc\" -DADMINPORTDIR=\"/var/racoon\" -g -O2


# For setkey
# =====================================================

include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(EXE_SRC_FILES)
LOCAL_C_INCLUDES += $(common_C_INCLUDES)
LOCAL_SHARED_LIBRARIES += $(EXE_LIBS)
LOCAL_STATIC_LIBRARIES += libipsec
LOCAL_CFLAGS += $(L_CFLAGS)
LOCAL_MODULE := setkey
include $(BUILD_EXECUTABLE)
