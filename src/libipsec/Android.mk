LOCAL_PATH:= $(call my-dir)

L_CFLAGS += -O3 -DANDROID_CHANGES -DHAVE_CONFIG_H

lib_SRC_FILES := ipsec_dump_policy.c ipsec_get_policylen.c ipsec_strerror.c \
	key_debug.c pfkey.c pfkey_dump.c policy_parse.c policy_token.c

common_C_INCLUDES += $(LOCAL_PATH)/../..

common_SHARED_LIBRARIES = libc libcutils

L_CFLAGS += -include $(LOCAL_PATH)/../../src/include-glibc/glibc-bugs.h \
  -I$(LOCAL_PATH)/../../src/include-glibc -I$(LOCAL_PATH)/../../src/libipsec \
  -Iexternal/openssl/include -I bionic/libc/private \
  -DSYSCONFDIR=\"/data/misc/vpn\" -DADMINPORTDIR=\"/var/racoon\" -g -O2


# For libracoon
# =====================================================

include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(lib_SRC_FILES)
LOCAL_C_INCLUDES += $(common_C_INCLUDES)
LOCAL_SHARED_LIBRARIES += $(common_SHARED_LIBRARIES)
LOCAL_CFLAGS += $(L_CFLAGS)
LOCAL_MODULE:= libipsec

include $(BUILD_STATIC_LIBRARY)
