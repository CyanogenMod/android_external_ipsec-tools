ifeq ($(TARGET_ARCH),arm)

IPSEC_PATH := $(call my-dir)

include $(IPSEC_PATH)/src/libipsec/Android.mk
include $(IPSEC_PATH)/src/racoon/Android.mk

endif
