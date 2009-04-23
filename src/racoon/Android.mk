LOCAL_PATH:= $(call my-dir)

# We need to build this for both the device (as a shared library)
# and the host (as a static library for tools to use).

L_CFLAGS += -O3 -DANDROID_CHANGES -DHAVE_CONFIG_H -DMAXNS=3


lib_SRC_FILES := kmpstat.c vmbuf.c sockmisc.c misc.c

DAEMON_SRC_FILES := main.c session.c isakmp.c handler.c isakmp_ident.c \
  isakmp_agg.c isakmp_base.c isakmp_quick.c isakmp_inf.c isakmp_newg.c \
  gssapi.c dnssec.c getcertsbyname.c privsep.c pfkey.c admin.c evt.c \
  ipsec_doi.c oakley.c grabmyaddr.c vendorid.c policy.c localconf.c \
  remoteconf.c crypto_openssl.c algorithm.c proposal.c sainfo.c strnames.c \
  plog.c logger.c schedule.c str2val.c safefile.c backupsa.c genlist.c \
  rsalist.c cftoken.c cfparse.c prsa_tok.c prsa_par.c vmbuf.c sockmisc.c \
  misc.c nattraversal.c

DAEMON_STATIC_LIBS := libipsec libracoon
DAEMON_SHARED_LIBS := libcutils libcrypto libssl

common_C_INCLUDES += $(LOCAL_PATH)/../..

L_CFLAGS += -include $(LOCAL_PATH)/../../src/include-glibc/glibc-bugs.h \
  -I$(LOCAL_PATH)/../../src/include-glibc -I$(LOCAL_PATH)/../../src/libipsec \
  -I$(LOCAL_PATH)/missing -Iexternal/openssl/include -I bionic/libc/private \
  -DSYSCONFDIR=\"/etc\" -DADMINPORTDIR=\"/var/racoon\" -g -O2

common_SHARED_LIBRARIES := libipsec

# For libracoon
# =====================================================

include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(lib_SRC_FILES)
LOCAL_C_INCLUDES += $(common_C_INCLUDES)
LOCAL_SHARED_LIBRARIES += $(common_SHARED_LIBRARIES)
LOCAL_CFLAGS += $(L_CFLAGS)
LOCAL_MODULE:= libracoon

include $(BUILD_STATIC_LIBRARY)

# For daemon racoon
# =====================================================

include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(DAEMON_SRC_FILES)
LOCAL_C_INCLUDES += $(common_C_INCLUDES)
LOCAL_SHARED_LIBRARIES += $(DAEMON_SHARED_LIBS)
LOCAL_STATIC_LIBRARIES += $(DAEMON_STATIC_LIBS)
LOCAL_CFLAGS += $(L_CFLAGS)
LOCAL_MODULE := racoon
include $(BUILD_EXECUTABLE)
