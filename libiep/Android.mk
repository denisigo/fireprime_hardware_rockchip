LOCAL_PATH := $(call my-dir)

#
# libiep.so
#
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	iep_api.cpp

LOCAL_CFLAGS := \
	$(CFLAGS) \
	-Wall \
	-Wextra \
	-DLOG_TAG=\"libiep\"

LOCAL_C_INCLUDES += $(TOP)/hardware/libhardware/include
LOCAL_LDFLAGS := \
	-Wl,-z,defs

LOCAL_SHARED_LIBRARIES := \
	libcutils

LOCAL_MODULE := libiep
LOCAL_MODULE_TAGS    := optional
LOCAL_PRELINK_MODULE := false

include $(BUILD_SHARED_LIBRARY)

#
# iep_func_test
#
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	iep_func_test.cpp

#LOCAL_C_INCLUDES += kernel/include

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libiep \
	libvpu

#LOCAL_LDLIBS += -lpthread

LOCAL_MODULE := iep_func_test
LOCAL_MODULE_TAGS := optional tests
LOCAL_PRELINK_MODULE := false

include $(BUILD_EXECUTABLE)
