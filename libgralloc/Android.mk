# 
# Copyright (C) 2010 ARM Limited. All rights reserved.
# 
# Copyright (C) 2008 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#ifeq ($(strip $(TARGET_BOARD_PLATFORM_GPU)),mali400)
LOCAL_PATH := $(call my-dir)

# HAL module implemenation, not prelinked and stored in
# hw/<OVERLAY_HARDWARE_MODULE_ID>.<ro.product.board>.so
include $(CLEAR_VARS)
LOCAL_PRELINK_MODULE := false
LOCAL_MODULE_PATH := $(TARGET_OUT_SHARED_LIBRARIES)/hw

MALI_DDK_TEST_PATH := hardware/arm/

# Which DDK are we building for?
ifneq (,$(wildcard $(MALI_DDK_TEST_PATH)))
# Mali-T6xx DDK
MALI_DDK_PATH := vendor/arm/mali6xx
LOCAL_SHARED_LIBRARIES := liblog libcutils libGLESv1_CM libGLES_mali libion

# All include files are accessed from the DDK root
DDK_PATH := $(LOCAL_PATH)/../../..
UMP_HEADERS_PATH := $(DDK_PATH)/kernel/include
LOCAL_C_INCLUDES := $(DDK_PATH) $(UMP_HEADERS_PATH)

LOCAL_CFLAGS := -DLOG_TAG=\"gralloc\" -DSTANDARD_LINUX_SCREEN -DMALI_600
else
# Mali-200/300/400MP DDK
MALI_DDK_PATH := hardware/arm/mali
ifeq ($(strip $(GRAPHIC_MEMORY_PROVIDER)),dma_buf)
SHARED_MEM_LIBS := libion libhardware
else
SHARED_MEM_LIBS := libUMP
endif
LOCAL_SHARED_LIBRARIES := liblog libcutils libutils libGLESv1_CM $(SHARED_MEM_LIBS)

LOCAL_C_INCLUDES := system/core/include/ $(MALI_DDK_PATH)/include 
# Include the UMP header files
LOCAL_C_INCLUDES += hardware/rockchip/libgralloc_ump/ump/include
#LOCAL_C_INCLUDES += $(MALI_DDK_PATH)/src/ump/include

LOCAL_CFLAGS := -DLOG_TAG=\"gralloc\" -DGRALLOC_32_BITS -DSTANDARD_LINUX_SCREEN -DPLATFORM_SDK_VERSION=$(PLATFORM_SDK_VERSION)
endif

#mod by huangds

ifeq ($(strip $(BOARD_USE_LCDC_COMPOSER)),true)	
LOCAL_CFLAGS += -DUSE_LCDC_COMPOSER
endif

ifeq ($(strip $(GRAPHIC_MEMORY_PROVIDER)),dma_buf)
LOCAL_CFLAGS += -DUSE_DMA_BUF
endif

ifeq ($(strip $(BOARD_WITH_IOMMU)),true)
LOCAL_CFLAGS += -DBOARD_WITH_IOMMU
endif

ifeq ($(strip $(TARGET_BOARD_PLATFORM)),sofia3gr)
LOCAL_CFLAGS += -DUSE_X86
endif

ifeq ($(strip $(TARGET_BOARD_PLATFORM)),rk3188)
LOCAL_CFLAGS += -DUSE_RK3188
endif

LOCAL_C_INCLUDES += \
        system/core/libion/include \
        system/core/libion/kernel-headers
LOCAL_SRC_FILES := \
	gralloc_module.cpp \
	alloc_device.cpp \
	framebuffer_device.cpp

LOCAL_MODULE := gralloc.$(TARGET_BOARD_HARDWARE)
LOCAL_MODULE_TAGS := optional
#LOCAL_CFLAGS+= -DMALI_VSYNC_EVENT_REPORT_ENABLE
include $(BUILD_SHARED_LIBRARY)

#endif
