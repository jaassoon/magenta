# Copyright 2016 The Fuchsia Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

LOCAL_DIR := $(GET_LOCAL_DIR)

DRIVER_SRCS += \
    $(LOCAL_DIR)/block.cpp \
    $(LOCAL_DIR)/device.cpp \
    $(LOCAL_DIR)/gpu.cpp \
    $(LOCAL_DIR)/ring.cpp \
    $(LOCAL_DIR)/virtio_c.c \
    $(LOCAL_DIR)/virtio_driver.cpp \

# TODO: figure out a better way than offsetof to get back to the main object
MODULE_CPPFLAGS += -Wno-invalid-offsetof

