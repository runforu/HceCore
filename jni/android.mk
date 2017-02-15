# Copyright (C) 2009 The Android Open Source Project
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
#
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := native
LOCAL_SRC_FILES := native.c native_impl.c log.c tag_list.c test.c static.c
LOCAL_SRC_FILES += crypto/khazad.c crypto/base64.c crypto/aes.c crypto/arc4.c crypto/des.c crypto/md5.c crypto/sha1.c crypto/sha2.c crypto/sha4.c crypto/pkcs5_pbkdf2.c fio/file_util.c
LOCAL_C_INCLUDES :=  $(JNI_H_INCLUDE)
LOCAL_PRELINK_MODULE := false

ifeq ($(_DEBUG_),1) 
	LOCAL_LDLIBS :=  -llog
endif

include $(BUILD_SHARED_LIBRARY)

