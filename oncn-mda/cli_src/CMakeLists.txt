# Copyright (c) 2019 Huawei Technologies Co., Ltd.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

MESSAGE("======================Enter cli folder=======================")
set(CMAKE_C_COMPILER "gcc")
set(CMAKE_C_FLAGS "-g -Wall -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wno-deprecated-declarations -Werror -ftrapv -O2 -fPIE -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack")

set(EXECUTABLE_OUTPUT_PATH ${DEPLOY_PROGRAM})
AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/func SRC_LIST)

if($ENV{HS_COVERAGE_ENABLE})
        message("Enable Coverage compile option")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
endif($ENV{HS_COVERAGE_ENABLE})

add_executable(mdacore mdacore.c ${SRC_LIST})
target_link_libraries(mdacore -lbpf -lboundscheck -lelf -lz -lm)

MESSAGE("======================Leave cli folder=======================")
