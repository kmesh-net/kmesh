# Copyright 2023 The Kmesh Authors.

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

MESSAGE("======================Enter ebpf folder=======================")
set(CMAKE_C_COMPILER "clang")
set(CMAKE_C_FLAGS "-g -Wall -O2 -Werror -D_FORTIFY_SOURCE=2 -Wno-deprecated-declarations -ftrapv -target bpf -D__x86_64__ -fPIC")

set(LIBRARY_OUTPUT_PATH ${DEPLOY_LIB})

add_library(sock_ops OBJECT sock_ops.c)
add_library(sock_redirect OBJECT sock_redirect.c)

MESSAGE("======================Leave ebpf folder=======================")
