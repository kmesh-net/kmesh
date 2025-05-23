# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Kmesh

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
