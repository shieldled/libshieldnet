# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
# Fail if a hand-rolled client admission is reintroduced.
#
# Nine sources each built a FINISH from the offset-indexed key schedule by hand.
# Nine copies drift silently, and nothing caught it. client_helper.h is now the
# one copy, so this fails the build rather than review when a tenth appears.
#
# Runs two ways, and must keep working both:
#   ctest --test-dir <build>            (add_test in test/sn/CMakeLists.txt)
#   cmake -P test/sn/no_handrolled_admission.cmake   (CI, no build needed)
#
# cmake -E has no grep, so this is script mode with file(STRINGS ... REGEX).

# IN_LIST below needs CMP0057 NEW, which this pins rather than inheriting from
# whatever cmake the runner has.
cmake_minimum_required(VERSION 3.10)

get_filename_component(SN_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

# The two files allowed to call it: the helper itself, and the golden-vector
# test, which must keep calling the encoders directly or its pin goes circular.
set(ALLOWED
    "${SN_ROOT}/test/sn/client_helper.h"
    "${SN_ROOT}/test/sn/test_sn_kdf.c"
)

file(GLOB_RECURSE CANDIDATES
    "${SN_ROOT}/test/*.c" "${SN_ROOT}/test/*.h"
    "${SN_ROOT}/fuzz/*.c" "${SN_ROOT}/fuzz/*.h"
)

set(OFFENDERS "")
foreach(f ${CANDIDATES})
    if(f IN_LIST ALLOWED)
        continue()
    endif()
    # No trailing "(": a call split across lines would slip a stricter regex,
    # and a bare mention in a comment is worth a look anyway.
    file(STRINGS "${f}" HITS REGEX "sn_encode_finish")
    if(HITS)
        file(RELATIVE_PATH rel "${SN_ROOT}" "${f}")
        list(APPEND OFFENDERS "${rel}")
    endif()
endforeach()

if(OFFENDERS)
    string(REPLACE ";" "\n  " PRETTY "${OFFENDERS}")
    message(FATAL_ERROR
        "hand-rolled admission found in:\n  ${PRETTY}\n"
        "Build the FINISH with ch_finish()/ch_finish_from() from "
        "test/sn/client_helper.h instead. If this file genuinely "
        "must call the encoder directly, add it to ALLOWED here and say why.")
endif()

message(STATUS "no_handrolled_admission: ok")
