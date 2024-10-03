#
# Copyright (C) 2024 Renesas Electronics Corporation.
# Copyright (C) 2024 EPAM Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

include(ExternalProject)

set(aoscore_build_dir ${CMAKE_CURRENT_BINARY_DIR}/aoscore)

ExternalProject_Add(
    aoscore
    PREFIX ${aoscore_build_dir}
    GIT_REPOSITORY https://github.com/mykola-kobets-epam/aos_core_lib_cpp.git
    GIT_TAG renew-cert-fix
    GIT_PROGRESS TRUE
    GIT_SHALLOW TRUE
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_INSTALL_PREFIX=${aoscore_build_dir}
               -DWITH_TEST=${WITH_TEST}
    UPDATE_COMMAND ""
)

file(MAKE_DIRECTORY ${aoscore_build_dir}/include)

add_library(aoscommon STATIC IMPORTED GLOBAL)
set_target_properties(aoscommon PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${aoscore_build_dir}/include)
set_target_properties(aoscommon PROPERTIES IMPORTED_LOCATION ${aoscore_build_dir}/lib/libaoscommoncpp.a)
add_dependencies(aoscommon aoscore)

add_library(mbedtls::crypto STATIC IMPORTED GLOBAL)
set_target_properties(mbedtls::crypto PROPERTIES IMPORTED_LOCATION ${aoscore_build_dir}/lib/libmbedcrypto.a)
add_dependencies(mbedtls::crypto aoscore)

add_library(mbedtls::mbedtls STATIC IMPORTED GLOBAL)
set_target_properties(mbedtls::mbedtls PROPERTIES IMPORTED_LOCATION ${aoscore_build_dir}/lib/libmbedtls.a)
add_dependencies(mbedtls::mbedtls aoscore)

add_library(mbedtls::mbedx509 STATIC IMPORTED GLOBAL)
set_target_properties(mbedtls::mbedx509 PROPERTIES IMPORTED_LOCATION ${aoscore_build_dir}/lib/libmbedx509.a)
add_dependencies(mbedtls::mbedx509 aoscore)

add_library(mbedtls INTERFACE IMPORTED)
set_property(TARGET mbedtls PROPERTY INTERFACE_LINK_LIBRARIES mbedtls::crypto mbedtls::mbedtls mbedtls::mbedx509)
