set(LIBZMQ_PREFIX ${CMAKE_BINARY_DIR}/libzmq)
set(ZeroMQ_VERSION 4.3.5)
set(LIBZMQ_URL https://github.com/zeromq/libzmq/releases/download/v${ZeroMQ_VERSION}/zeromq-${ZeroMQ_VERSION}.tar.gz)
set(LIBZMQ_HASH SHA512=a71d48aa977ad8941c1609947d8db2679fc7a951e4cd0c3a1127ae026d883c11bd4203cf315de87f95f5031aec459a731aec34e5ce5b667b8d0559b157952541)

message(${LIBZMQ_URL})

if(LIBZMQ_TARBALL_URL)
    # make a build time override of the tarball url so we can fetch it if the original link goes away
    set(LIBZMQ_URL ${LIBZMQ_TARBALL_URL})
endif()


file(MAKE_DIRECTORY ${LIBZMQ_PREFIX}/include)

set(libzmq_compiler_args)
foreach(lang C CXX)
    foreach(thing COMPILER FLAGS COMPILER_LAUNCHER)
        if(DEFINED CMAKE_${lang}_${thing})
            list(APPEND libzmq_compiler_args "-DCMAKE_${lang}_${thing}=${CMAKE_${lang}_${thing}}")
        endif()
    endforeach()
endforeach()

# Cross-compile: ExternalProject must know Windows or CMake adds Linux -rdynamic.
if(CMAKE_SYSTEM_NAME)
    list(APPEND libzmq_compiler_args "-DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}")
endif()
if(CMAKE_SYSTEM_VERSION)
    list(APPEND libzmq_compiler_args "-DCMAKE_SYSTEM_VERSION=${CMAKE_SYSTEM_VERSION}")
endif()
if(CMAKE_RC_COMPILER)
    list(APPEND libzmq_compiler_args "-DCMAKE_RC_COMPILER=${CMAKE_RC_COMPILER}")
endif()
if(CMAKE_TOOLCHAIN_FILE)
    list(APPEND libzmq_compiler_args "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}")
endif()
# MinGW has afunix.h, but libzmq's IPC code only includes it for MSVC.
if(WIN32 AND NOT MSVC)
    list(APPEND libzmq_compiler_args "-DZMQ_HAVE_IPC=OFF")
endif()

if(CMAKE_OSX_DEPLOYMENT_TARGET)
    list(APPEND libzmq_compiler_args "-DCMAKE_OSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET}")
endif()

include(ExternalProject)
include(ProcessorCount)
ExternalProject_Add(libzmq_external
    PREFIX ${LIBZMQ_PREFIX}
    URL ${LIBZMQ_URL}
    URL_HASH ${LIBZMQ_HASH}
    CMAKE_ARGS ${libzmq_compiler_args}
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5
    -DWITH_LIBSODIUM=ON -DENABLE_CURVE=ON -DZMQ_BUILD_TESTS=OFF -DWITH_PERF_TOOL=OFF -DENABLE_DRAFTS=OFF
    -DBUILD_SHARED=OFF -DBUILD_STATIC=ON -DWITH_DOC=OFF -DCMAKE_INSTALL_PREFIX=${LIBZMQ_PREFIX}
    BUILD_BYPRODUCTS ${LIBZMQ_PREFIX}/${CMAKE_INSTALL_LIBDIR}/libzmq.a
    )

add_library(libzmq_vendor STATIC IMPORTED GLOBAL)
add_dependencies(libzmq_vendor libzmq_external)
set_target_properties(libzmq_vendor PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${LIBZMQ_PREFIX}/include
    INTERFACE_COMPILE_DEFINITIONS ZMQ_STATIC
    IMPORTED_LOCATION ${LIBZMQ_PREFIX}/${CMAKE_INSTALL_LIBDIR}/libzmq.a)
if(WIN32)
    set_property(TARGET libzmq_vendor APPEND PROPERTY INTERFACE_LINK_LIBRARIES ws2_32 iphlpapi)
endif()
