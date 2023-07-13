cmake_minimum_required(VERSION 3.0.0)
project(infiniteidpq-pkcs11 VERSION 0.1.0 LANGUAGES C)
include(CTest)
enable_testing()

set(SOURCES
    src/infiniteidpq-pkcs11.c
)

add_library(infiniteidpq-pkcs11 ${SOURCES})

set_target_properties(infiniteidpq-pkcs11 PROPERTIES VERSION ${PROJECT_VERSION})
target_include_directories(infiniteidpq-pkcs11 PRIVATE include)
target_include_directories(infiniteidpq-pkcs11 PRIVATE src)
set_target_properties(infiniteidpq-pkcs11 PROPERTIES PUBLIC_HEADER include/infiniteidpq-pkcs11.h)

include(GNUInstallDirs)
install(TARGETS infiniteidpq-pkcs11
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})