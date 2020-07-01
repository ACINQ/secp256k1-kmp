cmake_minimum_required(VERSION 3.10.0)

add_library( secp256k1-jni SHARED
    ${CMAKE_CURRENT_LIST_DIR}/../../../c/src/org_bitcoin_Secp256k1CFunctions.c
)

target_include_directories( secp256k1-jni
    PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../../../../native/secp256k1
    PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../../../c/headers/java
)

target_link_libraries( secp256k1-jni
    ${CMAKE_CURRENT_LIST_DIR}/../../../../native/build/android-${ANDROID_ABI}/libsecp256k1.a
)
