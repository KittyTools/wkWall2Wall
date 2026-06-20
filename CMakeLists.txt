cmake_minimum_required(VERSION 3.20)
project(wkWall2Wall VERSION 0.1.0 LANGUAGES CXX)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "wkWall2Wall must be built as a 32-bit x86 DLL because Worms Armageddon is a 32-bit process.")
endif()

add_library(wkWall2Wall SHARED
    src/Config.cpp
    src/Logger.cpp
    src/Version.cpp
    src/WaHooks.cpp
    src/WaMemory.cpp
    src/WaTaskMessageCodec.cpp
    src/WallGameMessage.cpp
    src/WallMetadata.cpp
    src/WallProtocol.cpp
    src/WallSession.cpp
    src/WallSync.cpp
    src/WallTouch.cpp
    src/WallTransport.cpp
    src/dllmain.cpp
)

target_compile_features(wkWall2Wall PRIVATE cxx_std_20)
target_compile_definitions(wkWall2Wall PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(wkWall2Wall PRIVATE ddraw gdi32 opengl32 version)

set_target_properties(wkWall2Wall PROPERTIES
    OUTPUT_NAME "wkWall2Wall"
    PREFIX ""
)

if(MSVC)
    target_compile_options(wkWall2Wall PRIVATE /W4 /permissive-)
    set_property(TARGET wkWall2Wall PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
