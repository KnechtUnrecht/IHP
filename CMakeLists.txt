cmake_minimum_required(VERSION 3.16)
project(IHP LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Suppress miniz warnings
if(MSVC)
    add_compile_options(/W3 /wd4244 /wd4267 /wd4996)
else()
    add_compile_options(-Wall -Wextra -Wno-unused-parameter)
endif()

# ── Third-party sources ───────────────────────────────────────────────

# Dear ImGui
set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/third_party/imgui)
set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/imgui_impl_win32.cpp
    ${IMGUI_DIR}/imgui_impl_dx11.cpp
)

# miniz (compiled as C)
set(MINIZ_DIR ${CMAKE_SOURCE_DIR}/third_party/miniz)
set(MINIZ_SOURCES
    ${MINIZ_DIR}/miniz.c
    ${MINIZ_DIR}/miniz_tdef.c
    ${MINIZ_DIR}/miniz_tinfl.c
    ${MINIZ_DIR}/miniz_zip.c
)

# ── Application sources ──────────────────────────────────────────────

set(APP_SOURCES
    src/main.cpp
    src/gui/gui.cpp
    src/gui/code_viewer.cpp
    src/scanner/scanner_engine.cpp
    src/scanner/jar_reader.cpp
    src/scanner/class_parser.cpp
    src/scanner/bytecode_decoder.cpp
    src/scanner/java_decompiler.cpp
    src/scanner/jar_metadata.cpp
    src/scanner/scan_export.cpp
    src/scanner/signature_db.cpp
    src/scanner/detections/rat_detector.cpp
    src/scanner/detections/obfuscation_detector.cpp
    src/scanner/detections/trojan_detector.cpp
    src/updater/updater.cpp
    src/utils/hash.cpp
)

# ── Build executable ─────────────────────────────────────────────────

add_executable(${PROJECT_NAME} WIN32
    ${APP_SOURCES}
    ${IMGUI_SOURCES}
    ${MINIZ_SOURCES}
    ${CMAKE_SOURCE_DIR}/IHP.rc
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party/imgui
    ${CMAKE_SOURCE_DIR}/third_party/miniz
    ${CMAKE_SOURCE_DIR}/third_party/json
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    d3d11
    dxgi
    bcrypt
    ole32
    shell32
    winhttp
)

# Set output name
set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME "IHP"
    VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)
