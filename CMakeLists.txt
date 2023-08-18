cmake_minimum_required(VERSION 3.10)
set(PROJECT_NAME DMIDECODER)
set(TARGET_NAME dmidecoder)
project(${PROJECT_NAME} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

file(GLOB_RECURSE PROJECT_SOURCES CONFIGURE_DEPENDS
    "*.h"
    "*.cpp"
)

#boost win32
if(WIN32)
    if(MSVC)
        set(BOOST_ROOT "C:/boost_1_82_0_msvc")
        set(BOOST_INCLUDEDIR "C:/boost_1_82_0_msvc/include")
        set(BOOST_LIBRARYDIR "C:/boost_1_82_0_msvc/lib")
    endif()
endif()

#boost linux
if(UNIX AND NOT APPLE)
    set(BOOST_ROOT "/home/$ENV{USER}/boost_1_82_0_gcc")
    set(BOOST_INCLUDEDIR "/home/$ENV{USER}/boost_1_82_0_gcc/include")
    set(BOOST_LIBRARYDIR "/home/$ENV{USER}/boost_1_82_0_gcc/lib")
endif()

set(Boost_DEBUG ON)
set(Boost_USE_STATIC_LIBS ON)

#boost packages
find_package(Boost 1.82.0 EXACT COMPONENTS REQUIRED
    url
    json
    system
    date_time
    filesystem
    program_options
)

find_package(Qt5 COMPONENTS Core REQUIRED)

add_executable(${TARGET_NAME}
    ${PROJECT_SOURCES}
)

target_include_directories(${TARGET_NAME} PRIVATE
    ${Boost_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(${TARGET_NAME} PRIVATE
    Qt5::Core
    ${Boost_LIBRARIES}
    ${WIN_LINKER_LIBS}
    ${LINUX_LINKER_LIBS}
)

install(TARGETS ${TARGET_NAME}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
