@echo off
command /C echo changing to dos-16 file structure
set C_DEFINES=

REM set copycmd=/Y
REM copy sources.ce sources

build -cZ
copy .\obj%BUILD_ALT_DIR%\i386\*.sys ..
