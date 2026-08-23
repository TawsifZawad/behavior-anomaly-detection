@echo off
REM Double-click to launch the Windows demo. With no arguments it shows
REM the [1] Own / [2] Analyze / [3] Live menu and keeps the window open.
REM Works from anywhere as long as this file stays in the project folder.
cd /d "%~dp0"
software\windows-demo.exe
