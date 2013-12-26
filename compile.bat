@IF [%1]==[] GOTO :help
@IF [%1]==[/?] GOTO :help
@IF [%1]==[-help] GOTO :help
@IF [%1]==[--help] GOTO :help

@call :folder %CD%
@set P_CLASS=%CURDIRNAME%class
@set P_JAR=%CURDIRNAME%lib
@set P_SRC=%CURDIRNAME%src

@if not exist %P_CLASS% mkdir %P_CLASS%
@if exist %P_JAR%\%1.jar del /F/Q %P_JAR%\%1.jar >NUL
@del /F/S/Q %P_CLASS%\* >NUL
@rmdir /S /Q %P_CLASS%\com >NUL
@cd %P_SRC%
@javac -d "%P_CLASS%" %1.java
@cd %CURDIRNAME%

@SET /P dojar=Make %1.jar ? [y/n]: 
@IF /i NOT "%dojar%"=="y" GOTO :eof 
@cd %P_CLASS%
@echo Manifest-Version: 1.0 > manifest.tmp
@jar -cfme %P_JAR%/%1.jar manifest.tmp %1 *
@del /F/Q manifest.tmp
@cd %CURDIRNAME%

@goto :eof

:folder
@SET CURDIRNAME=%~dp0
@goto :eof

:help
@echo Usage: compile {name of the java main class without the extension}
@echo Example: compile test
@goto :eof