
@call :folder %CD%
@set P_DOC=%CURDIRNAME%doc
@set P_JAR=%CURDIRNAME%lib
@set P_SRC=%CURDIRNAME%src

@echo WARNING : do NOT put the compiled jar in the classpath or it will do nasty stuff 
@SET /P makedoc=Build javadoc ? [y/n]: 
@IF /i NOT "%makedoc%"=="y" GOTO :eof 
@del /F/S/Q %P_DOC%\* >NUL
@rmdir /S /Q %P_DOC% >NUL
@mkdir %P_DOC%
@cd %P_SRC%
::rem http://download.java.net/jdk8/docs/technotes/tools/solaris/javadoc.html
@javadoc -d "%P_DOC%" -sourcepath .\ -author -noqualifier all -quiet -tag copyright:tpo:"Copyright:" -tag license:tpo:"License:" -tag todo:a:"Not yet implemented:" -tag note:a:"Note:" -extdirs .\ -subpackages com
@cd %CURDIRNAME%

@goto :eof

:folder
@SET CURDIRNAME=%~dp0
@goto :eof
