where /q python.exe
IF errorlevel 1 (goto :ERR) ELSE (goto :MOF)

:MOF
echo "Success"
goto :EOF

:ERR
echo "Python not found - please install Python from python.org"

:EOF