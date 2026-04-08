where /q python.exe
IF errorlevel 1 (goto :ERROR) ELSE (goto :INST)

:ERROR
echo "Error: Python not found - please install Python from python.org"
goto :EOF

:INST
python.exe -m pip install pyyaml;
set thisdir=%~dp0
cd %thisdir%
cmd /k python.exe _install_.py

:EOF