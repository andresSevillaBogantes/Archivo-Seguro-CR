@echo off
cd /d "%~dp0"
py -m pip install -r requirements.txt
if errorlevel 1 (
 echo No se pudo instalar la biblioteca. Revise que Python este instalado.
 pause
 exit /b 1
)
py aplicacion.py
if errorlevel 1 pause
