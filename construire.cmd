@echo off
rem Construit les programmes C du depot avec MSVC (cl.exe) et nmake.
rem Usage : construire.cmd [cible nmake], par exemple « construire.cmd clean ».
rem
rem cl.exe ne trouve ses en-tetes et bibliotheques (Windows SDK compris) que si
rem vcvars64.bat a rempli les variables INCLUDE, LIB et PATH. On localise
rem l'installation avec vswhere, l'outil que Microsoft fournit pour cela, plutot
rem que de figer un chemin qui change d'une version a l'autre.
setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo vswhere introuvable : les Build Tools Visual Studio sont-ils installes ?
    exit /b 1
)
set "VS="
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS=%%i"
if not defined VS (
    echo Compilateur C x64 introuvable dans les Build Tools.
    exit /b 1
)
rem vcvars64.bat appelle lui-meme vswhere par son nom : on le met dans le PATH,
rem sinon il affiche « 'vswhere.exe' n'est pas reconnu » (sans gravite, mais trompeur).
set "PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer;%PATH%"
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
cd /d "%~dp0"
nmake /nologo %*
