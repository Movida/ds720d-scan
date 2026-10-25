# Makefile pour nmake, l'outil de construction livré avec les Build Tools Visual Studio.
# Se lance par construire.cmd, qui prépare d'abord l'environnement du compilateur.
#
# Pourquoi nmake et un Makefile écrit à la main plutôt qu'un projet .vcxproj
# (MSBuild) ou CMake : chaque option du compilateur et de l'éditeur de liens est
# visible ici, sans couche qui la génère. Le WDK de l'étape 6 passera par MSBuild,
# imposé pour les pilotes ; d'ici là, on garde le plus simple et le plus lisible.
#
# Options de cl.exe :
#   /utf-8     sources et chaînes en UTF-8 (commentaires en français)
#   /std:c17   C standard, sans extensions C++
#   /W4 /WX    avertissements au niveau 4, traités comme des erreurs
#   /Zi /Od    informations de débogage, sans optimisation : plus simple à suivre
#   /MT        bibliothèque C liée en statique : l'exécutable tourne sans redistribuable
CFLAGS = /nologo /utf-8 /std:c17 /W4 /WX /Zi /Od /MT /Fdout\vc.pdb
LDFLAGS = /nologo /DEBUG

all: out\essai_trace.exe out\bascule_winusb.exe

out\bascule_winusb.obj: src\bascule_winusb.c
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\bascule_winusb.c

# newdev.lib : DiInstallDevice ; advapi32.lib : test d'élévation du jeton.
out\bascule_winusb.exe: out\bascule_winusb.obj
	link $(LDFLAGS) /OUT:$@ out\bascule_winusb.obj setupapi.lib newdev.lib advapi32.lib

out\trace.obj: src\trace.c src\trace.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\trace.c

out\essai_trace.obj: src\essai_trace.c src\trace.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\essai_trace.c

out\essai_trace.exe: out\essai_trace.obj out\trace.obj
	link $(LDFLAGS) /OUT:$@ out\essai_trace.obj out\trace.obj

clean:
	@if exist out rmdir /s /q out
