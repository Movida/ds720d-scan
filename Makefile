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

all: out\essai_trace.exe out\essai_bot.exe out\essai_image.exe out\ds720d.exe out\convertir.exe out\bascule_winusb.exe

# Image brute vers PGM ou PNG (étape 3f) : ne parle pas au scanner.
out\image.obj: src\image.c src\image.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\image.c

out\convertir.obj: src\convertir.c src\image.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\convertir.c

out\convertir.exe: out\convertir.obj out\image.obj
	link $(LDFLAGS) /OUT:$@ out\convertir.obj out\image.obj

# Sommes de contrôle de image.c contre des valeurs de référence publiées.
out\essai_image.obj: src\essai_image.c src\image.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\essai_image.c

out\essai_image.exe: out\essai_image.obj out\image.obj
	link $(LDFLAGS) /OUT:$@ out\essai_image.obj out\image.obj

# Essai de bot.c et tunnel.c contre un faux périphérique (bouchons dans essai_bot.c) :
# ni peripherique.obj ni winusb.lib, rien ne peut partir vers le scanner.
out\essai_bot.obj: src\essai_bot.c src\bot.h src\peripherique.h src\trace.h src\tunnel.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\essai_bot.c

out\essai_bot.exe: out\essai_bot.obj out\bot.obj out\tunnel.obj out\trace.obj
	link $(LDFLAGS) /OUT:$@ out\essai_bot.obj out\bot.obj out\tunnel.obj out\trace.obj

out\bascule_winusb.obj: src\bascule_winusb.c
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\bascule_winusb.c

# newdev.lib : DiInstallDevice ; advapi32.lib : test d'élévation du jeton.
out\bascule_winusb.exe: out\bascule_winusb.obj
	link $(LDFLAGS) /OUT:$@ out\bascule_winusb.obj setupapi.lib newdev.lib advapi32.lib

out\trace.obj: src\trace.c src\trace.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\trace.c

out\peripherique.obj: src\peripherique.c src\peripherique.h src\trace.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\peripherique.c

out\bot.obj: src\bot.c src\bot.h src\peripherique.h src\trace.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\bot.c

out\ds720d.obj: src\ds720d.c src\bot.h src\peripherique.h src\trace.h src\tunnel.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\ds720d.c

out\tunnel.obj: src\tunnel.c src\tunnel.h src\bot.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\tunnel.c

# winusb.lib : fonctions WinUsb_* ; setupapi.lib : recherche du scanner (SetupDi*) ;
# cfgmgr32.lib : état réel de l'appareil (CM_Get_DevNode_Status). Toutes viennent du Windows SDK.
out\ds720d.exe: out\ds720d.obj out\bot.obj out\tunnel.obj out\peripherique.obj out\trace.obj
	link $(LDFLAGS) /OUT:$@ out\ds720d.obj out\bot.obj out\tunnel.obj out\peripherique.obj out\trace.obj winusb.lib setupapi.lib cfgmgr32.lib

out\essai_trace.obj: src\essai_trace.c src\trace.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\essai_trace.c

out\essai_trace.exe: out\essai_trace.obj out\trace.obj
	link $(LDFLAGS) /OUT:$@ out\essai_trace.obj out\trace.obj

clean:
	@if exist out rmdir /s /q out
