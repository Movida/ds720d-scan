# Makefile pour nmake, l'outil de construction livré avec les Build Tools Visual Studio.
# Se lance par construire.cmd, qui prépare d'abord l'environnement du compilateur.
#
# Pourquoi nmake et un Makefile écrit à la main plutôt qu'un projet .vcxproj
# (MSBuild) ou CMake : chaque option du compilateur et de l'éditeur de liens est
# visible ici, sans couche qui la génère. Les pilotes noyau suivent la même règle
# (étape 5f, cible « noyau » plus bas) : MSBuild n'est que la voie habituelle du
# WDK, cl et link font le vrai travail et se pilotent très bien à la main.
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

# Image brute vers PGM ou PNG (étape 3f), rendue depuis l'étape 4d : ne parle pas au scanner.
out\image.obj: src\image.c src\image.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\image.c

out\convertir.obj: src\convertir.c src\image.h src\rendu.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\convertir.c

# Rendu de la page (étape 4d) : recadrage, courbe de tons, verso, 600 dpi.
out\rendu.obj: src\rendu.c src\rendu.h src\image.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\rendu.c

out\convertir.exe: out\convertir.obj out\image.obj out\rendu.obj
	link $(LDFLAGS) /OUT:$@ out\convertir.obj out\image.obj out\rendu.obj

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

# --- Pilotes noyau (étape 5f) : construits par « construire.cmd noyau » --------------
#
# Le WDK 10.0.26100 fournit en-têtes et bibliothèques du noyau et de KMDF.
# /X fait oublier à cl la variable INCLUDE posée par vcvars64.bat : elle pointe
# vers les en-têtes de l'espace utilisateur (um, ucrt), qui n'ont rien à faire
# dans un pilote. On ne garde que ceux du WDK : km\crt (la petite bibliothèque
# C du noyau : ctype.h, excpt.h, intrin.h…), km, shared et KMDF.
#
# KMDF 1.15 : la plus ancienne version du WDK 26100, présente depuis Windows 10
# 1507 ; nos pilotes n'ont besoin d'aucune fonction plus récente, et une version
# basse se charge partout (WdfLdr refuse une version plus haute que celle du
# système). KMDF_VERSION_MAJOR/MINOR ne sont lus par les en-têtes qu'à partir
# de KMDF 1.25 : avec 1.15, ils ne servent qu'aux messages de DriverEntry.
#
# Cible des en-têtes du noyau (étape 6b) : NTDDI_VERSION 0x0A000008, Windows 10
# 2004 (NTDDI_WIN10_VB, sdkddkver.h), la première version qui a ExAllocatePool2
# (allocations remises à zéro, à partir de 6d). Sans ce réglage, les en-têtes
# viseraient la dernière version de Windows et laisseraient appeler des
# fonctions absentes des versions plus anciennes, sans le moindre avertissement.
# _WIN32_WINNT suit (0x0A00, Windows 10), comme l'exige sdkddkver.h.
#
# Options propres au noyau :
#   /kernel    code noyau : pas d'exceptions C++, pas de RTTI, définit _KERNEL_MODE
#   /GS        cookie de pile, vérifié par BufferOverflowFastFailK.lib (noyau)
#   /Gy        une fonction par section, pour que /OPT:REF écarte les inutiles
#   /D_WIN64 /D_AMD64_ /DAMD64   architecture, attendue par les en-têtes km
# Aucun avertissement n'est coupé ici : le seul que lève KMDF (C4324) l'est
# autour de #include <wdf.h> dans le source.
WDK = C:\Program Files (x86)\Windows Kits\10
WDKVER = 10.0.26100.0
KMDF_MAJ = 1
KMDF_MIN = 15
KCFLAGS = /nologo /utf-8 /std:c17 /W4 /WX /Zi /Od /kernel /GS /Gy /X \
	/I"$(WDK)\Include\$(WDKVER)\km\crt" /I"$(WDK)\Include\$(WDKVER)\km" \
	/I"$(WDK)\Include\$(WDKVER)\shared" /I"$(WDK)\Include\wdf\kmdf\$(KMDF_MAJ).$(KMDF_MIN)" \
	/D_WIN64 /D_AMD64_ /DAMD64 /DKMDF_VERSION_MAJOR=$(KMDF_MAJ) /DKMDF_VERSION_MINOR=$(KMDF_MIN) \
	/DNTDDI_VERSION=0x0A000008 /D_WIN32_WINNT=0x0A00 /Fdout\noyau\vc.pdb
# Options de link pour un pilote :
#   /DRIVER /SUBSYSTEM:NATIVE   image noyau, chargée par le gestionnaire d'E/S
#   /ENTRY:FxDriverEntry        entrée de KMDF (WdfDriverEntry.lib) : lie le pilote
#                               à WdfLdr, initialise le cookie /GS, puis appelle DriverEntry
#   /NODEFAULTLIB               aucune bibliothèque C de l'espace utilisateur
#   /RELEASE                    somme de contrôle de l'en-tête PE, attendue d'une image noyau
#   /OPT:REF /OPT:ICF           écarte le code inutile et fusionne les doublons, comme
#                               le WDK ; /DEBUG les désactiverait sinon
KLDFLAGS = /nologo /DEBUG /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:FxDriverEntry /NODEFAULTLIB \
	/MACHINE:X64 /RELEASE /OPT:REF /OPT:ICF /LIBPATH:"$(WDK)\Lib\$(WDKVER)\km\x64" \
	/LIBPATH:"$(WDK)\Lib\wdf\kmdf\x64\$(KMDF_MAJ).$(KMDF_MIN)"
# ntoskrnl.lib et hal.lib : services du noyau ; BufferOverflowFastFailK.lib : /GS ;
# WdfDriverEntry.lib : FxDriverEntry ; WdfLdr.lib : chargement de la bibliothèque KMDF.
KLIBS = ntoskrnl.lib hal.lib BufferOverflowFastFailK.lib WdfDriverEntry.lib WdfLdr.lib

noyau: out\noyau\bonjour.sys out\noyau\ds720d.sys

# Pilote d'essai sans matériel (étape 5f) : DriverEntry, DbgPrint, déchargement.
out\noyau\bonjour.obj: noyau\bonjour.c
	@if not exist out\noyau mkdir out\noyau
	cl $(KCFLAGS) /c /Fo$@ noyau\bonjour.c

out\noyau\bonjour.sys: out\noyau\bonjour.obj
	link $(KLDFLAGS) /OUT:$@ out\noyau\bonjour.obj $(KLIBS)

# Pilote du scanner (étape 6, docs/pilote.md). Le paquet d'installation (INF,
# catalogue, signatures) se fait ensuite par noyau\paquet.ps1 : signer demande
# le certificat du magasin de l'utilisateur, ce qui relève d'un script plutôt
# que de la construction.
out\noyau\ds720d.obj: noyau\ds720d.c
	@if not exist out\noyau mkdir out\noyau
	cl $(KCFLAGS) /c /Fo$@ noyau\ds720d.c

out\noyau\ds720d.sys: out\noyau\ds720d.obj
	link $(KLDFLAGS) /OUT:$@ out\noyau\ds720d.obj $(KLIBS)

clean:
	@if exist out rmdir /s /q out
