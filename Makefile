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

all: out\essai_trace.exe out\essai_bot.exe out\essai_image.exe out\essai_permis.exe out\ds720d.exe out\ds720dk.exe out\essai_refus.exe out\convertir.exe out\bascule_winusb.exe

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

out\essai_bot.exe: out\essai_bot.obj out\bot.obj out\tunnel.obj out\permis.obj out\trace.obj
	link $(LDFLAGS) /OUT:$@ out\essai_bot.obj out\bot.obj out\tunnel.obj out\permis.obj out\trace.obj

# Barrière des commandes observées (étape 6e), partagée avec le pilote noyau :
# du C pur, compilé ici pour l'outil et dans la cible « noyau » pour le pilote.
out\permis.obj: src\permis.c src\permis.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\permis.c

# Essai de la barrière, sans scanner : chaque requête observée passe, chaque
# variante est refusée.
out\essai_permis.obj: src\essai_permis.c src\permis.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\essai_permis.c

out\essai_permis.exe: out\essai_permis.obj out\permis.obj
	link $(LDFLAGS) /OUT:$@ out\essai_permis.obj out\permis.obj

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

out\tunnel.obj: src\tunnel.c src\tunnel.h src\bot.h src\permis.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\tunnel.c

# winusb.lib : fonctions WinUsb_* ; setupapi.lib : recherche du scanner (SetupDi*) ;
# cfgmgr32.lib : état réel de l'appareil (CM_Get_DevNode_Status). Toutes viennent du Windows SDK.
out\ds720d.exe: out\ds720d.obj out\bot.obj out\tunnel.obj out\permis.obj out\peripherique.obj out\trace.obj
	link $(LDFLAGS) /OUT:$@ out\ds720d.obj out\bot.obj out\tunnel.obj out\permis.obj out\peripherique.obj out\trace.obj winusb.lib setupapi.lib cfgmgr32.lib

# ds720dk.exe (étape 6e) : le même programme que ds720d.exe, mais qui parle au
# scanner par notre pilote noyau (client_noyau.c, deux IOCTL) au lieu de
# WinUSB (peripherique.c) et du Bulk-Only en espace utilisateur (bot.c).
# setupapi.lib : recherche de l'interface du pilote.
out\client_noyau.obj: src\client_noyau.c src\bot.h src\peripherique.h src\trace.h noyau\ds720d_ioctl.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\client_noyau.c

out\ds720dk.exe: out\ds720d.obj out\tunnel.obj out\permis.obj out\client_noyau.obj out\trace.obj
	link $(LDFLAGS) /OUT:$@ out\ds720d.obj out\tunnel.obj out\permis.obj out\client_noyau.obj out\trace.obj setupapi.lib

# Essai de la barrière sur le vrai pilote (6e), dans la VM : deux requêtes
# inoffensives absentes de la liste, qui doivent être refusées.
out\essai_refus.obj: src\essai_refus.c src\bot.h src\peripherique.h src\trace.h
	@if not exist out mkdir out
	cl $(CFLAGS) /c /Fo$@ src\essai_refus.c

out\essai_refus.exe: out\essai_refus.obj out\client_noyau.obj out\trace.obj
	link $(LDFLAGS) /OUT:$@ out\essai_refus.obj out\client_noyau.obj out\trace.obj setupapi.lib

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
# Deux définitions que le projet MSBuild du WDK pose pour tout pilote
# (WindowsDriver.Shared.Props et WindowsDriver.Common.props), ajoutées en 6c :
#   WINNT=1                   evntrace.h n'ouvre son contenu qu'avec elle (ou
#                             _WINNT_, propre à l'espace utilisateur) : sans
#                             elle, ni TRACE_LEVEL_* ni rien d'ETW, d'où l'échec
#                             de la première construction des traces WPP
#   DEPRECATE_DDK_FUNCTIONS=1 signale à la compilation les fonctions du noyau
#                             déclarées obsolètes (ExAllocatePoolWithTag…)
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
	/DNTDDI_VERSION=0x0A000008 /D_WIN32_WINNT=0x0A00 /DWINNT=1 /DDEPRECATE_DDK_FUNCTIONS=1 /Fdout\noyau\vc.pdb
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
#
# Traces WPP (étape 6c, noyau\wpp.h) : tracewpp lit noyau\wpp.h (-scan) et
# chaque source, et écrit un .tmh par source dans out\noyau, que le source
# inclut (d'où /Iout\noyau). Options :
#   -km          pilote noyau : modèle km-default.tpl
#   -I…\Rev1     configuration et modèles livrés avec le WDK (defaultwpp.ini, *.tpl)
#   -p:ds720d    nom de module des messages (sinon le nom du dossier courant)
#   -odir:       dossier des .tmh générés, hors des sources
# Comme le projet MSBuild du WDK quand l'enregistreur IFR est demandé
# (WindowsDriver.Common.targets) : ENABLE_WPP_RECORDER=1 à la compilation et
# wpprecorder.lib à l'édition de liens. Les formats des messages vont dans le
# PDB (out\noyau\ds720d.pdb), où WinDbg les retrouve.
TRACEWPP = "$(WDK)\bin\$(WDKVER)\x64\tracewpp.exe"
WPPFLAGS = -km -I"$(WDK)\bin\$(WDKVER)\WppConfig\Rev1" -scan:noyau\wpp.h -p:ds720d -odir:out\noyau

#
# Sources du pilote, une couche par fichier (docs/pilote.md, « Couches ») :
#   ds720d.c  PnP, alimentation, démarrage du scanner
#   usb.c     URB : contrôle, configuration, abandon des pipes (6d), bulk et déblocage (6e)
#   bot.c     transport Bulk-Only (6d : GET_MAX_LUN ; 6e : CBW, CSW, Reset Recovery)
#   ioctl.c   interface et requêtes de l'outil (6e)
#   ..\src\permis.c  la barrière des commandes observées, partagée avec l'outil,
#             compilée ici avec les options du noyau ; sans trace WPP
# Chacun a son .tmh, généré par une règle à lui : nmake lancerait sinon
# tracewpp une fois par cible d'une règle commune. /Isrc pour permis.h.
KOBJS = out\noyau\ds720d.obj out\noyau\usb.obj out\noyau\bot.obj out\noyau\ioctl.obj out\noyau\permis.obj

out\noyau\ds720d.tmh: noyau\ds720d.c noyau\wpp.h
	@if not exist out\noyau mkdir out\noyau
	$(TRACEWPP) $(WPPFLAGS) noyau\ds720d.c

out\noyau\usb.tmh: noyau\usb.c noyau\wpp.h
	@if not exist out\noyau mkdir out\noyau
	$(TRACEWPP) $(WPPFLAGS) noyau\usb.c

out\noyau\bot.tmh: noyau\bot.c noyau\wpp.h
	@if not exist out\noyau mkdir out\noyau
	$(TRACEWPP) $(WPPFLAGS) noyau\bot.c

out\noyau\ioctl.tmh: noyau\ioctl.c noyau\wpp.h
	@if not exist out\noyau mkdir out\noyau
	$(TRACEWPP) $(WPPFLAGS) noyau\ioctl.c

out\noyau\ds720d.obj: noyau\ds720d.c noyau\ds720d.h noyau\usb.h noyau\bot.h noyau\wpp.h out\noyau\ds720d.tmh
	cl $(KCFLAGS) /DENABLE_WPP_RECORDER=1 /Iout\noyau /c /Fo$@ noyau\ds720d.c

out\noyau\usb.obj: noyau\usb.c noyau\usb.h noyau\wpp.h out\noyau\usb.tmh
	cl $(KCFLAGS) /DENABLE_WPP_RECORDER=1 /Iout\noyau /c /Fo$@ noyau\usb.c

out\noyau\bot.obj: noyau\bot.c noyau\bot.h noyau\usb.h noyau\wpp.h out\noyau\bot.tmh
	cl $(KCFLAGS) /DENABLE_WPP_RECORDER=1 /Iout\noyau /c /Fo$@ noyau\bot.c

out\noyau\ioctl.obj: noyau\ioctl.c noyau\ds720d.h noyau\ds720d_ioctl.h noyau\usb.h noyau\bot.h src\permis.h noyau\wpp.h out\noyau\ioctl.tmh
	cl $(KCFLAGS) /DENABLE_WPP_RECORDER=1 /Iout\noyau /Isrc /c /Fo$@ noyau\ioctl.c

out\noyau\permis.obj: src\permis.c src\permis.h
	@if not exist out\noyau mkdir out\noyau
	cl $(KCFLAGS) /c /Fo$@ src\permis.c

# usbdex.lib : USBD_CreateHandle, USBD_UrbAllocate et les autres routines USBD
# de Windows 8 et suivants (usbdlib.h) ; wpprecorder.lib : l'IFR (6c).
out\noyau\ds720d.sys: $(KOBJS)
	link $(KLDFLAGS) /OUT:$@ $(KOBJS) $(KLIBS) usbdex.lib wpprecorder.lib

clean:
	@if exist out rmdir /s /q out
