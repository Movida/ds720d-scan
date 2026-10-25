/*
 * ds720d_ioctl.h : interface entre le pilote ds720d.sys et l'outil ds720dk.exe
 * (étape 6e, docs/pilote.md § 2). Inclus des deux côtés : pilote (ntddk.h) et
 * outil (windows.h, winioctl.h). Pour définir le GUID, et non seulement le
 * déclarer, un seul source de chaque côté inclut initguid.h avant ce fichier.
 *
 * L'outil trouve le scanner par l'interface de périphérique ci-dessous, que
 * le pilote enregistre (WdfDeviceCreateDeviceInterface), l'ouvre, puis lui
 * envoie deux sortes de requêtes, toutes deux en METHOD_BUFFERED : le
 * gestionnaire d'E/S recopie les octets de l'outil dans un tampon système non
 * paginé, que le pilote confie tel quel à l'URB, puis recopie la réponse
 * (docs/pilote.md § 2, « Interface avec l'outil »). Chaque requête passe par
 * la barrière du pilote (src/permis.c) avant le moindre envoi : une requête
 * refusée échoue avec ERROR_ACCESS_DENIED, sans rien sur le bus.
 */
#ifndef DS720D_IOCTL_H
#define DS720D_IOCTL_H

/* Interface de périphérique du pilote, GUID tiré au hasard pour ce projet le
 * 25/10/2026 : {14E7FF18-2C35-493C-B912-605268730264}. */
DEFINE_GUID(GUID_DEVINTERFACE_DS720D, 0x14e7ff18, 0x2c35, 0x493c, 0xb9, 0x12, 0x60, 0x52, 0x68, 0x73, 0x02, 0x64);

/* Codes d'IOCTL (CTL_CODE : type d'appareil, fonction, méthode, accès). Type
 * 0x8720 et fonctions à partir de 0x800 : plages laissées aux fabricants (doc
 * WDK, « Defining I/O Control Codes »). Accès lecture et écriture : la poignée
 * doit avoir été ouverte avec GENERIC_READ | GENERIC_WRITE. */
/* Non signé : décalé de 16 bits par CTL_CODE, 0x8720 dépasserait la plage
 * d'un int (code 0x8720xxxx). */
#define DS720D_TYPE_APPAREIL 0x8720u
#define IOCTL_DS720D_CONTROLE \
    CTL_CODE(DS720D_TYPE_APPAREIL, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_DS720D_BOT CTL_CODE(DS720D_TYPE_APPAREIL, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

/*
 * IOCTL_DS720D_CONTROLE : un transfert de contrôle entrant sur le pipe par
 * défaut. Entrée : les 8 octets du paquet SETUP (USB 2.0 §9.3), qui doivent
 * être l'un de ceux de 1b (permis_controle). Sortie : wLength octets au plus,
 * le nombre reçu dans le nombre d'octets rendus par DeviceIoControl.
 */

/*
 * IOCTL_DS720D_BOT : une commande Bulk-Only complète (BOT §5 : CBW, données,
 * CSW), dont le pilote construit et contrôle le CBW et le CSW, avec Reset
 * Recovery en cas d'erreur de transport (BOT §5.3.4).
 * Entrée : DS720D_BOT_ENTREE, suivie, pour une commande sortante, des lg
 * octets à envoyer. Sortie : DS720D_BOT_SORTIE, suivie, pour une commande
 * entrante, des octets reçus (lg au plus).
 * La requête réussit dès que le pilote l'a traitée, même si le transport a
 * échoué : le détail est dans resultat, et les octets du CBW et du CSW sont
 * rendus pour que l'outil écrive sa trace au format commun.
 */
#define DS720D_LG_MAX 65536u /* plus grande phase de données : une lecture 0xC3 */

typedef struct _DS720D_BOT_ENTREE {
    UCHAR cdb[16];   /* CBWCB, complété de zéros */
    UCHAR lg_cdb;    /* bCBWCBLength, de 1 à 16 */
    UCHAR sortant;   /* 1 : données vers le scanner ; 0 : vers l'hôte */
    UCHAR lun;       /* bCBWLUN */
    UCHAR reserve;   /* 0 */
    ULONG lg;        /* dCBWDataTransferLength, DS720D_LG_MAX au plus */
} DS720D_BOT_ENTREE;

/* Étape atteinte par le transport (champ etape de la sortie). */
#define DS720D_ETAPE_RIEN 0     /* rien n'est parti */
#define DS720D_ETAPE_CBW 1      /* CBW envoyé */
#define DS720D_ETAPE_DONNEES 2  /* phase de données passée (ou absente) */
#define DS720D_ETAPE_CSW 3      /* CSW de 13 octets reçu */

typedef struct _DS720D_BOT_SORTIE {
    LONG resultat;   /* NTSTATUS : 0 si un CSW valide et significatif a été lu */
    UCHAR etape;     /* DS720D_ETAPE_* */
    UCHAR reprise;   /* 1 si le pilote a fait une Reset Recovery */
    UCHAR statut;    /* bCSWStatus, si etape vaut DS720D_ETAPE_CSW */
    UCHAR reserve;
    ULONG residu;    /* dCSWDataResidue */
    ULONG recus;     /* octets passés pendant la phase de données */
    UCHAR cbw[31];   /* le CBW tel qu'envoyé (BOT §5.1) */
    UCHAR csw[13];   /* le CSW tel que reçu (BOT §5.2) */
} DS720D_BOT_SORTIE;

/* Même disposition des deux côtés : mêmes types, même compilateur ; on le
 * vérifie quand même à la compilation. */
_Static_assert(sizeof(DS720D_BOT_ENTREE) == 24 && sizeof(DS720D_BOT_SORTIE) == 60, "disposition des structures");

#endif
