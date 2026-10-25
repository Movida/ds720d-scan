/*
 * bot.h : transport USB Mass Storage Bulk-Only (BOT 1.0) côté noyau.
 *
 * Couche générique, au-dessus de usb.h : elle vaudrait pour tout appareil
 * Mass Storage Bulk-Only (docs/pilote.md, « Couches »). Étape 6d : GET_MAX_LUN.
 * Étape 6e : CBW, données, CSW et Reset Recovery, repris de src/bot.c (étapes 2
 * et 3c) ; ce que faisait l'outil sur WinUSB, le pilote le fait désormais en
 * URB. Elle ne connaît pas SCSI : le CDB lui est fourni tout fait, et c'est
 * l'appelant (noyau/ioctl.c) qui le passe d'abord à la barrière.
 */
#ifndef DS720D_BOT_NOYAU_H
#define DS720D_BOT_NOYAU_H

#include "usb.h"

#define BOT_LG_CBW 31 /* BOT §5.1, table 5.1 */
#define BOT_LG_CSW 13 /* BOT §5.2, table 5.2 */

/* État du transport, dans le contexte de l'appareil (mémoire non paginée :
 * la pile USB écrit le CSW dans csw, éventuellement par DMA). */
typedef struct _BOT {
    USB_CIBLE *usb;
    UCHAR interface;              /* pour le reset de classe (BOT §3.1) */
    const USB_PIPE *entrant, *sortant;
    ULONG prochain_tag;           /* dCBWTag de la prochaine commande */
    UCHAR cbw[BOT_LG_CBW];
    UCHAR csw[BOT_LG_CSW];
} BOT;

/* Étape atteinte par une commande (mêmes valeurs que DS720D_ETAPE_* de
 * ds720d_ioctl.h, vérifié par ioctl.c ; repris ici pour que cette couche ne
 * dépende pas de l'interface propre au DS-720D). */
#define BOT_ETAPE_RIEN 0
#define BOT_ETAPE_CBW 1
#define BOT_ETAPE_DONNEES 2
#define BOT_ETAPE_CSW 3

/* Ce qu'une commande a donné, pour la sortie de IOCTL_DS720D_BOT. */
typedef struct _BOT_RESULTAT {
    NTSTATUS resultat;            /* STATUS_SUCCESS si le CSW est valide et significatif */
    UCHAR etape;                  /* BOT_ETAPE_* */
    BOOLEAN reprise;              /* une Reset Recovery a été faite */
    UCHAR statut;                 /* bCSWStatus */
    ULONG residu;                 /* dCSWDataResidue */
    ULONG recus;                  /* octets passés pendant la phase de données */
    UCHAR cbw[BOT_LG_CBW];        /* copie du CBW envoyé */
    UCHAR csw[BOT_LG_CSW];        /* copie du CSW reçu */
} BOT_RESULTAT;

/* GET_MAX_LUN (BOT §3.2) sur l'interface donnée : *max_lun reçoit le plus haut
 * numéro de LUN, de 0 à 15. */
NTSTATUS BotLireMaxLun(USB_CIBLE *u, UCHAR interface, UCHAR *max_lun);

/* À appeler une fois la configuration choisie, avant toute commande. */
VOID BotInitialiser(BOT *b, USB_CIBLE *u, UCHAR interface, const USB_PIPE *entrant, const USB_PIPE *sortant);

/* Une commande Bulk-Only : CBW, puis lg octets de données dans un sens ou dans
 * l'autre (tampon non paginé), puis CSW. Remplit *r ; renvoie r->resultat. */
NTSTATUS BotCommande(BOT *b, UCHAR lun, const UCHAR *cdb, UCHAR lg_cdb, BOOLEAN sortant, PVOID donnees, ULONG lg,
                     BOT_RESULTAT *r);

/* Reset Recovery (BOT §5.3.4) : reset de classe, puis déblocage des deux pipes. */
NTSTATUS BotReprise(BOT *b);

#endif
