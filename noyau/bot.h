/*
 * bot.h : transport USB Mass Storage Bulk-Only (BOT 1.0) côté noyau.
 *
 * Couche générique, au-dessus de usb.h : elle vaudrait pour tout appareil
 * Mass Storage Bulk-Only (docs/pilote.md, « Couches »). Étape 6d : la seule
 * requête de classe GET_MAX_LUN ; CBW, CSW et Reset Recovery viennent en 6e,
 * repris de src/bot.c.
 */
#ifndef DS720D_BOT_NOYAU_H
#define DS720D_BOT_NOYAU_H

#include "usb.h"

/* GET_MAX_LUN (BOT §3.2) sur l'interface donnée : *max_lun reçoit le plus haut
 * numéro de LUN, de 0 à 15. */
NTSTATUS BotLireMaxLun(USB_CIBLE *u, UCHAR interface, UCHAR *max_lun);

#endif
