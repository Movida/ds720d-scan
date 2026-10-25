/*
 * ds720d.h : ce que les sources du pilote partagent (étape 6e) : le contexte
 * de l'objet de périphérique, et les points d'entrée de ioctl.c.
 */
#ifndef DS720D_PILOTE_H
#define DS720D_PILOTE_H

#include "usb.h"
#include "bot.h"

/* Contexte de l'objet de périphérique : ce que le pilote sait du scanner
 * qu'il tient. KMDF l'alloue avec l'objet, mis à zéro, dans la mémoire non
 * paginée, et le libère avec lui. */
typedef struct _DS720D_APPAREIL {
    USB_CIBLE usb;              /* inscription auprès de la pile, configuration */
    UCHAR interface;            /* bInterfaceNumber de l'interface Bulk-Only */
    USB_PIPE entrant, sortant;  /* pipes bulk du transport Bulk-Only */
    UCHAR max_lun;              /* plus haut LUN, rendu par GET_MAX_LUN */
    BOT bot;                    /* transport Bulk-Only (6e) */
} DS720D_APPAREIL;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DS720D_APPAREIL, Ds720dAppareil)

/* Interface de périphérique et file des requêtes de l'outil (ioctl.c), à
 * créer dans EvtDriverDeviceAdd, une fois l'objet de périphérique créé. */
NTSTATUS Ds720dCreerInterface(WDFDEVICE appareil);

#endif
