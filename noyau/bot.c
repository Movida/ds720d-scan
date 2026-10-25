/*
 * bot.c : transport Bulk-Only côté noyau (étape 6d : GET_MAX_LUN). Voir bot.h.
 */
#include "bot.h"
#include "wpp.h"
#include "bot.tmh"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, BotLireMaxLun)
#endif

NTSTATUS BotLireMaxLun(USB_CIBLE *u, UCHAR interface, UCHAR *max_lun)
{
    /* GET_MAX_LUN, requête de classe Mass Storage Bulk-Only (BOT §3.2), le même
     * paquet que src/ds720d.c (lire_max_lun) et que Windows en 1b, trame 19223 :
     *   bmRequestType 0xA1 (appareil vers hôte, classe, destinataire l'interface)
     *   bRequest      0xFE (Get Max LUN)
     *   wValue        0
     *   wIndex        numéro de l'interface, lu dans les descripteurs
     *   wLength       1 : un seul octet, le plus haut numéro de LUN */
    const UCHAR setup[8] = {0xA1, 0xFE, 0x00, 0x00, interface, 0x00, 0x01, 0x00};
    UCHAR *octet;
    ULONG n = 0;
    NTSTATUS statut;

    PAGED_CODE();
    /* Tampon de l'étape DATA en mémoire non paginée : la pile USB peut y
     * écrire par DMA. Pas sur la pile du noyau, qui peut être déchargée quand
     * le fil attend. */
    octet = ExAllocatePool2(POOL_FLAG_NON_PAGED, 1, DS720D_ETIQUETTE);
    if (!octet)
        return STATUS_INSUFFICIENT_RESOURCES;
    statut = UsbControle(u, setup, octet, &n);
    if (NT_SUCCESS(statut) && n != 1) {
        /* BOT §3.2 permet aussi à un appareil sans LUN multiples de répondre
         * par un STALL : on s'arrêterait alors, comme src/ds720d.c, sans rien
         * tenter d'autre (UsbControle a déjà tracé l'erreur). */
        statut = STATUS_DEVICE_PROTOCOL_ERROR;
    } else if (NT_SUCCESS(statut) && *octet > 15) {
        statut = STATUS_DEVICE_PROTOCOL_ERROR; /* BOT §3.2 : de 0 à 15 */
    }
    if (NT_SUCCESS(statut)) {
        *max_lun = *octet;
        Trace(TRACE_LEVEL_INFORMATION, TRACE_BOT, "GET_MAX_LUN : plus haut LUN %u", *max_lun);
    } else {
        Trace(TRACE_LEVEL_ERROR, TRACE_BOT, "GET_MAX_LUN a echoue (0x%08lX, %lu octet(s))", (ULONG)statut, n);
    }
    ExFreePoolWithTag(octet, DS720D_ETIQUETTE);
    return statut;
}
