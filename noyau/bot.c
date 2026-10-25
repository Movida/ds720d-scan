/*
 * bot.c : transport Bulk-Only côté noyau. Voir bot.h.
 *
 * Étape 6e : CBW, données et CSW, avec la reprise sur erreur de src/bot.c,
 * selon BOT §5.3 et §6.7 :
 *   - STALL pendant les données : on débloque le pipe et on lit le CSW quand
 *     même (BOT §6.7.2 en entrée, §6.7.3 en sortie) ;
 *   - STALL à la lecture du CSW : on débloque et on réessaie une fois (BOT
 *     §5.3.3, figure 2) ;
 *   - CBW refusé, CSW invalide ou non significatif, erreur de phase, appareil
 *     muet : Reset Recovery (BOT §5.3.4), puis la commande échoue.
 * Aucune de ces situations n'apparaît dans les captures du pilote Brother : la
 * reprise ne s'appuie que sur la spec (CLAUDE.md : commande documentée).
 */
#include "bot.h"
#include "wpp.h"
#include "bot.tmh"

#define SIGNATURE_CBW 0x43425355u /* 'USBC' en petit-boutiste, BOT §5.1 */
#define SIGNATURE_CSW 0x53425355u /* 'USBS' en petit-boutiste, BOT §5.2 */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, BotLireMaxLun)
#pragma alloc_text(PAGE, BotInitialiser)
#pragma alloc_text(PAGE, BotCommande)
#pragma alloc_text(PAGE, BotReprise)
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

VOID BotInitialiser(BOT *b, USB_CIBLE *u, UCHAR interface, const USB_PIPE *entrant, const USB_PIPE *sortant)
{
    PAGED_CODE();
    b->usb = u;
    b->interface = interface;
    b->entrant = entrant;
    b->sortant = sortant;
    /* dCBWTag : valeur libre que l'appareil recopie dans le CSW (BOT §5.1).
     * Comme src/bot.c : un compteur qui part du compteur de performances,
     * différent à chaque démarrage, pour qu'un CSW resté en attente d'une
     * commande d'avant porte un autre tag et soit rejeté (BOT §6.3.1). */
    b->prochain_tag = KeQueryPerformanceCounter(NULL).LowPart;
}

static VOID Pose32(UCHAR *p, ULONG v)
{
    p[0] = (UCHAR)v;
    p[1] = (UCHAR)(v >> 8);
    p[2] = (UCHAR)(v >> 16);
    p[3] = (UCHAR)(v >> 24);
}

static ULONG Lit32(const UCHAR *p)
{
    return (ULONG)p[0] | (ULONG)p[1] << 8 | (ULONG)p[2] << 16 | (ULONG)p[3] << 24;
}

NTSTATUS BotReprise(BOT *b)
{
    /* Reset Recovery, BOT §5.3.4, trois temps dans cet ordre.
     * (a) Bulk-Only Mass Storage Reset, requête de classe (BOT §3.1) :
     *     bmRequestType 0x21 (hôte vers appareil, classe, destinataire
     *     l'interface), bRequest 0xFF, wValue 0, wIndex numéro d'interface,
     *     wLength 0. L'appareil se remet prêt à recevoir un CBW.
     * (b) puis (c) : déblocage du pipe IN, puis du pipe OUT, tentés même si (a)
     *     a échoué : c'est ce qui reste pour débloquer le transport. */
    const UCHAR setup[8] = {0x21, 0xFF, 0x00, 0x00, b->interface, 0x00, 0x00, 0x00};
    ULONG n;
    NTSTATUS statut, s;

    PAGED_CODE();
    Trace(TRACE_LEVEL_WARNING, TRACE_BOT, "Reset Recovery (BOT 5.3.4)");
    statut = UsbControle(b->usb, setup, NULL, &n);
    s = UsbDebloquer(b->usb, b->entrant);
    if (NT_SUCCESS(statut))
        statut = s;
    s = UsbDebloquer(b->usb, b->sortant);
    if (NT_SUCCESS(statut))
        statut = s;
    if (!NT_SUCCESS(statut))
        Trace(TRACE_LEVEL_ERROR, TRACE_BOT, "Reset Recovery incomplete (0x%08lX)", (ULONG)statut);
    return statut;
}

/* Échec de transport : Reset Recovery, puis la commande échoue avec statut. */
static NTSTATUS Abandon(BOT *b, BOT_RESULTAT *r, NTSTATUS statut, const char *raison)
{
    Trace(TRACE_LEVEL_ERROR, TRACE_BOT, "commande abandonnee a l'etape %u : %s (0x%08lX)", r->etape, raison,
          (ULONG)statut);
    BotReprise(b);
    r->reprise = TRUE;
    r->resultat = statut;
    return statut;
}

static BOOLEAN EstStall(NTSTATUS statut, USBD_STATUS usbd)
{
    return !NT_SUCCESS(statut) && usbd == USBD_STATUS_STALL_PID;
}

NTSTATUS BotCommande(BOT *b, UCHAR lun, const UCHAR *cdb, UCHAR lg_cdb, BOOLEAN sortant, PVOID donnees, ULONG lg,
                     BOT_RESULTAT *r)
{
    ULONG tag, n;
    USBD_STATUS usbd;
    NTSTATUS statut;

    PAGED_CODE();
    RtlZeroMemory(r, sizeof *r);
    if (lg_cdb < 1 || lg_cdb > 16 || lun > 15) /* BOT §5.1 : CDB de 1 à 16 octets, LUN sur 4 bits */
        return r->resultat = STATUS_INVALID_PARAMETER;
    tag = b->prochain_tag++;

    /* 1. CBW, BOT §5.1, table 5.1, octet par octet comme src/bot.c. */
    RtlZeroMemory(b->cbw, sizeof b->cbw);
    Pose32(b->cbw + 0, SIGNATURE_CBW); /* dCBWSignature */
    Pose32(b->cbw + 4, tag);           /* dCBWTag */
    Pose32(b->cbw + 8, lg);            /* dCBWDataTransferLength : octets attendus */
    b->cbw[12] = sortant ? 0x00 : 0x80; /* bmCBWFlags : bit 7 à 1, données vers l'hôte */
    b->cbw[13] = lun;                  /* bCBWLUN (bits 3..0) */
    b->cbw[14] = lg_cdb;               /* bCBWCBLength (bits 4..0) */
    RtlCopyMemory(b->cbw + 15, cdb, lg_cdb); /* CBWCB, complété de zéros jusqu'à 16 octets */
    RtlCopyMemory(r->cbw, b->cbw, sizeof r->cbw);
    Trace(TRACE_LEVEL_INFORMATION, TRACE_BOT, "CBW tag 0x%08lX, opcode 0x%02X, %s %lu o", tag, cdb[0],
          sortant ? "sortant" : "entrant", lg);

    statut = UsbBulk(b->usb, b->sortant, b->cbw, BOT_LG_CBW, &n, &usbd);
    if (!NT_SUCCESS(statut) || n != BOT_LG_CBW)
        /* CBW refusé (STALL du pipe OUT) ou perdu : BOT §6.6.1 demande une
         * Reset Recovery avant toute nouvelle commande. */
        return Abandon(b, r, NT_SUCCESS(statut) ? STATUS_DEVICE_PROTOCOL_ERROR : statut, "envoi du CBW");
    r->etape = BOT_ETAPE_CBW;

    /* 2. Données. Un STALL ici est légal (BOT §6.7.2 en entrée : l'appareil a
     * moins à envoyer que demandé ; §6.7.3 en sortie : il refuse la suite) : on
     * débloque le pipe concerné et on passe au CSW, qui dira le statut et le
     * résidu. Tout autre échec (délai dépassé, câble) laisse le transport dans
     * un état inconnu : Reset Recovery. */
    if (lg) {
        const USB_PIPE *pipe = sortant ? b->sortant : b->entrant;
        statut = UsbBulk(b->usb, pipe, donnees, lg, &n, &usbd);
        if (!NT_SUCCESS(statut) && !(EstStall(statut, usbd) && NT_SUCCESS(UsbDebloquer(b->usb, pipe))))
            return Abandon(b, r, statut, sortant ? "envoi des donnees" : "lecture des donnees");
        r->recus = n;
    }
    r->etape = BOT_ETAPE_DONNEES;

    /* 3. CSW, BOT §5.2, table 5.2 ; sur un STALL, déblocage puis un seul nouvel
     * essai (BOT §5.3.3 et figure 2). */
    statut = UsbBulk(b->usb, b->entrant, b->csw, BOT_LG_CSW, &n, &usbd);
    if (EstStall(statut, usbd) && NT_SUCCESS(UsbDebloquer(b->usb, b->entrant)))
        statut = UsbBulk(b->usb, b->entrant, b->csw, BOT_LG_CSW, &n, &usbd);
    if (!NT_SUCCESS(statut))
        return Abandon(b, r, statut, "lecture du CSW");
    RtlCopyMemory(r->csw, b->csw, n < BOT_LG_CSW ? n : BOT_LG_CSW);
    /* Validité selon BOT §6.3.1 : 13 octets, la signature 'USBS' et le tag du
     * CBW. Un CSW invalide impose une Reset Recovery (BOT §5.3.3). */
    if (n != BOT_LG_CSW)
        return Abandon(b, r, STATUS_DEVICE_PROTOCOL_ERROR, "CSW de longueur fausse (BOT 6.3.1)");
    r->etape = BOT_ETAPE_CSW;
    if (Lit32(b->csw) != SIGNATURE_CSW || Lit32(b->csw + 4) != tag)
        return Abandon(b, r, STATUS_DEVICE_PROTOCOL_ERROR, "CSW a la signature ou au tag faux (BOT 6.3.1)");
    r->residu = Lit32(b->csw + 8); /* dCSWDataResidue */
    r->statut = b->csw[12];        /* bCSWStatus, table 5.3 */
    Trace(TRACE_LEVEL_INFORMATION, TRACE_BOT, "CSW tag 0x%08lX, statut %u, residu %lu, %lu o passes", tag, r->statut,
          r->residu, r->recus);

    /* CSW « significatif » (BOT §6.3.2) : statut 0, 1 ou 2, et un résidu qui
     * ne dépasse pas ce qu'annonçait le CBW (même choix que src/bot.c, voir le
     * « résidu collé » de docs/protocole.md §1). Statut 2 : erreur de phase,
     * l'appareil exige une Reset Recovery (BOT §5.3.4). */
    if (r->statut > 2 || r->residu > lg)
        return Abandon(b, r, STATUS_DEVICE_PROTOCOL_ERROR, "CSW non significatif (BOT 6.3.2)");
    if (r->statut == 2)
        return Abandon(b, r, STATUS_DEVICE_PROTOCOL_ERROR, "erreur de phase (BOT 5.3.4)");
    r->resultat = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}
