/*
 * usb.c : couche URB du pilote (étape 6d). Voir usb.h.
 *
 * Chemin d'un URB : notre pilote -> IRP_MJ_INTERNAL_DEVICE_CONTROL avec le code
 * IOCTL_INTERNAL_USB_SUBMIT_URB et l'adresse de l'URB dans
 * Parameters.Others.Argument1 -> PDO du concentrateur (usbhub3.sys) -> pilote
 * du contrôleur (USBXHCI, UCX) -> câble. C'est exactement ce que faisait
 * winusb.sys pour nous aux étapes 2 à 5 ; le schéma de peripherique.c (étape 2)
 * annonçait ce moment.
 *
 * Inscription auprès de la pile (USBD_CreateHandle, contrat 0x602) et URB
 * alloués par USBD_UrbAllocate : c'est la façon actuelle (doc WDK, « Allocating
 * and Building URBs », « Best Practices: Using URBs ») ; la pile y rattache son
 * propre contexte, et USBD_AssignUrbToIoStackLocation relie l'URB à l'IRP. Un
 * URB alloué à la main dans le pool, la façon d'avant Windows 8, marcherait
 * encore, mais sans ce contexte.
 *
 * Envoi par une requête KMDF que l'on prépare nous-mêmes : KMDF met le code
 * majeur et le code d'IOCTL dans l'emplacement de pile suivant de l'IRP
 * (WdfIoTargetFormatRequestForInternalIoctlOthers), on y attache l'URB
 * (USBD_AssignUrbToIoStackLocation), puis KMDF l'envoie et attend, avec un
 * délai au bout duquel il annule l'IRP (la pile abandonne alors l'URB).
 * Pourquoi pas WdfIoTargetSendInternalIoctlOthersSynchronously, plus court :
 * il ne laisse pas la main sur l'emplacement de pile avant l'envoi, donc pas
 * d'appel à USBD_AssignUrbToIoStackLocation.
 */
#include "usb.h"
#include <usbioctl.h> /* IOCTL_INTERNAL_USB_SUBMIT_URB */
#include "wpp.h"
#include "usb.tmh"

/* Délai d'un transfert de contrôle : 2 s, comme DELAI_CONTROLE_MS en espace
 * utilisateur (src/peripherique.c : la réponse la plus lente de 1b arrive en
 * 4 ms). Posé dans l'URB lui-même (champ Timeout de CONTROL_TRANSFER_EX). */
#define DELAI_CONTROLE_MS 2000

/* Délai de garde de tout envoi, côté KMDF : 5 s, comme DELAI_BULK_MS
 * (src/peripherique.c). Pour un contrôle, le délai de l'URB tombe avant. */
#define DELAI_ENVOI_MS 5000

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, UsbOuvrir)
#pragma alloc_text(PAGE, UsbFermer)
#pragma alloc_text(PAGE, UsbControle)
#pragma alloc_text(PAGE, UsbChercherInterface)
#pragma alloc_text(PAGE, UsbChoisirConfiguration)
#pragma alloc_text(PAGE, UsbAbandonner)
#pragma alloc_text(PAGE, UsbBulk)
#pragma alloc_text(PAGE, UsbDebloquer)
#endif

NTSTATUS UsbOuvrir(WDFDEVICE appareil, USB_CIBLE *u)
{
    NTSTATUS statut;

    PAGED_CODE();
    /* La cible d'E/S par défaut de KMDF : le pilote juste en dessous de nous,
     * ici le PDO créé par le concentrateur pour le scanner. */
    u->cible = WdfDeviceGetIoTarget(appareil);
    /* Inscription : notre objet de périphérique, celui d'en dessous, la
     * version du contrat (0x602 : Windows 8 et suivants), notre étiquette. */
    statut = USBD_CreateHandle(WdfDeviceWdmGetDeviceObject(appareil), WdfDeviceWdmGetAttachedDevice(appareil),
                               USBD_CLIENT_CONTRACT_VERSION_602, DS720D_ETIQUETTE, &u->usbd);
    if (!NT_SUCCESS(statut)) {
        u->usbd = NULL;
        Trace(TRACE_LEVEL_ERROR, TRACE_USB, "USBD_CreateHandle a echoue (0x%08lX)", (ULONG)statut);
        return statut;
    }
    Trace(TRACE_LEVEL_INFORMATION, TRACE_USB, "inscrit aupres de la pile USB (contrat 0x602)");
    return STATUS_SUCCESS;
}

VOID UsbFermer(USB_CIBLE *u)
{
    PAGED_CODE();
    if (u->usbd) {
        USBD_CloseHandle(u->usbd);
        u->usbd = NULL;
        Trace(TRACE_LEVEL_INFORMATION, TRACE_USB, "desinscrit de la pile USB");
    }
    u->configuration = NULL;
}

/*
 * Envoie un URB et attend sa fin. Renvoie le statut de l'IRP ; si l'IRP réussit
 * mais que l'URB porte une erreur USBD, renvoie STATUS_UNSUCCESSFUL. Le statut
 * USBD (UrbHeader.Status, usb.h : USBD_STATUS_STALL_PID, …) est tracé par
 * l'appelant, qui sait ce qu'il envoyait.
 */
static NTSTATUS Envoyer(USB_CIBLE *u, PURB urb)
{
    WDFREQUEST requete;
    WDF_REQUEST_SEND_OPTIONS options;
    NTSTATUS statut;

    statut = WdfRequestCreate(WDF_NO_OBJECT_ATTRIBUTES, u->cible, &requete);
    if (!NT_SUCCESS(statut))
        return statut;
    /* IRP_MJ_INTERNAL_DEVICE_CONTROL et IOCTL_INTERNAL_USB_SUBMIT_URB dans
     * l'emplacement de pile suivant ; aucun tampon : l'URB porte les siens. */
    statut = WdfIoTargetFormatRequestForInternalIoctlOthers(u->cible, requete, IOCTL_INTERNAL_USB_SUBMIT_URB, NULL,
                                                             NULL, NULL, NULL, NULL, NULL);
    if (NT_SUCCESS(statut)) {
        /* Parameters.Others.Argument1 = l'URB, et le lien avec le contexte que
         * la pile a rattaché à l'URB par USBD_UrbAllocate. */
        USBD_AssignUrbToIoStackLocation(u->usbd, IoGetNextIrpStackLocation(WdfRequestWdmGetIrp(requete)), urb);
        WDF_REQUEST_SEND_OPTIONS_INIT(&options, WDF_REQUEST_SEND_OPTION_SYNCHRONOUS | WDF_REQUEST_SEND_OPTION_TIMEOUT);
        WDF_REQUEST_SEND_OPTIONS_SET_TIMEOUT(&options, WDF_REL_TIMEOUT_IN_MS(DELAI_ENVOI_MS));
        /* Envoi synchrone : au retour, la requête est terminée, ou refusée
         * avant même l'envoi (WdfRequestSend rend alors FALSE) ; dans les deux
         * cas, son statut dit ce qui s'est passé. */
        (void)WdfRequestSend(requete, u->cible, &options);
        statut = WdfRequestGetStatus(requete);
    }
    WdfObjectDelete(requete);
    if (NT_SUCCESS(statut) && !USBD_SUCCESS(urb->UrbHeader.Status))
        statut = STATUS_UNSUCCESSFUL;
    return statut;
}

NTSTATUS UsbControle(USB_CIBLE *u, const UCHAR setup[8], PVOID donnees, ULONG *transferes)
{
    PURB urb;
    NTSTATUS statut;
    /* wLength, octets 6 et 7, petit-boutiste (USB 2.0 §9.3, table 9-2). */
    USHORT lg = (USHORT)(setup[6] | setup[7] << 8);
    /* Bit 7 de bmRequestType : sens de l'étape DATA (table 9-2). */
    BOOLEAN entrant = (setup[0] & 0x80) != 0;

    PAGED_CODE();
    *transferes = 0;
    statut = USBD_UrbAllocate(u->usbd, &urb);
    if (!NT_SUCCESS(statut))
        return statut;
    /* URB_FUNCTION_CONTROL_TRANSFER_EX (usb.h, struct _URB_CONTROL_TRANSFER_EX),
     * champ par champ. USBD_UrbAllocate rend un URB mis à zéro. */
    urb->UrbControlTransferEx.Hdr.Length = sizeof(struct _URB_CONTROL_TRANSFER_EX);
    urb->UrbControlTransferEx.Hdr.Function = URB_FUNCTION_CONTROL_TRANSFER_EX;
    /* Pas de poignée de pipe : USBD_DEFAULT_PIPE_TRANSFER désigne le pipe de
     * contrôle par défaut (endpoint 0). Le sens doit suivre le bit 7 de
     * bmRequestType ; en entrée, une réponse plus courte que wLength est
     * acceptée (USBD_SHORT_TRANSFER_OK), comme USB 2.0 §9.4.3 l'autorise pour
     * un descripteur. */
    urb->UrbControlTransferEx.PipeHandle = NULL;
    urb->UrbControlTransferEx.TransferFlags = USBD_DEFAULT_PIPE_TRANSFER |
        (entrant ? USBD_TRANSFER_DIRECTION_IN | USBD_SHORT_TRANSFER_OK : USBD_TRANSFER_DIRECTION_OUT);
    urb->UrbControlTransferEx.TransferBufferLength = lg;
    urb->UrbControlTransferEx.TransferBuffer = lg ? donnees : NULL;
    urb->UrbControlTransferEx.TransferBufferMDL = NULL;
    urb->UrbControlTransferEx.Timeout = DELAI_CONTROLE_MS;
    /* Les 8 octets du paquet SETUP, tels que l'appelant les a écrits : la
     * pile les recopie sur le bus sans les recomposer. */
    RtlCopyMemory(urb->UrbControlTransferEx.SetupPacket, setup, 8);

    statut = Envoyer(u, urb);
    if (NT_SUCCESS(statut))
        *transferes = urb->UrbControlTransferEx.TransferBufferLength;
    Trace(NT_SUCCESS(statut) ? TRACE_LEVEL_INFORMATION : TRACE_LEVEL_ERROR, TRACE_USB,
          "URB CONTROL_TRANSFER_EX, SETUP %02X %02X %02X %02X %02X %02X %02X %02X : statut 0x%08lX, USBD 0x%08lX, %lu o",
          setup[0], setup[1], setup[2], setup[3], setup[4], setup[5], setup[6], setup[7], (ULONG)statut,
          (ULONG)urb->UrbHeader.Status, *transferes);
    USBD_UrbFree(u->usbd, urb);
    return statut;
}

PUSB_INTERFACE_DESCRIPTOR UsbChercherInterface(PUSB_CONFIGURATION_DESCRIPTOR conf, ULONG lg, UCHAR classe,
                                               UCHAR sous_classe, UCHAR protocole)
{
    const UCHAR *d = (const UCHAR *)conf;
    PUSB_INTERFACE_DESCRIPTOR trouvee = NULL;
    BOOLEAN entrant = FALSE, sortant = FALSE;

    PAGED_CODE();
    /* Même parcours que lire_descripteurs de src/ds720d.c : chaque descripteur
     * doit tenir entier dans les lg octets avant qu'on lise ses champs, et un
     * bLength inférieur à 2 arrête tout (il ferait boucler sur place). */
    for (ULONG i = 0; i + 2 <= lg && d[i] >= 2 && i + d[i] <= lg; i += d[i]) {
        const UCHAR *p = d + i;
        if (p[1] == USB_INTERFACE_DESCRIPTOR_TYPE && p[0] >= sizeof(USB_INTERFACE_DESCRIPTOR)) {
            if (trouvee)
                break; /* interface suivante : celle qu'on a trouvée est complète */
            if (p[5] == classe && p[6] == sous_classe && p[7] == protocole)
                trouvee = (PUSB_INTERFACE_DESCRIPTOR)p;
        } else if (trouvee && p[1] == USB_ENDPOINT_DESCRIPTOR_TYPE && p[0] >= sizeof(USB_ENDPOINT_DESCRIPTOR) &&
                   (p[3] & 3) == USB_ENDPOINT_TYPE_BULK) {
            if (p[2] & 0x80)
                entrant = TRUE;
            else
                sortant = TRUE;
        }
    }
    if (!trouvee || !entrant || !sortant) {
        Trace(TRACE_LEVEL_ERROR, TRACE_USB, "pas d'interface %02X/%02X/%02X avec deux endpoints bulk", classe,
              sous_classe, protocole);
        return NULL;
    }
    return trouvee;
}

NTSTATUS UsbChoisirConfiguration(USB_CIBLE *u, PUSB_CONFIGURATION_DESCRIPTOR conf, PUSB_INTERFACE_DESCRIPTOR itf,
                                 USB_PIPE *entrant, USB_PIPE *sortant)
{
    USBD_INTERFACE_LIST_ENTRY liste[2];
    PURB urb;
    NTSTATUS statut;

    PAGED_CODE();
    /* Une seule interface, terminée par une entrée vide. */
    RtlZeroMemory(liste, sizeof liste);
    liste[0].InterfaceDescriptor = itf;
    /* URB SELECT_CONFIGURATION : sa taille dépend du nombre d'interfaces et de
     * pipes (GET_SELECT_CONFIGURATION_REQUEST_SIZE, usbdlib.h). Construit par
     * USBD_SelectConfigUrbAllocateAndBuild, l'allocateur qui va avec notre
     * inscription (USBD_UrbAllocate ne rend qu'un URB de taille fixe) : il
     * recopie numéro d'interface, réglage alternatif et nombre de pipes depuis
     * nos descripteurs. C'est nous qui avons lu les descripteurs et choisi
     * l'interface ; la réponse, champ par champ, est lue plus bas. */
    statut = USBD_SelectConfigUrbAllocateAndBuild(u->usbd, conf, liste, &urb);
    if (!NT_SUCCESS(statut)) {
        Trace(TRACE_LEVEL_ERROR, TRACE_USB, "USBD_SelectConfigUrbAllocateAndBuild a echoue (0x%08lX)", (ULONG)statut);
        return statut;
    }
    statut = Envoyer(u, urb);
    Trace(NT_SUCCESS(statut) ? TRACE_LEVEL_INFORMATION : TRACE_LEVEL_ERROR, TRACE_USB,
          "URB SELECT_CONFIGURATION, configuration %u, interface %u : statut 0x%08lX, USBD 0x%08lX",
          conf->bConfigurationValue, itf->bInterfaceNumber, (ULONG)statut, (ULONG)urb->UrbHeader.Status);
    if (NT_SUCCESS(statut)) {
        /* Réponse de la pile : la poignée de configuration, puis, pour chaque
         * endpoint de l'interface, une poignée de pipe (usb.h,
         * USBD_INTERFACE_INFORMATION et USBD_PIPE_INFORMATION). */
        PUSBD_INTERFACE_INFORMATION info = &urb->UrbSelectConfiguration.Interface;
        u->configuration = urb->UrbSelectConfiguration.ConfigurationHandle;
        RtlZeroMemory(entrant, sizeof *entrant);
        RtlZeroMemory(sortant, sizeof *sortant);
        for (ULONG i = 0; i < info->NumberOfPipes; i++) {
            PUSBD_PIPE_INFORMATION p = &info->Pipes[i];
            USB_PIPE *cible = (p->EndpointAddress & 0x80) ? entrant : sortant;
            Trace(TRACE_LEVEL_INFORMATION, TRACE_USB, "pipe %lu : endpoint 0x%02X, type %d, paquets de %u o", i,
                  p->EndpointAddress, (int)p->PipeType, p->MaximumPacketSize);
            if (p->PipeType == UsbdPipeTypeBulk && !cible->poignee) {
                cible->adresse = p->EndpointAddress;
                cible->taille_paquet = p->MaximumPacketSize;
                cible->poignee = p->PipeHandle;
            }
        }
        if (!entrant->poignee || !sortant->poignee) {
            Trace(TRACE_LEVEL_ERROR, TRACE_USB, "la configuration ne donne pas deux pipes bulk");
            statut = STATUS_DEVICE_CONFIGURATION_ERROR;
        }
    }
    USBD_UrbFree(u->usbd, urb);
    return statut;
}

NTSTATUS UsbAbandonner(USB_CIBLE *u, const USB_PIPE *pipe)
{
    PURB urb;
    NTSTATUS statut;

    PAGED_CODE();
    if (!pipe->poignee || !u->usbd)
        return STATUS_SUCCESS;
    statut = USBD_UrbAllocate(u->usbd, &urb);
    if (!NT_SUCCESS(statut))
        return statut;
    /* URB_FUNCTION_ABORT_PIPE (usb.h, struct _URB_PIPE_REQUEST) : la pile
     * termine tous les transferts en attente sur ce pipe. Vu en 5d, quand
     * USBSTOR et WinUSB lâchent le scanner. */
    urb->UrbPipeRequest.Hdr.Length = sizeof(struct _URB_PIPE_REQUEST);
    urb->UrbPipeRequest.Hdr.Function = URB_FUNCTION_ABORT_PIPE;
    urb->UrbPipeRequest.PipeHandle = pipe->poignee;
    statut = Envoyer(u, urb);
    /* Après un débranchement, l'appareil n'est plus là : l'échec est normal
     * et sans conséquence, d'où un simple avertissement. */
    Trace(NT_SUCCESS(statut) ? TRACE_LEVEL_INFORMATION : TRACE_LEVEL_WARNING, TRACE_USB,
          "URB ABORT_PIPE, endpoint 0x%02X : statut 0x%08lX, USBD 0x%08lX", pipe->adresse, (ULONG)statut,
          (ULONG)urb->UrbHeader.Status);
    USBD_UrbFree(u->usbd, urb);
    return statut;
}

NTSTATUS UsbBulk(USB_CIBLE *u, const USB_PIPE *pipe, PVOID tampon, ULONG lg, ULONG *transferes, USBD_STATUS *usbd)
{
    PURB urb;
    NTSTATUS statut;
    BOOLEAN entrant = (pipe->adresse & 0x80) != 0;

    PAGED_CODE();
    *transferes = 0;
    *usbd = USBD_STATUS_SUCCESS;
    statut = USBD_UrbAllocate(u->usbd, &urb);
    if (!NT_SUCCESS(statut))
        return statut;
    /* URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER (usb.h, struct
     * _URB_BULK_OR_INTERRUPT_TRANSFER), champ par champ. En entrée, une
     * réponse plus courte que lg est permise (USBD_SHORT_TRANSFER_OK) : en
     * Bulk-Only, l'appareil peut envoyer moins que demandé et le dire par le
     * résidu du CSW (BOT §6.7.2). La pile découpe le tampon en paquets de
     * wMaxPacketSize (512 o en haute vitesse) ; un seul URB par phase. */
    urb->UrbBulkOrInterruptTransfer.Hdr.Length = sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER);
    urb->UrbBulkOrInterruptTransfer.Hdr.Function = URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER;
    urb->UrbBulkOrInterruptTransfer.PipeHandle = pipe->poignee;
    urb->UrbBulkOrInterruptTransfer.TransferFlags =
        entrant ? USBD_TRANSFER_DIRECTION_IN | USBD_SHORT_TRANSFER_OK : USBD_TRANSFER_DIRECTION_OUT;
    urb->UrbBulkOrInterruptTransfer.TransferBufferLength = lg;
    urb->UrbBulkOrInterruptTransfer.TransferBuffer = tampon;
    urb->UrbBulkOrInterruptTransfer.TransferBufferMDL = NULL;
    urb->UrbBulkOrInterruptTransfer.UrbLink = NULL;

    statut = Envoyer(u, urb);
    *usbd = urb->UrbHeader.Status;
    /* La pile rend dans TransferBufferLength ce qui est passé, même partiel. */
    *transferes = urb->UrbBulkOrInterruptTransfer.TransferBufferLength;
    if (!NT_SUCCESS(statut))
        Trace(TRACE_LEVEL_WARNING, TRACE_USB, "URB BULK, endpoint 0x%02X, %lu o demandes : statut 0x%08lX, USBD 0x%08lX, %lu o",
              pipe->adresse, lg, (ULONG)statut, (ULONG)*usbd, *transferes);
    USBD_UrbFree(u->usbd, urb);
    return statut;
}

NTSTATUS UsbDebloquer(USB_CIBLE *u, const USB_PIPE *pipe)
{
    PURB urb;
    NTSTATUS statut;

    PAGED_CODE();
    statut = USBD_UrbAllocate(u->usbd, &urb);
    if (!NT_SUCCESS(statut))
        return statut;
    /* URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL (usb.h, struct
     * _URB_PIPE_REQUEST) : ce que fait USBSTOR pour Windows en 1b (trame
     * 19241) et WinUsb_ResetPipe pour src/peripherique.c (periph_debloquer). */
    urb->UrbPipeRequest.Hdr.Length = sizeof(struct _URB_PIPE_REQUEST);
    urb->UrbPipeRequest.Hdr.Function = URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL;
    urb->UrbPipeRequest.PipeHandle = pipe->poignee;
    statut = Envoyer(u, urb);
    Trace(NT_SUCCESS(statut) ? TRACE_LEVEL_INFORMATION : TRACE_LEVEL_ERROR, TRACE_USB,
          "URB SYNC_RESET_PIPE_AND_CLEAR_STALL, endpoint 0x%02X : statut 0x%08lX, USBD 0x%08lX", pipe->adresse,
          (ULONG)statut, (ULONG)urb->UrbHeader.Status);
    USBD_UrbFree(u->usbd, urb);
    return statut;
}
