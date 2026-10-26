/*
 * ds720d.sys : pilote KMDF du scanner Brother DS-720D (étape 6, docs/pilote.md).
 *
 * Étape 6b : squelette PnP. Le pilote se lie au scanner par son INF
 * (ds720d.inf, identifiant matériel USB\VID_04F9&PID_60E2), crée son objet de
 * périphérique et annonce chaque rappel de PnP et d'alimentation.
 *
 * Étape 6d : premiers URB, au démarrage (EvtDevicePrepareHardware), dans
 * l'ordre où Windows les envoie pour USBSTOR en 1b (trames 19191 à 19224) :
 * descripteurs DEVICE et CONFIGURATION, sélection de la configuration (la pile
 * envoie SET_CONFIGURATION, qui fait passer l'appareil de l'état « adressé » à
 * l'état « configuré » d'USB 2.0 §9.1.1 et active ses endpoints bulk), puis
 * GET_MAX_LUN. Rien d'autre : pas encore de commande SCSI (6e). Ni les
 * descripteurs STRING de 1b (inutiles au pilote ; l'outil les lira en 6e), ni
 * le numéro de série, qui ne doit pas finir dans une trace (CLAUDE.md).
 * Au retrait, abandon des pipes, sans déconfiguration (docs/pilote.md, § 2).
 *
 * Étape 6e : interface de périphérique et requêtes de l'outil ds720dk.exe
 * (ioctl.c), qui passent par la barrière des commandes observées
 * (src/permis.c), puis par le transport Bulk-Only du pilote (bot.c).
 *
 * Étape 6i (relecture de fond) : un seul client à la fois, compté par le
 * pilote (Ds720dOuverture, Ds720dFermeture) ; second descripteur
 * CONFIGURATION revérifié.
 *
 * Pourquoi un pilote PnP, alors que bonjour.sys (5f) était non-PnP : c'est le
 * gestionnaire PnP qui charge le pilote quand le scanner apparaît, appelle
 * EvtDriverDeviceAdd pour qu'on s'attache au-dessus de l'objet physique créé
 * par le concentrateur USB (le PDO), et nous prévient du retrait. KMDF tient
 * la machine d'états PnP et alimentation (doc WDK, « PnP and Power Management
 * in KMDF Drivers ») : nos rappels n'y sont que des points d'entrée.
 *
 * Ordre attendu au branchement (doc WDK, « A User Plugs in a Device ») :
 * EvtDriverDeviceAdd, EvtDevicePrepareHardware, EvtDeviceD0Entry. Au retrait
 * ordonné (désactivation) : EvtDeviceD0Exit, EvtDeviceReleaseHardware. Au
 * débranchement : EvtDeviceSurpriseRemoval s'intercale (« A User Unplugs a
 * Device »). EvtDriverUnload enfin, quand plus aucun appareil n'utilise le pilote.
 *
 * Messages par traces WPP depuis l'étape 6c (noyau/wpp.h) : gardés dans
 * l'enregistreur en mémoire du pilote (IFR), recopiés vers le débogueur sur
 * demande seulement depuis 6d (valeur EchoDebogueur, voir DriverEntry).
 * Textes en ASCII : le débogueur n'interprète pas l'UTF-8 des chaînes ANSI.
 *
 * Code paginable : DriverEntry ne sert qu'au chargement (section INIT, rendue
 * au système ensuite) ; EvtDriverDeviceAdd, EvtDevicePrepareHardware et
 * EvtDeviceReleaseHardware sont appelés à PASSIVE_LEVEL (doc de chacun), donc
 * placés en section PAGE. Les rappels d'alimentation D0Entry et D0Exit restent
 * en mémoire non paginée : ils tournent pendant les changements d'état
 * d'alimentation, où le disque qui porte le fichier d'échange peut ne pas être
 * prêt (doc WDK, « Making PnP and Power Management Callback Functions
 * Pageable » : à ne rendre paginables qu'avec précaution). EvtDeviceSurpriseRemoval
 * aussi, par prudence : il n'a que deux lignes. PAGED_CODE() n'agit que dans
 * une construction DBG (notre Makefile n'en fait pas), mais documente l'IRQL.
 */
#include <ntddk.h>
/* C4324 levé par wdfrequest.h de KMDF 1.15 (structure remplie à cause d'un
 * alignement qu'il demande lui-même) : coupé pour ce seul en-tête, comme dans
 * bonjour.c. */
#pragma warning(push)
#pragma warning(disable: 4324)
#include <wdf.h>
#pragma warning(pop)

#include "ds720d.h"

/* Traces WPP : la configuration, puis l'en-tête que tracewpp génère pour ce
 * source (out\noyau\ds720d.tmh, Makefile). Il doit venir après tout ce qu'il
 * utilise et avant le premier appel de Trace. */
#include "wpp.h"
#include "ds720d.tmh"

/* Copie des traces vers le débogueur (noyau/wpp.h) : 0 par défaut, 1 si la
 * valeur EchoDebogueur du registre du service le demande (lue par
 * DriverEntry). Écrite une seule fois, avant tout appareil ; lue ensuite par
 * chaque Trace. */
ULONG Ds720dEchoDebogueur;

/* Identifiants du scanner (descripteur DEVICE, 1b trame 19194). */
#define DS720D_VID 0x04F9
#define DS720D_PID 0x60E2

/* Le contexte de l'objet de périphérique (DS720D_APPAREIL) est dans ds720d.h,
 * partagé avec ioctl.c depuis 6e. */

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD Ds720dAjoutAppareil;
EVT_WDF_DRIVER_UNLOAD Ds720dDecharge;
EVT_WDF_DEVICE_PREPARE_HARDWARE Ds720dPreparerMateriel;
EVT_WDF_DEVICE_RELEASE_HARDWARE Ds720dLibererMateriel;
EVT_WDF_DEVICE_D0_ENTRY Ds720dEntreeD0;
EVT_WDF_DEVICE_D0_EXIT Ds720dSortieD0;
EVT_WDF_DEVICE_SURPRISE_REMOVAL Ds720dRetraitInopine;
EVT_WDF_DEVICE_FILE_CREATE Ds720dOuverture;
EVT_WDF_FILE_CLOSE Ds720dFermeture;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, Ds720dAjoutAppareil)
#pragma alloc_text(PAGE, Ds720dPreparerMateriel)
#pragma alloc_text(PAGE, Ds720dLibererMateriel)
#pragma alloc_text(PAGE, Ds720dDecharge)
/* Ouverture et fermeture : PASSIVE_LEVEL (wdfdevice.h, _IRQL_requires_max_). */
#pragma alloc_text(PAGE, Ds720dOuverture)
#pragma alloc_text(PAGE, Ds720dFermeture)
#endif

/* Nom lisible d'un état d'alimentation de KMDF (WDF_POWER_DEVICE_STATE,
 * wdfdevice.h) pour les messages de D0Entry et D0Exit. */
static const char *NomEtatD(WDF_POWER_DEVICE_STATE e)
{
    switch (e) {
    case WdfPowerDeviceD0: return "D0";
    case WdfPowerDeviceD1: return "D1";
    case WdfPowerDeviceD2: return "D2";
    case WdfPowerDeviceD3: return "D3";
    case WdfPowerDeviceD3Final: return "D3Final (premier demarrage ou arret)";
    case WdfPowerDevicePrepareForHibernation: return "preparation a l'hibernation";
    default: return "inconnu";
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    DECLARE_CONST_UNICODE_STRING(nom_echo, L"EchoDebogueur");
    WDF_DRIVER_CONFIG config;
    WDFDRIVER pilote;
    WDFKEY cle;
    ULONG echo = 0;
    NTSTATUS statut;

    /* Les traces d'abord, pour que tout ce qui suit soit enregistré. L'IFR a
     * besoin de l'objet pilote et du chemin du service (km-init.tpl). Le
     * chemin du service n'est plus affiché comme en 6b (%wZ) : WPP l'écrirait
     * %!USTR!, que DbgPrint ne comprend pas (noyau/wpp.h). */
    WPP_INIT_TRACING(DriverObject, RegistryPath);
    Trace(TRACE_LEVEL_INFORMATION, TRACE_PILOTE, "DriverEntry, KMDF demande %u.%u", KMDF_VERSION_MAJOR,
          KMDF_VERSION_MINOR);

    /* Pilote PnP : KMDF appellera Ds720dAjoutAppareil pour chaque scanner que
     * le gestionnaire PnP nous confie (un seul en pratique). */
    WDF_DRIVER_CONFIG_INIT(&config, Ds720dAjoutAppareil);
    config.EvtDriverUnload = Ds720dDecharge;

    statut = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &pilote);
    if (!NT_SUCCESS(statut)) {
        /* Pas d'objet pilote KMDF, donc pas d'EvtDriverUnload : on arrête
         * les traces ici, avant que l'image ne quitte la mémoire. */
        Trace(TRACE_LEVEL_ERROR, TRACE_PILOTE, "WdfDriverCreate a echoue (0x%08lX)", (ULONG)statut);
        WPP_CLEANUP(DriverObject);
        return statut;
    }

    /* Réglage facultatif, sous la clé Parameters du service (celle que l'INF
     * crée déjà pour le vérificateur KMDF) : EchoDebogueur, REG_DWORD. Absent
     * ou illisible, il vaut 0, la copie reste coupée. */
    if (NT_SUCCESS(WdfDriverOpenParametersRegistryKey(pilote, KEY_READ, WDF_NO_OBJECT_ATTRIBUTES, &cle))) {
        if (NT_SUCCESS(WdfRegistryQueryULong(cle, &nom_echo, &echo)))
            Ds720dEchoDebogueur = echo != 0;
        WdfRegistryClose(cle);
    }
    Trace(TRACE_LEVEL_INFORMATION, TRACE_PILOTE, "copie des traces vers le debogueur : %s",
          Ds720dEchoDebogueur ? "oui" : "non");
    return STATUS_SUCCESS;
}

/*
 * Un scanner est apparu : on crée notre objet de périphérique fonctionnel
 * (FDO), que KMDF attache au sommet de la pile, au-dessus du PDO du
 * concentrateur USB. Toute requête vers le scanner passera par nous ; les
 * nôtres descendront vers la pile USB (étape 6d).
 */
NTSTATUS Ds720dAjoutAppareil(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit)
{
    WDF_PNPPOWER_EVENT_CALLBACKS pnp;
    WDF_FILEOBJECT_CONFIG fichiers;
    WDF_OBJECT_ATTRIBUTES attributs;
    WDFDEVICE appareil;
    NTSTATUS statut;

    UNREFERENCED_PARAMETER(Driver);
    PAGED_CODE();
    Trace(TRACE_LEVEL_INFORMATION, TRACE_PNP, "EvtDriverDeviceAdd");

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp);
    pnp.EvtDevicePrepareHardware = Ds720dPreparerMateriel;
    pnp.EvtDeviceReleaseHardware = Ds720dLibererMateriel;
    pnp.EvtDeviceD0Entry = Ds720dEntreeD0;
    pnp.EvtDeviceD0Exit = Ds720dSortieD0;
    pnp.EvtDeviceSurpriseRemoval = Ds720dRetraitInopine;
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnp);

    /* Accès depuis l'espace utilisateur (6e, docs/pilote.md § 2) :
     *   - un seul client à la fois : deux outils entrelaceraient leurs
     *     commandes dans le tunnel 0xC5. Le pilote compte lui-même les
     *     ouvertures (Ds720dOuverture, Ds720dFermeture, plus bas) ;
     *   - FILE_DEVICE_SECURE_OPEN : la sécurité de l'appareil (posée par
     *     l'INF) vaut aussi pour tout nom ouvert « sous » lui, du genre
     *     \Device\…\quelquechose, que le gestionnaire d'E/S nous passerait
     *     sinon sans contrôle.
     * Jusqu'en 6h, l'exclusivité était demandée par WdfDeviceInitSetExclusive.
     * La doc WDK la dit sans effet pour un pilote de fonction : le
     * gestionnaire d'E/S ne la vérifie que sur l'objet nommé de la pile, le
     * PDO créé par le concentrateur, et « setting the exclusive flag for the
     * FDO has no effect » (« Specifying Exclusive Access to Device Objects »).
     * D'où la relecture de 6i. Or l'essai de 6i sur la version 6.5 montre une
     * seconde ouverture refusée (ERROR_ACCESS_DENIED) par ce Windows (build
     * 26300) : un comportement que la doc dément, sur lequel on ne s'appuie
     * donc pas. Le comptage par le pilote, lui, est documenté
     * (EvtDeviceFileCreate), tracé dans l'IFR, vérifié par essai_refus.c, et
     * couvre les ouvertures relatives à un descripteur déjà ouvert, que le
     * gestionnaire d'E/S laisse passer même pour un appareil exclusif (même
     * page). Pas non plus la valeur Exclusive de l'INF, l'autre voie de cette
     * page : elle refuserait avant notre code, sans trace, et notre comptage
     * ne serait jamais exercé. Un seul mécanisme, donc. */
    WDF_FILEOBJECT_CONFIG_INIT(&fichiers, Ds720dOuverture, Ds720dFermeture, WDF_NO_EVENT_CALLBACK);
    WdfDeviceInitSetFileObjectConfig(DeviceInit, &fichiers, WDF_NO_OBJECT_ATTRIBUTES);
    WdfDeviceInitSetCharacteristics(DeviceInit, FILE_DEVICE_SECURE_OPEN, TRUE);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributs, DS720D_APPAREIL);
    statut = WdfDeviceCreate(&DeviceInit, &attributs, &appareil);
    if (!NT_SUCCESS(statut)) {
        Trace(TRACE_LEVEL_ERROR, TRACE_PNP, "WdfDeviceCreate a echoue (0x%08lX)", (ULONG)statut);
        return statut;
    }
    Trace(TRACE_LEVEL_INFORMATION, TRACE_PNP, "objet de peripherique cree, attache au-dessus du PDO du concentrateur");
    /* Interface de périphérique et file des requêtes de l'outil (ioctl.c). Un
     * échec ici fait échouer l'ajout : KMDF supprime alors l'objet créé. */
    return Ds720dCreerInterface(appareil);
}

/* Taille du tampon des descripteurs, comme d[256] dans src/ds720d.c : la
 * configuration du DS-720D fait 32 octets (1b trame 19199). */
#define TAILLE_DESCRIPTEURS 256

/* Paquets SETUP des deux premières lectures de descripteurs, ceux de Windows
 * en 1b, à l'octet près (USB 2.0 §9.4.3, GET_DESCRIPTOR : bmRequestType 0x80,
 * bRequest 0x06, wValue type et index, wIndex 0, wLength). */
static const UCHAR SETUP_DEVICE[8] = {0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00};     /* trame 19191 */
static const UCHAR SETUP_CONFIGURATION[8] = {0x80, 0x06, 0x00, 0x02, 0x00, 0x00, 0x09, 0x00}; /* trame 19195 */

static USHORT Le16(const UCHAR *p) { return (USHORT)(p[0] | p[1] << 8); }

/* Rend ce que Demarrer a pris ; sans effet sur ce qui n'a pas été pris, d'où
 * son appel aussi bien après un démarrage manqué qu'au retrait. */
static VOID Liberer(DS720D_APPAREIL *a)
{
    UsbAbandonner(&a->usb, &a->entrant);
    UsbAbandonner(&a->usb, &a->sortant);
    RtlZeroMemory(&a->entrant, sizeof a->entrant);
    RtlZeroMemory(&a->sortant, sizeof a->sortant);
    UsbFermer(&a->usb);
}

/*
 * Démarrage du scanner, dans l'ordre de 1b (trames 19191 à 19224) ; d est un
 * tampon non paginé de TAILLE_DESCRIPTEURS octets. Les contrôles des réponses
 * sont ceux de lire_descripteurs et lire_max_lun dans src/ds720d.c.
 */
static NTSTATUS Demarrer(WDFDEVICE appareil, DS720D_APPAREIL *a, UCHAR *d)
{
    UCHAR setup[8];
    ULONG n;
    USHORT total;
    PUSB_INTERFACE_DESCRIPTOR itf;
    NTSTATUS statut;

    statut = UsbOuvrir(appareil, &a->usb);
    if (!NT_SUCCESS(statut))
        return statut;

    /* 1. DEVICE, 18 octets (USB 2.0 table 9-8) ; réponse trame 19194. On ne
     *    va pas plus loin si ce n'est pas un DS-720D : l'INF ne nous lie qu'à
     *    lui, mais le pilote ne parle qu'à ce qu'il a vérifié. */
    statut = UsbControle(&a->usb, SETUP_DEVICE, d, &n);
    if (!NT_SUCCESS(statut))
        return statut;
    if (n != 18 || d[0] != 18 || d[1] != USB_DEVICE_DESCRIPTOR_TYPE || Le16(d + 8) != DS720D_VID ||
        Le16(d + 10) != DS720D_PID) {
        Trace(TRACE_LEVEL_ERROR, TRACE_PNP, "descripteur DEVICE inattendu (%lu octets), arret", n);
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    /* 2. CONFIGURATION : les 9 octets de l'en-tête pour connaître wTotalLength
     *    (table 9-10), puis le tout (USB 2.0 §9.4.3) ; trames 19195 et 19197.
     *    Le second paquet ne diffère du premier que par wLength : 0x20 en 1b. */
    statut = UsbControle(&a->usb, SETUP_CONFIGURATION, d, &n);
    if (!NT_SUCCESS(statut))
        return statut;
    total = Le16(d + 2);
    if (n != 9 || d[1] != USB_CONFIGURATION_DESCRIPTOR_TYPE || total < 9 || total > TAILLE_DESCRIPTEURS) {
        Trace(TRACE_LEVEL_ERROR, TRACE_PNP, "en-tete CONFIGURATION inattendu (%lu octets, total %u), arret", n,
              total);
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }
    RtlCopyMemory(setup, SETUP_CONFIGURATION, 8);
    setup[6] = (UCHAR)total;
    setup[7] = (UCHAR)(total >> 8);
    statut = UsbControle(&a->usb, setup, d, &n);
    if (!NT_SUCCESS(statut))
        return statut;
    /* Revérifié (relecture 6i) : le parcours qui suit et la pile USB lisent la
     * configuration d'après son en-tête ; il doit être celui qu'on a lu
     * d'abord, pas un autre que l'appareil rendrait cette fois. */
    if (n != total || d[1] != USB_CONFIGURATION_DESCRIPTOR_TYPE || Le16(d + 2) != total) {
        Trace(TRACE_LEVEL_ERROR, TRACE_PNP, "CONFIGURATION complet : %lu octets, total %u attendu, arret", n, total);
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    /* 3. L'interface Mass Storage, SCSI transparent, Bulk-Only (classe 08,
     *    sous-classe 06, protocole 50 : BOT §4.3), lue et non supposée. */
    itf = UsbChercherInterface((PUSB_CONFIGURATION_DESCRIPTOR)d, total, 0x08, 0x06, 0x50);
    if (!itf)
        return STATUS_DEVICE_CONFIGURATION_ERROR;

    /* 4. Sélection de la configuration : la pile envoie SET_CONFIGURATION
     *    (trame 19214 en 1b ; USB 2.0 §9.4.7) et rend les pipes bulk. */
    statut = UsbChoisirConfiguration(&a->usb, (PUSB_CONFIGURATION_DESCRIPTOR)d, itf, &a->entrant, &a->sortant);
    if (!NT_SUCCESS(statut))
        return statut;
    a->interface = itf->bInterfaceNumber;

    /* 5. GET_MAX_LUN (BOT §3.2, trame 19223). */
    statut = BotLireMaxLun(&a->usb, a->interface, &a->max_lun);
    if (!NT_SUCCESS(statut))
        return statut;

    /* 6. Le transport Bulk-Only est prêt à porter les commandes de l'outil (6e). */
    BotInitialiser(&a->bot, &a->usb, a->interface, &a->entrant, &a->sortant);

    Trace(TRACE_LEVEL_INFORMATION, TRACE_PNP,
          "scanner pret : interface %u, Bulk-Only IN 0x%02X (%u o), OUT 0x%02X (%u o), plus haut LUN %u",
          a->interface, a->entrant.adresse, a->entrant.taille_paquet, a->sortant.adresse, a->sortant.taille_paquet,
          a->max_lun);
    return STATUS_SUCCESS;
}

/*
 * Le matériel nous est confié. Pour une carte PCI, on y recevrait ses
 * ressources (plages d'E/S, interruption) ; un appareil USB n'en a aucune :
 * tout passe par la pile USB, en URB. La liste doit donc être vide. C'est ici
 * que le pilote lit les descripteurs et choisit la configuration (6d).
 */
NTSTATUS Ds720dPreparerMateriel(WDFDEVICE Device, WDFCMRESLIST ResourcesRaw, WDFCMRESLIST ResourcesTranslated)
{
    DS720D_APPAREIL *a = Ds720dAppareil(Device);
    UCHAR *d;
    NTSTATUS statut;

    UNREFERENCED_PARAMETER(ResourcesRaw);
    PAGED_CODE();
    Trace(TRACE_LEVEL_INFORMATION, TRACE_PNP, "EvtDevicePrepareHardware : %lu ressource(s) materielle(s)",
          WdfCmResourceListGetCount(ResourcesTranslated));

    /* Tampon des descripteurs en mémoire non paginée : la pile USB y écrit
     * les réponses, éventuellement par DMA. Rendu dès la fin du démarrage :
     * la pile a recopié ce qu'il lui fallait de la configuration. */
    d = ExAllocatePool2(POOL_FLAG_NON_PAGED, TAILLE_DESCRIPTEURS, DS720D_ETIQUETTE);
    if (!d)
        return STATUS_INSUFFICIENT_RESOURCES;
    statut = Demarrer(Device, a, d);
    ExFreePoolWithTag(d, DS720D_ETIQUETTE);
    if (!NT_SUCCESS(statut)) {
        /* L'appareil ne démarre pas (code 10 dans le Gestionnaire de
         * périphériques) : on rend tout de suite ce qui a été pris. */
        Trace(TRACE_LEVEL_ERROR, TRACE_PNP, "demarrage manque (0x%08lX)", (ULONG)statut);
        Liberer(a);
    }
    return statut;
}

/* Le matériel nous est repris (désactivation, retrait, arrêt) : abandon des
 * pipes, puis désinscription de la pile USB. */
NTSTATUS Ds720dLibererMateriel(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated)
{
    UNREFERENCED_PARAMETER(ResourcesTranslated);
    PAGED_CODE();
    Trace(TRACE_LEVEL_INFORMATION, TRACE_PNP, "EvtDeviceReleaseHardware");
    Liberer(Ds720dAppareil(Device));
    return STATUS_SUCCESS;
}

/* L'appareil entre en D0, l'état de pleine marche. */
NTSTATUS Ds720dEntreeD0(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState)
{
    UNREFERENCED_PARAMETER(Device);
    Trace(TRACE_LEVEL_INFORMATION, TRACE_PNP, "EvtDeviceD0Entry, depuis %s", NomEtatD(PreviousState));
    return STATUS_SUCCESS;
}

/* L'appareil quitte D0 (mise en veille, désactivation, retrait). */
NTSTATUS Ds720dSortieD0(WDFDEVICE Device, WDF_POWER_DEVICE_STATE TargetState)
{
    UNREFERENCED_PARAMETER(Device);
    Trace(TRACE_LEVEL_INFORMATION, TRACE_PNP, "EvtDeviceD0Exit, vers %s", NomEtatD(TargetState));
    return STATUS_SUCCESS;
}

/* Débranchement sans préavis : le cas du faux contact du câble (étape 6h).
 * KMDF appellera ensuite D0Exit et ReleaseHardware ; à partir d'ici, tout
 * envoi vers le scanner échouerait. */
VOID Ds720dRetraitInopine(WDFDEVICE Device)
{
    UNREFERENCED_PARAMETER(Device);
    Trace(TRACE_LEVEL_WARNING, TRACE_PNP, "EvtDeviceSurpriseRemoval : scanner debranche");
}

/*
 * Un programme ouvre le scanner (CreateFile sur notre interface). Un seul à la
 * fois (6i) : le premier devient titulaire, les suivants sont refusés jusqu'à
 * ce qu'il ferme. Le refus est STATUS_SHARING_VIOLATION, que l'outil reçoit en
 * ERROR_SHARING_VIOLATION (« utilisé par un autre processus ») : distinct de
 * l'ERROR_ACCESS_DENIED de la barrière (ioctl.c) et des droits de l'INF.
 * KMDF peut appeler ce rappel pour deux ouvertures en même temps : il ne
 * passe par aucune file. D'où un compare-et-échange atomique : deux
 * programmes ne peuvent pas devenir titulaires ensemble.
 */
VOID Ds720dOuverture(WDFDEVICE Device, WDFREQUEST Request, WDFFILEOBJECT FileObject)
{
    DS720D_APPAREIL *a = Ds720dAppareil(Device);
    PUNICODE_STRING nom = WdfFileObjectGetFileName(FileObject);
    NTSTATUS statut = STATUS_SUCCESS;

    PAGED_CODE();
    if (nom && nom->Length) {
        /* Un nom « sous » l'appareil (\Device\…\x) : le pilote n'a pas
         * d'espace de noms, rien à ouvrir là. */
        Trace(TRACE_LEVEL_WARNING, TRACE_IOCTL, "ouverture d'un nom sous l'appareil refusee");
        statut = STATUS_OBJECT_NAME_NOT_FOUND;
    } else if (InterlockedCompareExchangePointer(&a->titulaire, FileObject, NULL) != NULL) {
        Trace(TRACE_LEVEL_WARNING, TRACE_IOCTL, "seconde ouverture refusee : le scanner est deja tenu par un client");
        statut = STATUS_SHARING_VIOLATION;
    } else {
        Trace(TRACE_LEVEL_INFORMATION, TRACE_IOCTL, "scanner ouvert par un client");
    }
    WdfRequestComplete(Request, statut);
}

/*
 * Le titulaire a fermé. KMDF n'appelle ce rappel qu'une fois le dernier
 * descripteur fermé et toutes ses requêtes terminées (doc WDK, EvtFileClose) :
 * le suivant ne peut donc pas glisser une commande pendant la dernière du
 * précédent. D'où ce rappel plutôt qu'EvtFileCleanup, appelé dès la fermeture
 * du descripteur, même avec des requêtes encore en cours. La place n'est
 * rendue que par son titulaire : une ouverture refusée ne la libère pas.
 */
VOID Ds720dFermeture(WDFFILEOBJECT FileObject)
{
    DS720D_APPAREIL *a = Ds720dAppareil(WdfFileObjectGetDevice(FileObject));

    PAGED_CODE();
    if (InterlockedCompareExchangePointer(&a->titulaire, NULL, FileObject) == FileObject)
        Trace(TRACE_LEVEL_INFORMATION, TRACE_IOCTL, "scanner rendu par son client");
}

/* Plus aucun scanner n'utilise le pilote : l'image va quitter la mémoire. On
 * arrête les traces en dernier : l'IFR et son tampon disparaissent avec elles. */
VOID Ds720dDecharge(WDFDRIVER Driver)
{
    PAGED_CODE();
    Trace(TRACE_LEVEL_INFORMATION, TRACE_PILOTE, "dechargement");
    WPP_CLEANUP(WdfDriverWdmGetDriverObject(Driver));
}
