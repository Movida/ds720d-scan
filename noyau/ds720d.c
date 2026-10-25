/*
 * ds720d.sys : pilote KMDF du scanner Brother DS-720D (étape 6, docs/pilote.md).
 *
 * Étape 6b : squelette PnP, sans aucun transfert. Le pilote se lie au scanner
 * par son INF (ds720d.inf, identifiant matériel USB\VID_04F9&PID_60E2), crée
 * son objet de périphérique et annonce chaque rappel de PnP et d'alimentation
 * dans le débogueur. Il n'envoie rien au scanner : pas même la sélection de
 * configuration, qui viendra à l'étape 6d. Sans elle, l'appareil reste dans
 * l'état « adressé » d'USB 2.0 §9.1.1 : énuméré par le concentrateur, mais
 * aucun endpoint bulk n'est actif. On ne risque donc rien côté scanner.
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
 * Messages par DbgPrintEx au niveau DPFLTR_ERROR_LEVEL, en ASCII, comme dans
 * bonjour.c ; les traces WPP les remplaceront à l'étape 6c.
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

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD Ds720dAjoutAppareil;
EVT_WDF_DRIVER_UNLOAD Ds720dDecharge;
EVT_WDF_DEVICE_PREPARE_HARDWARE Ds720dPreparerMateriel;
EVT_WDF_DEVICE_RELEASE_HARDWARE Ds720dLibererMateriel;
EVT_WDF_DEVICE_D0_ENTRY Ds720dEntreeD0;
EVT_WDF_DEVICE_D0_EXIT Ds720dSortieD0;
EVT_WDF_DEVICE_SURPRISE_REMOVAL Ds720dRetraitInopine;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, Ds720dAjoutAppareil)
#pragma alloc_text(PAGE, Ds720dPreparerMateriel)
#pragma alloc_text(PAGE, Ds720dLibererMateriel)
#pragma alloc_text(PAGE, Ds720dDecharge)
#endif

#define MSG(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ds720d : " __VA_ARGS__)

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
    WDF_DRIVER_CONFIG config;
    NTSTATUS statut;

    MSG("DriverEntry, KMDF demande %u.%u, service %wZ\n", KMDF_VERSION_MAJOR, KMDF_VERSION_MINOR,
        RegistryPath);

    /* Pilote PnP : KMDF appellera Ds720dAjoutAppareil pour chaque scanner que
     * le gestionnaire PnP nous confie (un seul en pratique). */
    WDF_DRIVER_CONFIG_INIT(&config, Ds720dAjoutAppareil);
    config.EvtDriverUnload = Ds720dDecharge;

    statut = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(statut))
        MSG("WdfDriverCreate a echoue (0x%08lX)\n", (ULONG)statut);
    return statut;
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
    WDFDEVICE appareil;
    NTSTATUS statut;

    UNREFERENCED_PARAMETER(Driver);
    PAGED_CODE();
    MSG("EvtDriverDeviceAdd\n");

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp);
    pnp.EvtDevicePrepareHardware = Ds720dPreparerMateriel;
    pnp.EvtDeviceReleaseHardware = Ds720dLibererMateriel;
    pnp.EvtDeviceD0Entry = Ds720dEntreeD0;
    pnp.EvtDeviceD0Exit = Ds720dSortieD0;
    pnp.EvtDeviceSurpriseRemoval = Ds720dRetraitInopine;
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnp);

    /* Pas de nom d'objet ni d'interface de périphérique à cette étape : rien
     * ne doit encore pouvoir nous ouvrir depuis l'espace utilisateur (6e). */
    statut = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &appareil);
    if (!NT_SUCCESS(statut)) {
        MSG("WdfDeviceCreate a echoue (0x%08lX)\n", (ULONG)statut);
        return statut;
    }
    MSG("objet de peripherique cree, attache au-dessus du PDO du concentrateur\n");
    return STATUS_SUCCESS;
}

/*
 * Le matériel nous est confié. Pour une carte PCI, on y recevrait ses
 * ressources (plages d'E/S, interruption) ; un appareil USB n'en a aucune :
 * tout passe par la pile USB, en URB. La liste doit donc être vide. C'est ici
 * que l'étape 6d lira les descripteurs et choisira la configuration.
 */
NTSTATUS Ds720dPreparerMateriel(WDFDEVICE Device, WDFCMRESLIST ResourcesRaw, WDFCMRESLIST ResourcesTranslated)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(ResourcesRaw);
    PAGED_CODE();
    MSG("EvtDevicePrepareHardware : %lu ressource(s) materielle(s)\n", WdfCmResourceListGetCount(ResourcesTranslated));
    return STATUS_SUCCESS;
}

/* Le matériel nous est repris (désactivation, retrait, arrêt). Rien à rendre
 * à cette étape. */
NTSTATUS Ds720dLibererMateriel(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(ResourcesTranslated);
    PAGED_CODE();
    MSG("EvtDeviceReleaseHardware\n");
    return STATUS_SUCCESS;
}

/* L'appareil entre en D0, l'état de pleine marche. */
NTSTATUS Ds720dEntreeD0(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState)
{
    UNREFERENCED_PARAMETER(Device);
    MSG("EvtDeviceD0Entry, depuis %s\n", NomEtatD(PreviousState));
    return STATUS_SUCCESS;
}

/* L'appareil quitte D0 (mise en veille, désactivation, retrait). */
NTSTATUS Ds720dSortieD0(WDFDEVICE Device, WDF_POWER_DEVICE_STATE TargetState)
{
    UNREFERENCED_PARAMETER(Device);
    MSG("EvtDeviceD0Exit, vers %s\n", NomEtatD(TargetState));
    return STATUS_SUCCESS;
}

/* Débranchement sans préavis : le cas du faux contact du câble (étape 6h).
 * KMDF appellera ensuite D0Exit et ReleaseHardware ; à partir d'ici, tout
 * envoi vers le scanner échouerait. */
VOID Ds720dRetraitInopine(WDFDEVICE Device)
{
    UNREFERENCED_PARAMETER(Device);
    MSG("EvtDeviceSurpriseRemoval : scanner debranche\n");
}

/* Plus aucun scanner n'utilise le pilote : l'image va quitter la mémoire. */
VOID Ds720dDecharge(WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);
    PAGED_CODE();
    MSG("dechargement\n");
}
