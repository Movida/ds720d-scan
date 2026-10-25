/*
 * bonjour.sys : premier pilote noyau du projet (étape 5f), sans matériel.
 *
 * But : éprouver toute la chaîne de l'étape 6 avant de toucher au scanner :
 * construction par notre Makefile (cl /kernel, link /DRIVER), liaison à la
 * bibliothèque KMDF (WdfLdr), signature de test, chargement dans la VM,
 * message lu dans WinDbg par KDNET, puis déchargement propre.
 *
 * Pourquoi KMDF et pas un pilote WDM nu, plus court : le pilote du scanner
 * sera KMDF (CLAUDE.md) ; un essai WDM ne prouverait rien sur la liaison à
 * WdfLdr ni sur FxDriverEntry, qui sont justement ce qui peut casser.
 *
 * Pourquoi « non-PnP » (WdfDriverInitNonPnpDriver) : sans matériel, il n'y a
 * pas d'appareil à attacher, donc pas d'EvtDriverDeviceAdd ni d'INF. Le pilote
 * se charge comme un service (sc create / sc start) et se décharge par
 * sc stop ; KMDF exige alors un EvtDriverUnload (doc WDK, « Creating a
 * Framework Driver Object », drivers non-PnP). Le PnP, l'INF et les pipes
 * USB viennent à l'étape 6.
 *
 * Messages par DbgPrintEx au niveau DPFLTR_ERROR_LEVEL : c'est le seul niveau
 * affiché par défaut dans le débogueur, sans régler Kd_IHVDRIVER_Mask (doc
 * WDK, « Reading and Filtering Debugging Messages »). Les traces WPP prévues
 * pour l'étape 6 remplaceront ce DbgPrint. Textes en ASCII : le débogueur
 * n'interprète pas l'UTF-8 des chaînes ANSI.
 */
#include <ntddk.h>
#include <wdf.h>

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD BonjourDecharge;

/*
 * Point d'entrée vu par KMDF. Le vrai point d'entrée de l'image est
 * FxDriverEntry (WdfDriverEntry.lib, /ENTRY du Makefile) : il lie le pilote
 * à la version de KMDF demandée à la compilation, puis appelle DriverEntry.
 */
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS statut;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "ds720d bonjour : DriverEntry, KMDF %u.%u, service %wZ\n",
               KMDF_VERSION_MAJOR, KMDF_VERSION_MINOR, RegistryPath);

    /* Aucun rappel EvtDriverDeviceAdd : pilote non-PnP. */
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = BonjourDecharge;

    statut = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES,
                             &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(statut)) {
        /* Rien n'a été alloué : il suffit de rendre l'erreur au gestionnaire
         * d'E/S, qui décharge l'image. */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "ds720d bonjour : WdfDriverCreate a echoue (0x%08X)\n", statut);
        return statut;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "ds720d bonjour : objet pilote KMDF cree, en attente de sc stop\n");
    return STATUS_SUCCESS;
}

/* Appelé par KMDF au sc stop, avant que l'image ne quitte la mémoire. */
VOID BonjourDecharge(WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ds720d bonjour : dechargement\n");
}
