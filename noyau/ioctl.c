/*
 * ioctl.c : l'interface du pilote vers l'outil ds720dk.exe (étape 6e,
 * docs/pilote.md § 2 ; codes et structures dans ds720d_ioctl.h).
 *
 * Une interface de périphérique, pour que l'outil trouve le scanner sans
 * connaître le nom interne de l'objet ; une file d'attente unique, à
 * répartition séquentielle : une seule requête à la fois, car le transport
 * Bulk-Only ne traite qu'une commande à la fois (BOT §5), et nos envois sont
 * synchrones (docs/pilote.md § 2, « Exécution »). Ses rappels tournent à
 * PASSIVE_LEVEL (ExecutionLevel), le seul niveau où l'on peut attendre la fin
 * d'un URB.
 *
 * Chaque requête passe par la barrière (src/permis.c) avant tout envoi : ce
 * fichier est le seul chemin de l'espace utilisateur vers le scanner, et donc
 * le seul endroit où la vérification ne peut pas être contournée.
 */
#include "ds720d.h"
/* initguid.h avant ds720d_ioctl.h, dans ce seul source du pilote : le GUID de
 * l'interface y est défini, pas seulement déclaré. */
#include <initguid.h>
#include "ds720d_ioctl.h"
#include "permis.h"
#include "wpp.h"
#include "ioctl.tmh"

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL Ds720dIoctl;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, Ds720dCreerInterface)
#pragma alloc_text(PAGE, Ds720dIoctl)
#endif

/* Les étapes du transport ont les mêmes valeurs des deux côtés (bot.h). */
C_ASSERT(DS720D_ETAPE_RIEN == BOT_ETAPE_RIEN && DS720D_ETAPE_CBW == BOT_ETAPE_CBW &&
         DS720D_ETAPE_DONNEES == BOT_ETAPE_DONNEES && DS720D_ETAPE_CSW == BOT_ETAPE_CSW);

NTSTATUS Ds720dCreerInterface(WDFDEVICE appareil)
{
    WDF_IO_QUEUE_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributs;
    NTSTATUS statut;

    PAGED_CODE();
    /* L'interface est inscrite maintenant ; KMDF l'active au démarrage de
     * l'appareil et la désactive à son arrêt : elle n'existe pour l'outil que
     * lorsque le scanner est prêt. */
    statut = WdfDeviceCreateDeviceInterface(appareil, &GUID_DEVINTERFACE_DS720D, NULL);
    if (!NT_SUCCESS(statut)) {
        Trace(TRACE_LEVEL_ERROR, TRACE_IOCTL, "WdfDeviceCreateDeviceInterface a echoue (0x%08lX)", (ULONG)statut);
        return statut;
    }
    /* File par défaut : elle reçoit toutes les requêtes de l'outil. Gérée par
     * l'alimentation (valeur par défaut) : KMDF ne lui remet de requête que
     * lorsque l'appareil est en D0, donc configuré. */
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&config, WdfIoQueueDispatchSequential);
    config.EvtIoDeviceControl = Ds720dIoctl;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributs);
    attributs.ExecutionLevel = WdfExecutionLevelPassive;
    statut = WdfIoQueueCreate(appareil, &config, &attributs, WDF_NO_HANDLE);
    if (!NT_SUCCESS(statut))
        Trace(TRACE_LEVEL_ERROR, TRACE_IOCTL, "WdfIoQueueCreate a echoue (0x%08lX)", (ULONG)statut);
    return statut;
}

/* IOCTL_DS720D_CONTROLE : un transfert de contrôle entrant, si le paquet SETUP
 * est l'un de ceux de 1b. */
static NTSTATUS Controle(DS720D_APPAREIL *a, WDFREQUEST requete, size_t lg_sortie, size_t lg_entree, ULONG_PTR *info)
{
    PVOID entree, sortie;
    UCHAR setup[8];
    USHORT lg;
    ULONG n = 0;
    NTSTATUS statut;

    if (lg_entree != sizeof setup)
        return STATUS_INVALID_PARAMETER;
    statut = WdfRequestRetrieveInputBuffer(requete, sizeof setup, &entree, NULL);
    if (!NT_SUCCESS(statut))
        return statut;
    /* Copie avant tout : en METHOD_BUFFERED, l'entrée et la sortie partagent le
     * même tampon système, que la réponse va écraser. */
    RtlCopyMemory(setup, entree, sizeof setup);
    if (!permis_controle(setup)) {
        Trace(TRACE_LEVEL_WARNING, TRACE_IOCTL,
              "SETUP %02X %02X %02X %02X %02X %02X %02X %02X refuse par la barriere : rien n'est parti", setup[0],
              setup[1], setup[2], setup[3], setup[4], setup[5], setup[6], setup[7]);
        return STATUS_ACCESS_DENIED;
    }
    lg = (USHORT)(setup[6] | setup[7] << 8); /* wLength ; tous les paquets permis sont entrants */
    if (lg_sortie < lg)
        return STATUS_BUFFER_TOO_SMALL;
    statut = WdfRequestRetrieveOutputBuffer(requete, lg, &sortie, NULL);
    if (!NT_SUCCESS(statut))
        return statut;
    statut = UsbControle(&a->usb, setup, sortie, &n);
    *info = n;
    return statut;
}

/* IOCTL_DS720D_BOT : une commande Bulk-Only, si la barrière la permet. */
static NTSTATUS Bot(DS720D_APPAREIL *a, WDFREQUEST requete, size_t lg_sortie, size_t lg_entree, ULONG_PTR *info)
{
    DS720D_BOT_ENTREE e;
    DS720D_BOT_SORTIE s;
    BOT_RESULTAT r;
    PUCHAR entree, sortie, donnees;
    size_t lg_attendue;
    NTSTATUS statut;

    if (lg_entree < sizeof e)
        return STATUS_INVALID_PARAMETER;
    statut = WdfRequestRetrieveInputBuffer(requete, sizeof e, (PVOID *)&entree, NULL);
    if (!NT_SUCCESS(statut))
        return statut;
    RtlCopyMemory(&e, entree, sizeof e);

    /* Forme de la requête, avant la barrière : CDB de 1 à 16 octets (BOT §5.1),
     * sens 0 ou 1, LUN existant, phase de données de 64 Kio au plus, et des
     * tailles de tampons qui collent exactement à la commande. */
    if (e.lg_cdb < 1 || e.lg_cdb > 16 || e.sortant > 1 || e.reserve || e.lun > a->max_lun || e.lg > DS720D_LG_MAX)
        return STATUS_INVALID_PARAMETER;
    if (lg_entree != sizeof e + (e.sortant ? e.lg : 0))
        return STATUS_INVALID_PARAMETER;
    lg_attendue = sizeof s + (e.sortant ? 0 : e.lg);
    if (lg_sortie < lg_attendue)
        return STATUS_BUFFER_TOO_SMALL;

    /* La barrière, sur la commande complète (CDB, sens, longueur, et les
     * données d'un dépôt). Refusée : rien ne part, l'outil reçoit
     * ERROR_ACCESS_DENIED. */
    if (!permis_bot(e.cdb, e.lg_cdb, e.sortant, e.lg, e.sortant ? entree + sizeof e : NULL)) {
        Trace(TRACE_LEVEL_WARNING, TRACE_IOCTL,
              "commande refusee par la barriere : opcode 0x%02X, CDB de %u octets, %s %lu o ; rien n'est parti",
              e.cdb[0], e.lg_cdb, e.sortant ? "sortant" : "entrant", e.lg);
        return STATUS_ACCESS_DENIED;
    }

    statut = WdfRequestRetrieveOutputBuffer(requete, lg_attendue, (PVOID *)&sortie, NULL);
    if (!NT_SUCCESS(statut))
        return statut;
    /* Données : en sortie, les octets de l'outil, juste après l'en-tête
     * d'entrée ; en entrée, la place juste après l'en-tête de sortie. Le
     * tampon système est non paginé : la pile USB s'en sert tel quel. L'en-tête
     * de sortie n'est écrit qu'après le transport, pour ne pas écraser des
     * données sortantes encore à envoyer (même tampon). */
    donnees = e.sortant ? entree + sizeof e : sortie + sizeof s;
    BotCommande(&a->bot, e.lun, e.cdb, e.lg_cdb, e.sortant, e.lg ? donnees : NULL, e.lg, &r);

    RtlZeroMemory(&s, sizeof s);
    s.resultat = r.resultat;
    s.etape = r.etape;
    s.reprise = r.reprise ? 1 : 0;
    s.statut = r.statut;
    s.residu = r.residu;
    s.recus = r.recus;
    RtlCopyMemory(s.cbw, r.cbw, sizeof s.cbw);
    RtlCopyMemory(s.csw, r.csw, sizeof s.csw);
    RtlCopyMemory(sortie, &s, sizeof s);
    *info = sizeof s + (e.sortant ? 0 : r.recus);
    /* La requête a été traitée : réussite, même si le transport a échoué (le
     * détail est dans s.resultat). Le gestionnaire d'E/S ne recopierait pas la
     * sortie vers l'outil après un statut d'erreur. */
    return STATUS_SUCCESS;
}

VOID Ds720dIoctl(WDFQUEUE file, WDFREQUEST requete, size_t lg_sortie, size_t lg_entree, ULONG code)
{
    DS720D_APPAREIL *a = Ds720dAppareil(WdfIoQueueGetDevice(file));
    ULONG_PTR info = 0;
    NTSTATUS statut;

    PAGED_CODE();
    if (!a->entrant.poignee || !a->sortant.poignee) {
        statut = STATUS_DEVICE_NOT_READY; /* pas de configuration : ne devrait pas arriver en D0 */
    } else {
        switch (code) {
        case IOCTL_DS720D_CONTROLE:
            statut = Controle(a, requete, lg_sortie, lg_entree, &info);
            break;
        case IOCTL_DS720D_BOT:
            statut = Bot(a, requete, lg_sortie, lg_entree, &info);
            break;
        default:
            statut = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }
    WdfRequestCompleteWithInformation(requete, statut, info);
}
