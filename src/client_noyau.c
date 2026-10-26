/*
 * client_noyau.c : le transport de ds720dk.exe, par notre pilote noyau
 * ds720d.sys (étape 6e, docs/pilote.md § 1).
 *
 * ds720dk.exe, c'est ds720d.c, tunnel.c et trace.c tels quels, liés à ce
 * fichier au lieu de peripherique.c (WinUSB) et bot.c (Bulk-Only en espace
 * utilisateur), comme essai_bot.exe se lie à ses bouchons. Il fournit les mêmes
 * fonctions (peripherique.h, bot.h), mais par les deux IOCTL du pilote
 * (noyau/ds720d_ioctl.h) :
 *   - periph_controle : IOCTL_DS720D_CONTROLE, un paquet SETUP de 1b ;
 *   - bot_commande_in/out : IOCTL_DS720D_BOT, une commande Bulk-Only complète,
 *     dont le pilote construit le CBW, lit le CSW et fait la Reset Recovery.
 * Le pilote rend les octets du CBW et du CSW : la trace au format commun
 * s'écrit donc ici avec les mêmes fonctions de trace.c, et doit égaler, ligne
 * à ligne, celle de ds720d.exe sous WinUSB (tags mis à part).
 *
 * Les fonctions bulk et de déblocage de peripherique.h, et bot_reprise, ne
 * sont pas fournies : seul bot.c s'en servait, et c'est désormais le pilote
 * qui transporte. Une édition de liens qui en aurait besoin échouerait, ce qui
 * est voulu.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
/* initguid.h avant ds720d_ioctl.h : le GUID de l'interface est défini ici. */
#include <initguid.h>
#include <setupapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bot.h"
#include "client_noyau.h"
#include "peripherique.h"
#include "trace.h"
#include "../noyau/ds720d_ioctl.h"

static HANDLE pilote = INVALID_HANDLE_VALUE;
/* Chemin de l'interface ouverte, gardé pour periph_seconde_ouverture. */
static wchar_t *chemin;

/* Ouvre l'interface du pilote. Lecture et écriture : les IOCTL du pilote les
 * exigent (FILE_READ_DATA | FILE_WRITE_DATA). Le partage (0) ne compte pas :
 * le gestionnaire d'E/S ne l'applique qu'aux fichiers ; c'est le pilote qui
 * n'accepte qu'un client à la fois (Ds720dOuverture, noyau/ds720d.c). */
static HANDLE ouvrir(const wchar_t *p)
{
    return CreateFileW(p, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

int periph_ouvrir(void)
{
    /* Le scanner se trouve par l'interface de périphérique de notre pilote,
     * présente seulement quand ds720d.sys tient le scanner et l'a démarré. */
    HDEVINFO liste = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_DS720D, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (liste == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "SetupDiGetClassDevs a échoué (Win32=%lu)\n", GetLastError());
        return -1;
    }
    SP_DEVICE_INTERFACE_DATA itf = {sizeof itf};
    int n = 0;
    for (DWORD i = 0; SetupDiEnumDeviceInterfaces(liste, NULL, &GUID_DEVINTERFACE_DS720D, i, &itf); i++) {
        DWORD taille = 0;
        n++;
        if (n > 1 || pilote != INVALID_HANDLE_VALUE)
            continue;
        if (!SetupDiGetDeviceInterfaceDetailW(liste, &itf, NULL, 0, &taille, NULL) &&
            (GetLastError() != ERROR_INSUFFICIENT_BUFFER || taille < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)))
            continue;
        SP_DEVICE_INTERFACE_DETAIL_DATA_W *detail = malloc(taille);
        if (!detail)
            break;
        detail->cbSize = sizeof *detail;
        if (SetupDiGetDeviceInterfaceDetailW(liste, &itf, detail, taille, NULL, NULL)) {
            pilote = ouvrir(detail->DevicePath);
            if (pilote == INVALID_HANDLE_VALUE) {
                DWORD e = GetLastError();
                fprintf(stderr, "CreateFile a échoué (Win32=%lu)%s\n", e,
                        e == ERROR_SHARING_VIOLATION ? " : le scanner est déjà ouvert par un autre programme "
                                                       "(le pilote n'accepte qu'un client à la fois)"
                        : e == ERROR_ACCESS_DENIED ? " : droits refusés (descripteur de sécurité posé par l'INF)"
                                                   : "");
            } else {
                chemin = _wcsdup(detail->DevicePath);
            }
        }
        free(detail);
    }
    SetupDiDestroyDeviceInfoList(liste);
    if (n == 0) {
        fprintf(stderr, "Aucun scanner tenu par le pilote ds720d : le pilote est-il installé, le scanner "
                        "branché (dans la VM) ?\n");
        return -1;
    }
    if (n > 1) {
        fprintf(stderr, "%d scanners tenus par le pilote ds720d : un seul est attendu\n", n);
        periph_fermer();
        return -1;
    }
    if (pilote == INVALID_HANDLE_VALUE)
        return -1;
    trace_note("scanner ouvert par le pilote noyau ds720d (interface GUID_DEVINTERFACE_DS720D)");
    return 0;
}

void periph_fermer(void)
{
    if (pilote != INVALID_HANDLE_VALUE) {
        CloseHandle(pilote);
        pilote = INVALID_HANDLE_VALUE;
    }
    free(chemin);
    chemin = NULL;
}

unsigned long periph_seconde_ouverture(void)
{
    if (pilote == INVALID_HANDLE_VALUE || !chemin)
        return ERROR_INVALID_HANDLE; /* pas de première ouverture : rien à éprouver */
    HANDLE h = ouvrir(chemin);
    if (h == INVALID_HANDLE_VALUE)
        return GetLastError();
    CloseHandle(h);
    return ERROR_SUCCESS;
}

long periph_controle(const uint8_t setup[8], uint8_t *donnees)
{
    DWORD n = 0;
    uint16_t lg = (uint16_t)(setup[6] | setup[7] << 8);

    trace_setup(setup);
    /* Le pilote n'accepte que les paquets SETUP de 1b, tous entrants. */
    if (!(setup[0] & 0x80)) {
        fprintf(stderr, "transfert de contrôle sortant : le pilote ne le permet pas\n");
        return -1;
    }
    if (!DeviceIoControl(pilote, IOCTL_DS720D_CONTROLE, (void *)setup, 8, donnees, lg, &n, NULL)) {
        DWORD e = GetLastError();
        trace_erreur(0x00, "contr\xC3\xB4le", e);
        if (e == ERROR_ACCESS_DENIED)
            fprintf(stderr, "paquet SETUP refusé par la barrière du pilote (src/permis.c)\n");
        SetLastError(e); /* rendu à l'appelant (essai_refus.c), après les écritures ci-dessus */
        return -1;
    }
    if (n)
        trace_ctrl_in(setup, donnees, n);
    return (long)n;
}

void bot_init(uint8_t interface, uint8_t ep_in, uint8_t ep_out)
{
    /* Le pilote a lu lui-même les descripteurs et choisi ses pipes au
     * démarrage (noyau/ds720d.c) : rien à retenir ici. */
    (void)interface;
    (void)ep_in;
    (void)ep_out;
}

/* Une commande par IOCTL_DS720D_BOT, puis la trace des trois temps, dans
 * l'ordre où ils ont eu lieu sur le bus : CBW, données, CSW (comme src/bot.c). */
static int commande(uint8_t lun, const uint8_t *cdb, uint8_t lg_cdb, int sortant, uint8_t *donnees, uint32_t lg,
                    struct bot_resultat *r)
{
    if (lg_cdb < 1 || lg_cdb > 16 || lg > DS720D_LG_MAX)
        return -1;
    DWORD lg_entree = sizeof(DS720D_BOT_ENTREE) + (sortant ? lg : 0);
    DWORD lg_sortie = sizeof(DS720D_BOT_SORTIE) + (sortant ? 0 : lg);
    uint8_t *entree = calloc(1, lg_entree), *sortie = calloc(1, lg_sortie);
    DWORD n = 0, erreur = ERROR_SUCCESS;
    int resultat = -1;

    if (!entree || !sortie) {
        fprintf(stderr, "mémoire insuffisante\n");
        goto fin;
    }
    DS720D_BOT_ENTREE *e = (DS720D_BOT_ENTREE *)entree;
    memcpy(e->cdb, cdb, lg_cdb);
    e->lg_cdb = lg_cdb;
    e->sortant = sortant ? 1 : 0;
    e->lun = lun;
    e->lg = lg;
    if (sortant && lg)
        memcpy(entree + sizeof *e, donnees, lg);

    if (!DeviceIoControl(pilote, IOCTL_DS720D_BOT, entree, lg_entree, sortie, lg_sortie, &n, NULL)) {
        erreur = GetLastError();
        if (erreur == ERROR_ACCESS_DENIED)
            fprintf(stderr, "commande 0x%02X refusée par la barrière du pilote (src/permis.c) : rien n'est parti\n",
                    cdb[0]);
        else
            fprintf(stderr, "IOCTL_DS720D_BOT a échoué (Win32=%lu)\n", erreur);
        trace_note("commande 0x%02X non transmise par le pilote (Win32=%lu)", cdb[0], erreur);
        goto fin;
    }
    if (n < sizeof(DS720D_BOT_SORTIE)) {
        fprintf(stderr, "réponse du pilote trop courte (%lu octets)\n", n);
        goto fin;
    }
    const DS720D_BOT_SORTIE *s = (const DS720D_BOT_SORTIE *)sortie;
    if (s->etape >= DS720D_ETAPE_CBW) {
        trace_cbw(s->cbw);
        if (sortant && lg)
            trace_data_out(donnees, lg); /* comme src/bot.c : tracées au départ */
    }
    if (!sortant && s->recus) {
        if (s->recus > lg || n < sizeof *s + s->recus) {
            fprintf(stderr, "réponse du pilote incohérente (%lu octets annoncés)\n", s->recus);
            goto fin;
        }
        memcpy(donnees, sortie + sizeof *s, s->recus);
        trace_data_in(donnees, s->recus);
    }
    if (s->etape >= DS720D_ETAPE_CSW)
        trace_csw(s->csw);
    if (s->reprise)
        trace_note("Reset Recovery (BOT §5.3.4), faite par le pilote");
    if (s->resultat != 0) {
        fprintf(stderr, "transport Bulk-Only : échec 0x%08lX à l'étape %u (le pilote a %sfait une Reset Recovery)\n",
                (unsigned long)s->resultat, s->etape, s->reprise ? "" : "pas ");
        goto fin;
    }
    r->statut = s->statut;
    r->residu = s->residu;
    r->recus = s->recus;
    resultat = 0;
fin:
    free(entree);
    free(sortie);
    /* Le code d'erreur de DeviceIoControl, s'il y en a eu un, rendu à
     * l'appelant (essai_refus.c) après les écritures et libérations ci-dessus. */
    if (erreur != ERROR_SUCCESS)
        SetLastError(erreur);
    return resultat;
}

int bot_commande_in(uint8_t lun, const uint8_t *cdb, uint8_t lg_cdb, uint8_t *donnees, uint32_t lg,
                    struct bot_resultat *r)
{
    return commande(lun, cdb, lg_cdb, 0, donnees, lg, r);
}

int bot_commande_out(uint8_t lun, const uint8_t *cdb, uint8_t lg_cdb, const uint8_t *donnees, uint32_t lg,
                     struct bot_resultat *r)
{
    /* commande() ne modifie pas un tampon sortant : elle le recopie dans la
     * requête et le trace. */
    return commande(lun, cdb, lg_cdb, 1, (uint8_t *)donnees, lg, r);
}
