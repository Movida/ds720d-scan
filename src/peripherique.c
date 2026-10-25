/*
 * peripherique.c : trouver, ouvrir et faire parler le scanner par WinUSB.
 *
 * Chemin d'un transfert : notre programme -> winusb.dll (espace utilisateur) ->
 * winusb.sys (pilote de fonction du scanner) -> pilote du concentrateur USB ->
 * contrôleur -> câble. winusb.sys traduit chaque appel en URB, la structure que
 * les pilotes USB s'échangent dans le noyau ; à l'étape 6, c'est notre pilote KMDF
 * qui fabriquera ces URB lui-même.
 *
 * Pourquoi WinUSB plutôt que libusb : libusb ajoute une couche qui ferait le travail
 * à notre place (règle du projet), et elle passe de toute façon par WinUSB sous
 * Windows. Pourquoi pas le SCSI pass-through sur USBSTOR : Windows y construirait
 * les CBW lui-même (voir docs/passation.md).
 */
#include "peripherique.h"
#include "trace.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
/* initguid.h avant usbiodef.h : le GUID y est alors défini, pas seulement déclaré. */
#include <initguid.h>
#include <setupapi.h>
#include <usbiodef.h>
#include <winusb.h>

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static HANDLE fichier = INVALID_HANDLE_VALUE;   /* poignée sur le scanner */
static WINUSB_INTERFACE_HANDLE winusb;          /* poignée WinUSB sur son interface 0 */

/* Délai maximal d'un transfert de contrôle : la réponse la plus lente de 1b
 * (descripteur DEVICE, trames 19191 à 19194) arrive en 4 ms ; 2 s laisse une
 * marge très large sans bloquer longtemps si le scanner ne répond pas. */
#define DELAI_CONTROLE_MS 2000

/* Délai maximal d'un transfert bulk. Une commande Bulk-Only de 1b se boucle en
 * moins d'une milliseconde (INQUIRY, trames 19225 à 19230) ; 5 s laisse une
 * grande marge tout en évitant d'attendre indéfiniment un scanner muet. */
#define DELAI_BULK_MS 5000

/* Lit une propriété texte (REG_SZ ou REG_MULTI_SZ) d'un appareil. */
static int propriete(HDEVINFO liste, SP_DEVINFO_DATA *app, DWORD prop, wchar_t *dst, DWORD taille)
{
    DWORD type;
    dst[0] = L'\0';
    return SetupDiGetDeviceRegistryPropertyW(liste, app, prop, &type, (BYTE *)dst, taille, NULL) ? 0 : -1;
}

/* Vrai si l'une des chaînes d'une liste REG_MULTI_SZ vaut motif (sans casse). */
static int contient(const wchar_t *multi, const wchar_t *motif)
{
    for (const wchar_t *s = multi; *s; s += wcslen(s) + 1)
        if (_wcsicmp(s, motif) == 0)
            return 1;
    return 0;
}

int periph_ouvrir(void)
{
    /* Interface de périphérique choisie : GUID_DEVINTERFACE_USB_DEVICE
     * ({A5DCBF10-6530-11D2-901F-00C04FB951ED}, usbiodef.h). Le pilote du
     * concentrateur l'enregistre pour tout appareil USB ; ouvrir son chemin envoie
     * la demande d'ouverture au sommet de la pile de l'appareil, ici winusb.sys.
     * Pourquoi pas une interface propre à WinUSB : le modèle générique de winusb.inf
     * n'en déclare aucune (pas de DeviceInterfaceGUIDs, voir docs/winusb.md). */
    wchar_t ident[64];
    swprintf(ident, 64, L"USB\\VID_%04X&PID_%04X", DS720D_VID, DS720D_PID);

    HDEVINFO liste = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_USB_DEVICE, NULL, NULL,
                                          DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (liste == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "SetupDiGetClassDevs a échoué (Win32=%lu)\n", GetLastError());
        return -1;
    }

    int trouve = 0;
    SP_DEVICE_INTERFACE_DATA itf = {sizeof itf};
    for (DWORD i = 0; !trouve && SetupDiEnumDeviceInterfaces(liste, NULL, &GUID_DEVINTERFACE_USB_DEVICE, i, &itf); i++) {
        /* Le détail (chemin d'accès) a une taille variable : premier appel pour la
         * connaître, second pour le lire. */
        DWORD taille = 0;
        SetupDiGetDeviceInterfaceDetailW(liste, &itf, NULL, 0, &taille, NULL);
        SP_DEVICE_INTERFACE_DETAIL_DATA_W *detail = malloc(taille);
        SP_DEVINFO_DATA app = {sizeof app};
        if (!detail)
            break;
        detail->cbSize = sizeof *detail;
        if (SetupDiGetDeviceInterfaceDetailW(liste, &itf, detail, taille, NULL, &app)) {
            wchar_t ids[1024], service[64];
            /* On reconnaît le scanner à son identifiant matériel plutôt qu'au chemin,
             * dont le format n'est pas documenté. */
            if (propriete(liste, &app, SPDRP_HARDWAREID, ids, sizeof ids - 2 * sizeof(wchar_t)) == 0 &&
                contient(ids, ident)) {
                trouve = 1;
                propriete(liste, &app, SPDRP_SERVICE, service, sizeof service);
                if (_wcsicmp(service, L"WINUSB") != 0) {
                    /* Sécurité : sous USBSTOR, le scanner est le disque F:. On ne
                     * l'ouvre pas, pour ne rien envoyer à la pile de stockage. */
                    fprintf(stderr, "Le scanner est sous le pilote « %ls », pas WinUSB : "
                                    "voir docs/winusb.md.\n", service);
                } else {
                    /* FILE_FLAG_OVERLAPPED : exigé par WinUSB, même pour des appels
                     * synchrones (doc WinUsb_Initialize). */
                    fichier = CreateFileW(detail->DevicePath, GENERIC_READ | GENERIC_WRITE,
                                          FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
                    if (fichier == INVALID_HANDLE_VALUE)
                        fprintf(stderr, "CreateFile a échoué (Win32=%lu)\n", GetLastError());
                }
            }
        }
        free(detail);
    }
    SetupDiDestroyDeviceInfoList(liste);

    if (!trouve) {
        fprintf(stderr, "Scanner %04X:%04X introuvable : est-il branché et allumé ?\n", DS720D_VID, DS720D_PID);
        return -1;
    }
    if (fichier == INVALID_HANDLE_VALUE)
        return -1;
    if (!WinUsb_Initialize(fichier, &winusb)) {
        fprintf(stderr, "WinUsb_Initialize a échoué (Win32=%lu)\n", GetLastError());
        CloseHandle(fichier);
        fichier = INVALID_HANDLE_VALUE;
        return -1;
    }
    ULONG delai = DELAI_CONTROLE_MS;
    WinUsb_SetPipePolicy(winusb, 0x00, PIPE_TRANSFER_TIMEOUT, sizeof delai, &delai);
    trace_note("scanner ouvert par WinUSB (interface GUID_DEVINTERFACE_USB_DEVICE)");
    return 0;
}

void periph_fermer(void)
{
    if (winusb) {
        WinUsb_Free(winusb);
        winusb = NULL;
    }
    if (fichier != INVALID_HANDLE_VALUE) {
        CloseHandle(fichier);
        fichier = INVALID_HANDLE_VALUE;
    }
}

long periph_controle(const uint8_t setup[8], uint8_t *donnees)
{
    /* WinUSB ne prend pas les 8 octets bruts mais une structure à cinq champs ; il
     * recompose le paquet à l'identique (mêmes champs, même ordre, petit-boutiste :
     * USB 2.0 table 9-2). On construit quand même les octets à la main : ce sont
     * eux qu'on trace, et eux qu'on comparera à la capture. */
    WINUSB_SETUP_PACKET sp;
    sp.RequestType = setup[0];
    sp.Request = setup[1];
    sp.Value = (USHORT)(setup[2] | setup[3] << 8);
    sp.Index = (USHORT)(setup[4] | setup[5] << 8);
    sp.Length = (USHORT)(setup[6] | setup[7] << 8);

    ULONG transferes = 0;
    int entrant = setup[0] & 0x80; /* bit 7 de bmRequestType : sens de l'étape DATA */
    trace_setup(setup);
    if (!entrant && sp.Length)
        trace_ctrl_out(donnees, sp.Length); /* données sortantes : tracées au départ */
    if (!WinUsb_ControlTransfer(winusb, sp, donnees, sp.Length, &transferes, NULL)) {
        trace_erreur(0x00, "contr\xC3\xB4le", GetLastError());
        return -1;
    }
    if (entrant && transferes)
        trace_ctrl_in(setup, donnees, transferes); /* données entrantes : tracées à l'arrivée */
    return (long)transferes;
}

/* Le délai est une politique de pipe WinUSB, à poser une fois par endpoint. */
static void delai_bulk(uint8_t endpoint)
{
    static uint8_t faits[32];
    unsigned i = (endpoint & 0x0F) | ((endpoint & 0x80) ? 16 : 0);
    if (!faits[i]) {
        ULONG delai = DELAI_BULK_MS;
        WinUsb_SetPipePolicy(winusb, endpoint, PIPE_TRANSFER_TIMEOUT, sizeof delai, &delai);
        faits[i] = 1;
    }
}

long periph_bulk_ecrire(uint8_t endpoint, const uint8_t *donnees, size_t lg, unsigned long *erreur)
{
    ULONG transferes = 0;
    delai_bulk(endpoint);
    /* WinUsb_WritePipe prend un tampon non constant, sans le modifier (doc WDK). */
    if (!WinUsb_WritePipe(winusb, endpoint, (PUCHAR)donnees, (ULONG)lg, &transferes, NULL)) {
        unsigned long e = GetLastError();
        trace_erreur(endpoint, "bulk", e);
        if (erreur)
            *erreur = e;
        return -1;
    }
    return (long)transferes;
}

long periph_bulk_lire(uint8_t endpoint, uint8_t *donnees, size_t lg, unsigned long *erreur)
{
    ULONG transferes = 0;
    delai_bulk(endpoint);
    if (!WinUsb_ReadPipe(winusb, endpoint, donnees, (ULONG)lg, &transferes, NULL)) {
        unsigned long e = GetLastError();
        trace_erreur(endpoint, "bulk", e);
        if (erreur)
            *erreur = e;
        return -1;
    }
    return (long)transferes;
}
