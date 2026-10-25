/*
 * bascule_winusb.c : installe WinUSB comme pilote du scanner DS-720D.
 *
 * Usage (terminal administrateur pour --oui) :
 *   bascule_winusb          dit ce qu'il ferait, sans rien changer
 *   bascule_winusb --oui    fait la bascule
 * Retour arrière : docs/winusb.md (pnputil /remove-device puis /scan-devices).
 *
 * Pourquoi ce programme : le Gestionnaire de périphériques ne propose que des
 * pilotes de la même classe d'installation que l'appareil. Le scanner est dans
 * la classe « USB » (contrôleurs de bus USB, {36FC9E60-…}, celle de usbstor.inf),
 * alors que winusb.inf déclare la classe « USBDevice » ({88BAE032-…}). Même par
 * « Disque fourni », il refuse (essai du 25/10, setupapi.dev.log). On fait donc
 * à la main, par SetupAPI, ce que le Gestionnaire ferait s'il acceptait :
 *   1. trouver le scanner, et lui seul ;
 *   2. passer sa classe d'installation à USBDevice (propriété ClassGUID, notée
 *      « R/W » dans setupapi.h) ;
 *   3. dresser la liste des pilotes de winusb.inf pour cet appareil et y prendre
 *      le modèle dont la section d'installation est WINUSB (le pilote de fonction,
 *      pas la variante de filtre WINUSB_LowerFilter ni les modèles Billboard/ADB) ;
 *   4. l'installer avec DiInstallDevice, l'API documentée pour installer un pilote
 *      précis du magasin de pilotes sur un appareil présent.
 * Pourquoi pas une INF à nous qui nommerait le scanner : elle devrait être signée.
 * Pourquoi pas Zadig : outil tiers, et il installe des INF générées et signées
 * par un certificat qu'il ajoute lui-même au magasin de confiance.
 */
/* UNICODE : DiInstallDevice n'existe qu'en version générique, dont le type
 * SP_DRVINFO_DATA suit ce réglage ; on travaille partout en UTF-16 (fonctions W). */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <newdev.h>
#include <setupapi.h>

#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define ID_SCANNER L"USB\\VID_04F9&PID_60E2"
/* [Version] ClassGuid de C:\Windows\INF\winusb.inf (classe « USBDevice »). */
#define CLASSE_USBDEVICE L"{88BAE032-5A81-49F0-BC3D-A4FF138216D6}"

static HDEVINFO liste = INVALID_HANDLE_VALUE;
static SP_DEVINFO_DATA scanner;

static int eleve(void)
{
    HANDLE jeton;
    TOKEN_ELEVATION e = {0};
    DWORD lg;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &jeton))
        return 0;
    GetTokenInformation(jeton, TokenElevation, &e, sizeof e, &lg);
    CloseHandle(jeton);
    return e.TokenIsElevated != 0;
}

static void propriete(DWORD prop, wchar_t *dst, DWORD taille)
{
    dst[0] = dst[1] = L'\0';
    SetupDiGetDeviceRegistryPropertyW(liste, &scanner, prop, NULL, (BYTE *)dst, taille - 2 * sizeof(wchar_t), NULL);
}

/* Trouve le scanner parmi les appareils USB présents, toutes classes confondues.
 * Refuse s'il y en a zéro ou plusieurs : on ne veut toucher qu'un appareil. */
static int trouver(void)
{
    if (liste != INVALID_HANDLE_VALUE)
        SetupDiDestroyDeviceInfoList(liste);
    liste = SetupDiGetClassDevsW(NULL, L"USB", NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (liste == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "SetupDiGetClassDevs a échoué (Win32=%lu)\n", GetLastError());
        return -1;
    }
    int n = 0;
    SP_DEVINFO_DATA app = {sizeof app};
    for (DWORD i = 0; SetupDiEnumDeviceInfo(liste, i, &app); i++) {
        wchar_t ids[1024] = L"";
        if (!SetupDiGetDeviceRegistryPropertyW(liste, &app, SPDRP_HARDWAREID, NULL, (BYTE *)ids,
                                               sizeof ids - 2 * sizeof(wchar_t), NULL))
            continue;
        for (const wchar_t *s = ids; *s; s += wcslen(s) + 1)
            if (_wcsicmp(s, ID_SCANNER) == 0) {
                scanner = app;
                n++;
                break;
            }
    }
    if (n != 1) {
        fprintf(stderr, "%d appareil(s) %ls présent(s) : il en faut exactement un.\n", n, ID_SCANNER);
        return -1;
    }
    return 0;
}

/* Liste les pilotes de winusb.inf pour le scanner et garde le modèle WINUSB.
 * Rien n'est écrit dans le registre ici : les paramètres d'installation ne
 * vivent que dans la liste en mémoire. */
static int chercher_winusb(SP_DRVINFO_DATA_W *pilote)
{
    SP_DEVINSTALL_PARAMS_W p = {sizeof p};
    SetupDiDestroyDriverInfoList(liste, &scanner, SPDIT_CLASSDRIVER);
    if (!SetupDiGetDeviceInstallParamsW(liste, &scanner, &p))
        return -1;
    GetWindowsDirectoryW(p.DriverPath, MAX_PATH);
    wcscat_s(p.DriverPath, MAX_PATH, L"\\INF\\winusb.inf");
    p.Flags |= DI_ENUMSINGLEINF;                /* cette INF seulement */
    p.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS;  /* y compris les modèles exclus des listes */
    if (!SetupDiSetDeviceInstallParamsW(liste, &scanner, &p) ||
        !SetupDiBuildDriverInfoList(liste, &scanner, SPDIT_CLASSDRIVER)) {
        fprintf(stderr, "liste des pilotes de winusb.inf impossible (Win32=%lu)\n", GetLastError());
        return -1;
    }
    static BYTE tampon[8192];
    SP_DRVINFO_DETAIL_DATA_W *detail = (SP_DRVINFO_DETAIL_DATA_W *)tampon;
    for (DWORD i = 0;; i++) {
        pilote->cbSize = sizeof *pilote;
        if (!SetupDiEnumDriverInfoW(liste, &scanner, SPDIT_CLASSDRIVER, i, pilote))
            break;
        detail->cbSize = sizeof *detail;
        if (!SetupDiGetDriverInfoDetailW(liste, &scanner, pilote, detail, sizeof tampon, NULL) &&
            GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            continue;
        printf("  modèle « %ls », section %ls\n", pilote->Description, detail->SectionName);
        if (_wcsicmp(detail->SectionName, L"WINUSB") == 0)
            return 0;
    }
    return 1; /* pas trouvé */
}

static void retour_arriere(void)
{
    fprintf(stderr, "Pour revenir à USBSTOR (terminal administrateur) :\n"
                    "  pnputil /remove-device /deviceid \"USB\\VID_04F9&PID_60E2\"\n"
                    "  pnputil /scan-devices\n");
}

int main(int argc, char **argv)
{
    int oui = argc > 1 && strcmp(argv[1], "--oui") == 0;
    wchar_t service[64], lieu[256], classe[64];
    SP_DRVINFO_DATA_W pilote;
    SetConsoleOutputCP(CP_UTF8);

    if (trouver() != 0)
        return 1;
    propriete(SPDRP_SERVICE, service, sizeof service);
    propriete(SPDRP_LOCATION_INFORMATION, lieu, sizeof lieu);
    propriete(SPDRP_CLASSGUID, classe, sizeof classe);
    printf("scanner : %ls, emplacement %ls, pilote %ls, classe %ls\n", ID_SCANNER, lieu, service, classe);
    if (_wcsicmp(service, L"WINUSB") == 0) {
        printf("déjà sous WinUSB : rien à faire.\n");
        return 0;
    }

    printf("pilotes de winusb.inf proposés sans changer de classe :\n");
    int r = chercher_winusb(&pilote);
    if (r < 0)
        return 1;
    if (!oui) {
        printf("%s\nAvec --oui, dans un terminal administrateur : %sinstallation du modèle WINUSB.\n",
               r == 0 ? "modèle WINUSB trouvé." : "modèle WINUSB absent : la classe doit changer.",
               r == 0 ? "" : "classe passée à USBDevice, puis ");
        return 0;
    }
    if (!eleve()) {
        fprintf(stderr, "--oui demande un terminal administrateur.\n");
        return 1;
    }

    if (r != 0) {
        /* Étape 2 : changement de classe. Windows supprime alors la clé logicielle
         * (clé « Driver ») de l'appareil, propre à l'ancienne classe ; USBSTOR reste
         * chargé jusqu'à l'installation suivante, qui redémarre l'appareil. */
        printf("changement de classe vers USBDevice %ls\n", CLASSE_USBDEVICE);
        if (!SetupDiSetDeviceRegistryPropertyW(liste, &scanner, SPDRP_CLASSGUID, (const BYTE *)CLASSE_USBDEVICE,
                                               (DWORD)sizeof CLASSE_USBDEVICE)) {
            fprintf(stderr, "changement de classe refusé (Win32=%lu) : rien n'a été modifié.\n", GetLastError());
            return 1;
        }
        /* On relit l'appareil pour repartir d'un élément à jour de sa nouvelle classe. */
        if (trouver() != 0 || chercher_winusb(&pilote) != 0) {
            fprintf(stderr, "modèle WINUSB toujours introuvable après le changement de classe.\n");
            retour_arriere();
            return 1;
        }
    }

    BOOL redemarrage = FALSE;
    printf("installation de « %ls » (winusb.inf, section WINUSB)…\n", pilote.Description);
    if (!DiInstallDevice(NULL, liste, &scanner, &pilote, DIIDFLAG_NOFINISHINSTALLUI, &redemarrage)) {
        fprintf(stderr, "DiInstallDevice a échoué (Win32=%lu, 0x%08lX)\n", GetLastError(), GetLastError());
        retour_arriere();
        return 1;
    }
    trouver();
    propriete(SPDRP_SERVICE, service, sizeof service);
    printf("fait : pilote %ls%s\n", service, redemarrage ? ", redémarrage de Windows demandé" : "");
    SetupDiDestroyDeviceInfoList(liste);
    return 0;
}
