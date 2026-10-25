/*
 * image.c : PGM et PNG écrits octet par octet, sans bibliothèque d'image ni zlib.
 *
 * Pourquoi PNG sans compression : le format PNG impose un flux zlib (RFC 1950)
 * de données deflate (RFC 1951), mais deflate prévoit des blocs « stockés »
 * (BTYPE = 00, RFC 1951 §3.2.4), recopiés tels quels. On reste ainsi au plus bas
 * niveau du format (signature, chunks, CRC-32, en-tête zlib, Adler-32) sans
 * écrire un compresseur, qui serait un projet en soi. Le prix : un fichier aussi
 * gros que l'image brute (environ 10 Mo pour une page en couleur), que
 * n'importe quel lecteur PNG ouvre. Pourquoi pas seulement PGM : Windows ne
 * l'ouvre pas sans logiciel tiers ; PGM reste utile car trivial à vérifier.
 *
 * Le PNG s'écrit au fil de l'eau : la taille du flux zlib se calcule d'avance
 * (en-tête, données filtrées, 5 octets par bloc stocké, Adler-32), ce qui permet
 * un seul chunk IDAT dont le CRC se calcule pendant l'écriture.
 */
#include "image.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Sommes de contrôle                                                        */
/* ------------------------------------------------------------------------- */

uint32_t image_crc32(uint32_t crc, const uint8_t *o, size_t lg)
{
    /* CRC-32 de PNG, annexe D de la spécification : polynôme 0x04C11DB7 en ordre
     * inversé (0xEDB88320), registre initialisé à 0xFFFFFFFF et complémenté à
     * la fin. L'appelant passe 0 pour commencer, puis le résultat précédent. */
    static uint32_t table[256];
    static int prete;
    if (!prete) {
        for (uint32_t n = 0; n < 256; n++) {
            uint32_t c = n;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[n] = c;
        }
        prete = 1;
    }
    crc = ~crc;
    for (size_t i = 0; i < lg; i++)
        crc = table[(crc ^ o[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

uint32_t image_adler32(uint32_t adler, const uint8_t *o, size_t lg)
{
    /* Adler-32, RFC 1950 §8.2 : deux sommes modulo 65521, s1 des octets (départ
     * à 1), s2 des s1 successifs ; l'appelant passe 1 pour commencer. */
    uint32_t s1 = adler & 0xFFFF, s2 = adler >> 16;
    for (size_t i = 0; i < lg; i++) {
        s1 = (s1 + o[i]) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    return s2 << 16 | s1;
}

/* ------------------------------------------------------------------------- */
/* PGM                                                                       */
/* ------------------------------------------------------------------------- */

int image_pgm(const char *chemin, const uint8_t *brut, size_t lignes)
{
    FILE *f;
    if (fopen_s(&f, chemin, "wbx") != 0) /* « x » : ne jamais écraser une image */
        return -1;
    /* En-tête Netpbm : « P5 », largeur, hauteur, valeur maximale, séparés par des
     * blancs, puis un seul blanc avant les octets, ligne par ligne de haut en bas. */
    int ok = fprintf(f, "P5\n%u %zu\n255\n", IMAGE_LARGEUR, lignes) > 0;
    for (size_t y = 0; ok && y < lignes; y++)
        ok = fwrite(brut + y * IMAGE_OCTETS_LIGNE + IMAGE_LARGEUR, 1, IMAGE_LARGEUR, f) == IMAGE_LARGEUR;
    return fclose(f) == 0 && ok ? 0 : -1;
}

/* ------------------------------------------------------------------------- */
/* PNG                                                                       */
/* ------------------------------------------------------------------------- */

#define BLOC_STOCKE_MAX 65535u /* LEN d'un bloc stocké tient sur 16 bits (RFC 1951 §3.2.4) */

/* Écrivain du chunk IDAT : il découpe le flux en blocs stockés, tient l'Adler-32
 * des données et le CRC-32 du chunk à jour. */
struct png {
    FILE *f;
    uint32_t crc;            /* CRC-32 du chunk IDAT en cours (type compris) */
    uint32_t adler;          /* Adler-32 des données non compressées */
    unsigned long long reste; /* octets de données encore à écrire */
    uint8_t bloc[BLOC_STOCKE_MAX];
    size_t dans_bloc;
    int ok;
};

static void pose_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* Octets du chunk IDAT : écrits et comptés dans son CRC. */
static void idat_ecrire(struct png *p, const uint8_t *o, size_t lg)
{
    if (p->ok && fwrite(o, 1, lg, p->f) != lg)
        p->ok = 0;
    p->crc = image_crc32(p->crc, o, lg);
}

/* Vide le bloc en cours : en-tête d'un octet (BFINAL au bit 0, BTYPE = 00 aux
 * bits 1-2, le reste de l'octet ignoré puisqu'un bloc stocké repart sur un
 * octet entier), LEN et NLEN en petit-boutiste, puis les données. */
static void bloc_vider(struct png *p)
{
    uint8_t entete[5];
    uint16_t lg = (uint16_t)p->dans_bloc;
    entete[0] = p->reste == 0 ? 0x01 : 0x00;
    entete[1] = (uint8_t)lg;
    entete[2] = (uint8_t)(lg >> 8);
    entete[3] = (uint8_t)~lg;
    entete[4] = (uint8_t)(~lg >> 8);
    idat_ecrire(p, entete, sizeof entete);
    idat_ecrire(p, p->bloc, p->dans_bloc);
    p->dans_bloc = 0;
}

/* Données non compressées (octet de filtre et points), au fil de l'eau. */
static void donnees_ecrire(struct png *p, const uint8_t *o, size_t lg)
{
    p->adler = image_adler32(p->adler, o, lg);
    while (lg) {
        size_t n = BLOC_STOCKE_MAX - p->dans_bloc;
        if (n > lg)
            n = lg;
        memcpy(p->bloc + p->dans_bloc, o, n);
        p->dans_bloc += n;
        p->reste -= n;
        o += n;
        lg -= n;
        if (p->dans_bloc == BLOC_STOCKE_MAX || p->reste == 0)
            bloc_vider(p);
    }
}

/* Un chunk complet hors IDAT : longueur, type, données, CRC du type et des
 * données (spécification PNG §5.3). */
static int chunk(FILE *f, const char type[4], const uint8_t *donnees, uint32_t lg)
{
    uint8_t t[8];
    pose_be32(t, lg);
    memcpy(t + 4, type, 4);
    uint32_t crc = image_crc32(image_crc32(0, t + 4, 4), donnees, lg);
    uint8_t c[4];
    pose_be32(c, crc);
    return fwrite(t, 1, 8, f) == 8 && fwrite(donnees, 1, lg, f) == lg && fwrite(c, 1, 4, f) == 4 ? 0 : -1;
}

int image_png(const char *chemin, const uint8_t *brut, size_t lignes, int couleur, unsigned ppp_y)
{
    /* Signature, §5.2 : 89 « PNG » CR LF SUB LF, faite pour détecter les
     * transferts qui abîment les fins de ligne ou le 8e bit. */
    static const uint8_t signature[8] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    static struct png p; /* 64 Kio de tampon : hors de la pile */
    uint32_t canaux = couleur ? 3 : 1;
    unsigned long long octets_ligne = 1ull + IMAGE_LARGEUR * canaux; /* octet de filtre + points */
    unsigned long long donnees = octets_ligne * lignes;
    unsigned long long blocs = (donnees + BLOC_STOCKE_MAX - 1) / BLOC_STOCKE_MAX;
    /* Flux zlib : CMF et FLG (2 o), blocs (5 o d'en-tête chacun), Adler-32 (4 o). */
    unsigned long long lg_zlib = 2 + donnees + 5 * blocs + 4;
    if (lignes == 0 || lignes > 0x7FFFFFFF || lg_zlib > 0x7FFFFFFF) /* longueurs PNG sur 31 bits, §5.3 */
        return -1;

    memset(&p, 0, sizeof p);
    if (fopen_s(&p.f, chemin, "wbx") != 0)
        return -1;
    p.ok = fwrite(signature, 1, sizeof signature, p.f) == sizeof signature;

    /* IHDR, §11.2.2 : largeur, hauteur (32 bits gros-boutistes), profondeur 8,
     * type de couleur 0 (gris) ou 2 (RVB), compression 0 (deflate), filtrage 0,
     * pas d'entrelacement. */
    uint8_t ihdr[13];
    pose_be32(ihdr, IMAGE_LARGEUR);
    pose_be32(ihdr + 4, (uint32_t)lignes);
    ihdr[8] = 8;
    ihdr[9] = couleur ? 2 : 0;
    ihdr[10] = ihdr[11] = ihdr[12] = 0;
    if (chunk(p.f, "IHDR", ihdr, sizeof ihdr) != 0)
        p.ok = 0;

    /* pHYs, §11.3.5.3 : points par mètre (300 par pouce = 11 811), unité 1
     * (mètre), pour qu'un logiciel affiche ou imprime la page à sa vraie taille et
     * avec ses proportions : à 600 dpi, seule la résolution verticale double. */
    uint8_t phys[9];
    pose_be32(phys, 11811);
    pose_be32(phys + 4, ppp_y == 600 ? 23622 : 11811); /* 600 / 0,0254 m, arrondi */
    phys[8] = 1;
    if (chunk(p.f, "pHYs", phys, sizeof phys) != 0)
        p.ok = 0;

    /* IDAT : longueur et type, puis le flux zlib. En-tête zlib, RFC 1950 §2.2 :
     * CMF = 0x78 (méthode 8, deflate ; fenêtre de 32 Kio), FLG = 0x01 (niveau 0,
     * pas de dictionnaire, et 0x7801 multiple de 31 comme l'exige FCHECK). */
    uint8_t t[8], zlib[2] = {0x78, 0x01};
    pose_be32(t, (uint32_t)lg_zlib);
    memcpy(t + 4, "IDAT", 4);
    if (fwrite(t, 1, 4, p.f) != 4)
        p.ok = 0;
    p.crc = 0;
    idat_ecrire(&p, t + 4, 4);
    idat_ecrire(&p, zlib, 2);
    p.adler = 1;
    p.reste = donnees;
    static uint8_t ligne[1 + 3 * IMAGE_LARGEUR];
    for (size_t y = 0; y < lignes; y++) {
        const uint8_t *src = brut + y * IMAGE_OCTETS_LIGNE;
        ligne[0] = 0; /* filtre 0 (« None », §9.2) : les points tels quels */
        if (couleur) {
            for (uint32_t x = 0; x < IMAGE_LARGEUR; x++) { /* plans R, V, B → points RVB */
                ligne[1 + 3 * x] = src[x];
                ligne[2 + 3 * x] = src[IMAGE_LARGEUR + x];
                ligne[3 + 3 * x] = src[2 * IMAGE_LARGEUR + x];
            }
        } else {
            memcpy(ligne + 1, src + IMAGE_LARGEUR, IMAGE_LARGEUR); /* plan vert */
        }
        donnees_ecrire(&p, ligne, (size_t)octets_ligne);
    }
    uint8_t a[4];
    pose_be32(a, p.adler); /* Adler-32 en gros-boutiste, RFC 1950 §2.2 */
    idat_ecrire(&p, a, 4);
    uint8_t c[4];
    pose_be32(c, p.crc);
    if (fwrite(c, 1, 4, p.f) != 4)
        p.ok = 0;

    if (chunk(p.f, "IEND", NULL, 0) != 0) /* IEND, §11.2.5 : vide */
        p.ok = 0;
    int ferme = fclose(p.f) == 0;
    return p.ok && ferme ? 0 : -1;
}
