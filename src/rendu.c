/*
 * rendu.c : recadrage, miroir du verso, courbe de tons et largeur doublée à
 * 600 dpi. Chaque règle vient d'une mesure sur les BMP du pilote Brother
 * (banc/image_brute.py, banc/courbe_tons.py) ; les sections citées sont celles
 * de docs/protocole.md.
 *
 * Pourquoi reproduire le pilote Brother plutôt qu'un rendu « à notre goût »
 * (étirement du blanc au blanc, gamma 2,2…) : c'est la seule référence mesurable,
 * chaque choix se vérifie contre ses BMP. Une retouche à nous ne se vérifierait
 * contre rien.
 *
 * Ce que l'on ne reproduit pas, volontairement :
 *   - le fond sombre que le pilote ajoute sous la feuille jusqu'à 14 po : c'est
 *     un remplissage du PC, pas une donnée du scanner ; la page s'arrête où
 *     s'arrête le brut ;
 *   - la correction de la couleur, qui dépend du document (§5, « Rendu du pilote
 *     Brother ») et dont on ignore l'algorithme. PALLIATIF : en couleur, on
 *     applique à chaque plan la courbe du gris. La page est juste en tons, mais
 *     plus sombre et moins équilibrée que celle du pilote.
 */
#include "rendu.h"

#include <stdlib.h>
#include <string.h>

/* Courbe de tons du gris, docs/courbe-gris.txt (étape 4c) : médiane des valeurs
 * du BMP du pilote pour chaque valeur brute du plan vert, sur six faces
 * (1e-gris-300-recto-twain-3, les quatre faces de 1e-gris-300-recto-verso,
 * 1e-gris-600-recto), mesurée de 45 à 177 ; ailleurs, la loi de puissance
 * 255 · (v / 255)^0,5544 qui colle à la mesure à 1,1 niveau près.
 * Pourquoi une table plutôt que pow() : elle garde la mesure telle quelle là où
 * elle existe, et le rendu reste en entiers, comme le fera le pilote noyau. */
const uint8_t rendu_courbe_gris[256] = {
      0,  12,  17,  22,  25,  29,  32,  35,  37,  40,  42,  45,  47,  49,  51,  53,  /*   0- 15 */
     55,  57,  59,  60,  62,  64,  66,  67,  69,  70,  72,  73,  75,  76,  78,  79,  /*  16- 31 */
     81,  82,  83,  85,  86,  87,  89,  90,  91,  93,  94,  95,  96,  97,  98, 100,  /*  32- 47 */
    101, 102, 103, 104, 105, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,  /*  48- 63 */
    118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133,  /*  64- 79 */
    134, 135, 136, 137, 138, 139, 139, 140, 141, 142, 143, 144, 145, 146, 146, 147,  /*  80- 95 */
    148, 150, 150, 151, 152, 152, 154, 155, 155, 156, 157, 158, 159, 160, 161, 161,  /*  96-111 */
    162, 163, 164, 165, 165, 166, 167, 168, 169, 169, 170, 171, 172, 172, 173, 174,  /* 112-127 */
    175, 175, 176, 177, 178, 178, 179, 180, 181, 181, 182, 183, 183, 184, 185, 186,  /* 128-143 */
    186, 187, 188, 188, 189, 190, 191, 191, 192, 193, 193, 194, 195, 195, 196, 197,  /* 144-159 */
    198, 198, 199, 200, 200, 201, 201, 202, 202, 204, 204, 205, 206, 206, 207, 208,  /* 160-175 */
    208, 209, 209, 210, 210, 211, 212, 212, 213, 213, 214, 215, 215, 216, 217, 217,  /* 176-191 */
    218, 219, 219, 220, 220, 221, 222, 222, 223, 223, 224, 225, 225, 226, 227, 227,  /* 192-207 */
    228, 228, 229, 230, 230, 231, 231, 232, 233, 233, 234, 234, 235, 236, 236, 237,  /* 208-223 */
    237, 238, 238, 239, 240, 240, 241, 241, 242, 243, 243, 244, 244, 245, 245, 246,  /* 224-239 */
    247, 247, 248, 248, 249, 249, 250, 251, 251, 252, 252, 253, 253, 254, 254, 255,  /* 240-255 */
};

/* Géométrie mesurée (§5 et §6), en lignes à 300 ppp et en colonnes brutes. */
#define PREMIERE_COLONNE 4u     /* recto : BMP(x, y) = brut(x + 4, y + 11) */
#define DERNIERE_COLONNE 2551u  /* verso : BMP(x, y) = brut(2 551 − x, y + 146) */
#define SAUT_RECTO 11u
#define SAUT_VERSO 146u         /* 135 lignes de retard du capteur arrière */
#define POINTS_300 2548u        /* largeur des BMP à 300 ppp */
#define POINTS_600 2550u        /* points bruts gardés à 600 ppp (BMP de 5 100) */

/* Colonne brute du k-ième point gardé, selon la face. */
static uint32_t colonne(uint32_t k, int verso)
{
    return verso ? DERNIERE_COLONNE - k : PREMIERE_COLONNE + k;
}

int rendu_page(const uint8_t *brut, size_t lignes, const struct rendu_options *o, struct image *im)
{
    memset(im, 0, sizeof *im);
    uint32_t canaux = o->couleur ? 3 : 1;
    im->canaux = canaux;
    im->ppp_y = o->ppp_y;

    if (o->brut) {
        /* Les plans tels quels, sans recadrage : à 600 dpi, 300 ppp en X. */
        if (lignes == 0 || lignes > 0x7FFFFFFF)
            return -1;
        im->largeur = IMAGE_LARGEUR;
        im->hauteur = (uint32_t)lignes;
        im->ppp_x = 300;
        im->points = malloc((size_t)im->largeur * im->hauteur * canaux);
        if (!im->points)
            return -1;
        for (size_t y = 0; y < lignes; y++) {
            const uint8_t *src = brut + y * IMAGE_OCTETS_LIGNE;
            uint8_t *dst = im->points + y * IMAGE_LARGEUR * canaux;
            if (canaux == 1) {
                memcpy(dst, src + IMAGE_LARGEUR, IMAGE_LARGEUR); /* plan vert */
            } else {
                for (uint32_t x = 0; x < IMAGE_LARGEUR; x++) { /* plans R, V, B → points RVB */
                    dst[3 * x] = src[x];
                    dst[3 * x + 1] = src[IMAGE_LARGEUR + x];
                    dst[3 * x + 2] = src[2 * IMAGE_LARGEUR + x];
                }
            }
        }
        return 0;
    }

    /* À 600 dpi, une ligne brute vaut une demi-ligne à 300 ppp : les sauts
     * doublent (22 lignes au recto, vérifié sur 1e-gris-600-recto ; 292 au verso,
     * DÉDUIT : aucune capture de recto-verso à 600 dpi). */
    unsigned facteur = o->ppp_y == 600 ? 2u : 1u;
    size_t saut = (size_t)(o->verso ? SAUT_VERSO : SAUT_RECTO) * facteur;
    uint32_t points = o->ppp_y == 600 ? POINTS_600 : POINTS_300;
    if (lignes <= saut || lignes - saut > 0x7FFFFFFF)
        return -1;
    im->hauteur = (uint32_t)(lignes - saut);
    im->largeur = points * facteur;
    im->ppp_x = 300 * facteur;
    im->points = malloc((size_t)im->largeur * im->hauteur * canaux);
    if (!im->points)
        return -1;

    /* Plans du gris : le vert seul (son plan suit le gris du pilote, 0,985 sur 2a,
     * §5) ; en couleur, rouge, vert, bleu. */
    static const uint32_t plans_gris[1] = {1}, plans_couleur[3] = {0, 1, 2};
    const uint32_t *plans = canaux == 1 ? plans_gris : plans_couleur;

    for (uint32_t y = 0; y < im->hauteur; y++) {
        const uint8_t *src = brut + (y + saut) * IMAGE_OCTETS_LIGNE;
        uint8_t *dst = im->points + (size_t)y * im->largeur * canaux;
        for (uint32_t c = 0; c < canaux; c++) {
            const uint8_t *plan = src + plans[c] * IMAGE_LARGEUR;
            for (uint32_t k = 0; k < points; k++) {
                uint8_t v = rendu_courbe_gris[plan[colonne(k, o->verso)]];
                if (facteur == 1) {
                    dst[k * canaux + c] = v;
                    continue;
                }
                /* 600 dpi (§5, étape 4b) : le point brut, puis la moyenne avec son
                 * voisin. Le voisin du dernier point gardé existe encore dans le
                 * brut (colonne 2 554 au recto, 1 au verso) : pas de cas de bord.
                 * La moyenne se fait après la courbe, sur les valeurs rendues.
                 * L'ordre du pilote n'est pas établi : moyenner les bruts puis
                 * appliquer la courbe ne changerait que les points intermédiaires
                 * aux bords des traits (la courbe est concave). L'écart moyen
                 * mesuré contre son BMP, 2,2 niveaux, ne justifie pas d'aller
                 * plus loin (étape 4d). */
                uint8_t suivant = rendu_courbe_gris[plan[colonne(k + 1, o->verso)]];
                dst[(2 * k) * canaux + c] = v;
                dst[(2 * k + 1) * canaux + c] = (uint8_t)((v + suivant + 1) / 2);
            }
        }
    }
    return 0;
}
