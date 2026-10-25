/*
 * trace.h : trace de chaque transfert USB émis par notre code.
 *
 * Une ligne par évènement, au format commun décrit dans docs/format-trace.md,
 * le même que celui qu'écrit l'analyseur de captures (banc/analyse_capture.py).
 * Les deux traces se comparent alors ligne à ligne avec banc/compare_traces.py.
 *
 * Le module garde un petit état, comme l'analyseur : le dernier CBW envoyé
 * (pour décoder la réponse et vérifier le tag du CSW) et l'index du descripteur
 * STRING du numéro de série (pour le masquer s'il passait par là).
 */
#ifndef DS720D_TRACE_H
#define DS720D_TRACE_H

#include <stddef.h>
#include <stdint.h>

/* Ouvre la trace. chemin peut valoir NULL : sortie standard seulement.
 * Sinon, chaque ligne part aussi dans ce fichier (UTF-8). Renvoie 0 si tout va bien. */
int trace_ouvrir(const char *chemin);
void trace_fermer(void);

/* Ligne de commentaire « # … », ignorée par la comparaison. */
void trace_note(const char *format, ...);

/* Transferts de contrôle (USB 2.0 §9.3 et §8.5.3). */
void trace_setup(const uint8_t setup[8]);
void trace_ctrl_in(const uint8_t setup[8], const uint8_t *donnees, size_t lg);
void trace_ctrl_out(const uint8_t *donnees, size_t lg);

/* Transport Bulk-Only (BOT §5.1 et §5.2). */
void trace_cbw(const uint8_t cbw[31]);
void trace_data_in(const uint8_t *donnees, size_t lg);
void trace_data_out(const uint8_t *donnees, size_t lg);
void trace_csw(const uint8_t csw[13]);

/* Transfert qui a échoué : endpoint, type (« contrôle », « bulk ») et code
 * d'erreur Win32 rendu par GetLastError() après l'appel WinUSB. */
void trace_erreur(uint8_t endpoint, const char *type, unsigned long code_win32);

#endif
