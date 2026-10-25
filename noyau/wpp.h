/*
 * wpp.h : configuration des traces WPP du pilote (étape 6c, docs/pilote.md).
 *
 * WPP (Windows software trace PreProcessor) : on écrit Trace(niveau, drapeau,
 * "format", arguments) comme un printf ; avant la compilation, tracewpp.exe lit
 * ce fichier et chaque source, et génère pour chacun un en-tête .tmh (ici
 * out\noyau\ds720d.tmh) qui remplace l'appel par un enregistrement binaire :
 * le pilote ne stocke que le numéro du message et ses arguments, le texte du
 * format reste dans le PDB et n'est reconstitué qu'à la lecture (doc WDK,
 * « WPP Software Tracing »). Coût presque nul quand personne n'écoute.
 *
 * Deux lecteurs, sans session de traçage à lancer dans la VM :
 *   - l'enregistreur en mémoire (Inflight Trace Recorder, IFR) : chaque
 *     message de niveau inférieur à VERBOSE est copié dans un tampon circulaire
 *     du pilote, que WinDbg lit par « !rcdrkd.rcdrlogdump ds720d », en direct
 *     ou dans un vidage mémoire après un plantage (doc WDK, « Using the
 *     Inflight Trace Recorder in KMDF and UMDF 2 Drivers »). Activé par
 *     ENABLE_WPP_RECORDER=1 (Makefile) et wpprecorder.lib, comme le fait le
 *     projet MSBuild du WDK (WindowsDriver.Common.targets) ;
 *   - le débogueur, en direct, sur demande seulement (depuis 6d) : WPP appelle
 *     WPP_DEBUG pour chaque message retenu (commentaire de tracemacro.tpl :
 *     « Called for each enabled event: WPP_DEBUG((MSG, arg1, arg2, arg3...)) »),
 *     ici un DbgPrintEx si la valeur de registre EchoDebogueur du service vaut
 *     1 (Parameters\EchoDebogueur, lue par DriverEntry ; noyau\installer.ps1
 *     echo 1). Conséquence : les formats ne doivent employer que des
 *     conversions que DbgPrint comprend aussi (%u, %lu, %lX, %s, %p…), pas les
 *     extensions de WPP comme %!STATUS!.
 *
 * Pourquoi la copie vers le débogueur est coupée par défaut (étape 6d) : avec
 * KDNET, chaque DbgPrint gèle les processeurs de la VM le temps d'envoyer le
 * message. Deux plantages 0x80 (NMI_HARDWARE_FAILURE, processeur au repos,
 * aucune ligne de notre code sur la pile) sont survenus juste après des
 * rafales de messages, WinDbg attaché ; quarante cycles de démarrage et
 * d'arrêt sans débogueur, aucun. La cause exacte côté VMware et Windows reste
 * déduite, pas prouvée (docs/pilote.md, 6d).
 *
 * Pourquoi pas DbgPrintEx seul, comme en 6b : rien ne resterait en mémoire
 * pour lire les derniers messages dans un vidage après un écran bleu, et
 * chaque message coûterait un formatage même sans débogueur.
 * Pourquoi pas une session ETW (tracelog) dans la VM : un outil de plus à y
 * copier et lancer, pour ce que l'IFR donne déjà (docs/pilote.md, § 2).
 */
#ifndef DS720D_WPP_H
#define DS720D_WPP_H

/* TRACE_LEVEL_ERROR, WARNING, INFORMATION, VERBOSE (niveaux d'ETW). */
#include <evntrace.h>

/*
 * Fournisseur de traces du pilote : un GUID tiré au hasard pour ce projet le
 * 25/10/2026 ({69D7FAD8-DB14-46C0-AD2F-35EE5136C07E}), et un drapeau par
 * couche du pilote (docs/pilote.md, « Couches »). Les drapeaux USB, BOT et
 * IOCTL serviront à partir de 6d et 6e ; leur ordre fixe leur valeur (1, 2,
 * 4…) : on n'en ajoute qu'à la fin.
 */
#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(Ds720dTraces, (69d7fad8, db14, 46c0, ad2f, 35ee5136c07e), \
        WPP_DEFINE_BIT(TRACE_PILOTE)  /* chargement, déchargement */ \
        WPP_DEFINE_BIT(TRACE_PNP)     /* rappels de PnP et d'alimentation */ \
        WPP_DEFINE_BIT(TRACE_USB)     /* URB (6d) */ \
        WPP_DEFINE_BIT(TRACE_BOT)     /* transport Bulk-Only (6e) */ \
        WPP_DEFINE_BIT(TRACE_IOCTL)   /* requêtes de l'outil (6e) */ \
    )

/*
 * Trace(NIVEAU, DRAPEAU, MSG, ...) : un message est émis vers une session ETW
 * si le drapeau y est activé avec un niveau suffisant ; c'est ce que disent
 * ces deux macros, reprises de la forme des exemples KMDF du WDK. Les niveaux
 * sont ceux d'evntrace.h : TRACE_LEVEL_ERROR, WARNING, INFORMATION, VERBOSE.
 */
#define WPP_LEVEL_FLAGS_LOGGER(niveau, drapeau) WPP_LEVEL_LOGGER(drapeau)
#define WPP_LEVEL_FLAGS_ENABLED(niveau, drapeau) \
    (WPP_LEVEL_ENABLED(drapeau) && WPP_CONTROL(WPP_BIT_##drapeau).Level >= niveau)

/*
 * Copie de chaque message retenu vers le débogueur (voir plus haut). WPP passe
 * la liste (MSG, arguments) entre parenthèses ; DS720D_MSG la déplie en
 * préfixant « ds720d : » et en ajoutant le saut de ligne que DbgPrint attend.
 * Niveau DPFLTR_ERROR_LEVEL : le seul affiché par défaut (comme en 6b).
 * « , ## __VA_ARGS__ » retire la virgule quand le message n'a pas d'argument :
 * avec /std:c17, cl emploie le préprocesseur conforme, qui la garderait sinon
 * (doc MSVC, « MSVC new preprocessor overview », élision de la virgule).
 */
#define DS720D_MSG(MSG, ...) "ds720d : " MSG "\n", ## __VA_ARGS__
/* Une expression et non une instruction : WPP place WPP_DEBUG dans une
 * expression à virgules (tracemacro.tpl). */
extern ULONG Ds720dEchoDebogueur;
#define WPP_DEBUG(args) \
    (Ds720dEchoDebogueur ? (void)DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DS720D_MSG args) : (void)0)

/*
 * Déclaration de la fonction de trace pour tracewpp, qui lit le bloc
 * ci-dessous avec l'option -scan du Makefile (en commentaires de ligne, comme
 * dans les exemples du WDK). NIVEAU et DRAPEAU s'y écrivent LEVEL et FLAGS :
 * ce sont les mots-clés que tracewpp reconnaît.
 */
// begin_wpp config
// FUNC Trace(LEVEL, FLAGS, MSG, ...);
// end_wpp

#endif
