"""Garde anti-suppression : bloquer l'effacement accidentel du projet par un agent, y compris rm -rf en mode sans permission. Eviter qu'un agent efface le depot par erreur. Hook PreToolUse Claude Code et Codex avec confirmation humaine.

Pourquoi
--------
04/10 : l'audit des harnais a montre que l'invariant « hook anti-suppression sous la racine
du depot » ne tenait pas :
- Codex : `bash C:/...garde-suppression.sh` sortait en 127 (fichier introuvable), 78 fois
  sur 80, et le lanceur tolerant rendait 0. Codex en mode YOLO n'avait aucune garde.
- Claude : le hook ne visait que l'outil `Bash`, alors que ce poste passe par `PowerShell`.
- Les deux : `Remove-Item .x -Recurse`, `rm -rf ./x` ou `git clean -fd` lances depuis le depot
  passaient, faute du nom du depot dans la commande.

Racine protegee : variable d'environnement GARDE_RACINE (chemin absolu), sinon le dossier
courant au lancement du hook. Tout dossier qui porte le meme nom que la racine (clone,
worktree, montage WSL) est traite comme le depot : la garde prefere refuser trop que trop peu.

Regle : analyse statique des formes connues, sans executer la commande. Les suppressions
depuis le depot exigent des cibles toutes absolues et temporaires. Les deplacements internes
et les ecritures ordinaires restent permis. Les fichiers listes ci-dessous sont proteges.
Ce filtre n'est pas un interpreteur de shell ni une isolation du systeme de fichiers.

Usage (stdin : JSON du hook) :
    python garde_suppression.py claude   # refus : message sur stderr, code 2
    python garde_suppression.py codex    # refus : permissionDecision deny, code 0
    python garde_suppression.py antigravity  # refus : {"decision": "deny"}, sinon {"decision": "ask"}
    python garde_suppression.py hermes   # refus : {"decision": "block"} sur stdout (hook pre_tool_call d'Hermes)
    python garde_suppression.py --bilan 7  # refus par regle et moteur sur les 7 derniers jours
Trace hors depot : ~/.codex/hooks/garde_trace.jsonl, ou GARDE_TRACE pour les tests.
Les anciennes lignes sans date sont comptees a part, sans leur inventer de date.
Une erreur de la garde elle-meme refuse aussi : une garde en panne ne laisse rien passer.
"""

from __future__ import annotations

import json
import ntpath
import os
import re
import sys

# 12/10 (latence) : ast, fnmatch et pathlib ne sont plus importes au demarrage.
# La garde tourne avant chaque commande, ast n'est utile qu'au code Python en ligne.
TRACE = os.environ.get("GARDE_TRACE") or os.path.join(
    os.path.expanduser("~"), ".codex", "hooks", "garde_trace.jsonl"
)

# Chemins relatifs a chaque racine du depot ou atelier. CLAUDE.md, la garde et .git sont
# proteges a toute profondeur. Les deux configurations le sont aussi hors depot.
FICHIERS_PROTEGES = (
    "claude.md",
    "garde_suppression.py",
    ".claude/settings.json",
    ".codex/hooks.json",
    ".git",
)
MESSAGE = (
    "SUPPRESSION BLOQUEE dans le depot protege : confirmation humaine requise. "
    "Explique la raison a l'utilisateur et laisse-lui le geste (hook anti-suppression). "
    "Pour git stash ou git merge, fusion humaine par geste, arbre propre d'abord "
    "(git status --porcelain --untracked-files=no doit etre vide)."
)

SUPPRESSIONS = {
    "rm",
    "rmdir",
    "rd",
    "del",
    "erase",
    "ri",
    "remove-item",
    "clear-content",
    # Verbes manquants a la relecture Antigravity du 05/10.
    "shred",
    "wipe",
    "srm",
    "unlink",
    "rimraf",
    "trash",
    "trash-put",
}
DEPLACEMENTS = {"move-item", "mv", "move", "mi"}
# Renommage sur place : ren et rename de cmd equivalent a Rename-Item (relecture Antigravity).
RENOMME = {"rename-item", "rni", "ren", "rename"}
COPIES = {"copy-item", "cp", "copy", "cpi"}
# Definition d'un alias dans la commande : le verbe cree est applique a la suite de la ligne.
ALIAS_DEF = {"set-alias", "new-alias", "sal", "nal"}
# Cles de configuration git qui desarment un hook ou redirigent une commande.
GIT_CONFIG_DESARME = {"core.hookspath", "core.fsmonitor", "core.sshcommand"}
TELECHARGEURS = {
    "curl",
    "wget",
    "certutil",
    "invoke-webrequest",
    "iwr",
    "invoke-restmethod",
    "irm",
}
EXTRACTEURS = {"tar", "7z", "7za", "7zr", "expand-archive"}
# .DownloadFile(url, cible) de WebClient : la cible ecrite est le second argument.
TELECHARGE_NET = re.compile(
    r"(?i)\.downloadfile(?:async)?\s*\(\s*[^,]*,\s*(.*?)\s*(?:,|\))"
)
ECRITURES = {
    "set-content",
    "out-file",
    "add-content",
    "new-item",
    "copy-item",
    "rename-item",
    "tee-object",
}
# Commande opaque (chaine evaluee ou encodee) : son contenu ne se lit pas, on la traite comme destructrice.
OPAQUE = re.compile(
    r"(?i)\b(iex|invoke-expression)\b|\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{8,}"
)
# Lanceurs (relecture Antigravity du 05/10) : ils executent une autre commande, jugee comme si
# elle etait tapee seule. Coquilles, interpretes avec code en ligne, prefixes, Start-Process.
COQUILLES = {"cmd", "powershell", "pwsh", "bash", "sh", "zsh", "dash", "ksh", "fish"}
INTERPRETES = {
    "node": r"-e|--eval|-p|--print",
    "nodejs": r"-e|--eval|-p|--print",
    "bun": r"-e|--eval|-p|--print",
    "perl": r"-[a-zA-Z0-9]*[eE]",
    "ruby": r"-[a-zA-Z]*e",
    "php": r"-r",
    "lua": r"-e",
    "rscript": r"-e",
}
# Prefixes qui lancent la suite de la ligne, avec leurs options a valeur.
PREFIXES = {
    "env": {"-u", "--unset", "-C", "--chdir"},
    "sudo": {"-u", "-g", "-p", "-C", "-D", "-h", "-r", "-t", "-U", "--user", "--chdir"},
    "doas": {"-u", "-C"},
    "nice": {"-n", "--adjustment"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "nohup": set(),
    "time": set(),
    "busybox": set(),
    "exec": {"-a"},
    "command": set(),
    "builtin": set(),
    "call": set(),
    "wsl": {"-d", "--distribution", "-u", "--user", "--cd"},
    "xargs": {"-I", "-n", "-P", "-d", "-a", "-L", "-s", "-E"}
    | {"--max-args", "--max-procs", "--delimiter", "--arg-file", "--replace", "--eof"},
}
VALEURS_COQUILLES = {
    "-executionpolicy",
    "-ep",
    "-ex",
    "-windowstyle",
    "-w",
    "-version",
    "-inputformat",
    "-if",
    "-outputformat",
    "-of",
    "-psconsolefile",
    "-configurationname",
    "-settingsfile",
    "-workingdirectory",
    "-wd",
    "-o",
    "--rcfile",
    "--init-file",
}
# Operateurs PowerShell qui suivent une valeur : la ligne est une expression, pas un appel.
OPERATEURS = {",", "=", "+=", "-=", "+", "-", "*", "/", "%", ".."} | {
    f"-{o}"
    for o in [
        "eq",
        "ne",
        "gt",
        "ge",
        "lt",
        "le",
        "like",
        "notlike",
        "match",
        "notmatch",
        "contains",
        "notcontains",
        "in",
        "notin",
        "is",
        "isnot",
        "as",
        "replace",
        "split",
        "join",
        "f",
        "and",
        "or",
        "xor",
        "not",
        "band",
        "bor",
        "ceq",
        "ieq",
        "cmatch",
        "imatch",
        "creplace",
        "ireplace",
    ]
}
DEMARRER = {"start-process", "start", "saps"}
VALEURS_DEMARRER = (
    "-verb",
    "-windowstyle",
    "-redirectstandardinput",
    "-redirectstandardoutput",
    "-redirectstandarderror",
    "-credential",
    "-environment",
)
# Code en ligne d'un interprete qui detruit ou lance une commande shell.
SCRIPT_DESTRUCTEUR = re.compile(
    r"(?i)\b(?:rm|rmdir|rm_r|rm_rf|rmSync|rmdirSync|unlink|unlinkSync|rmtree|remove_tree|"
    r"remove_dir|remove_entry|delete|truncate|truncateSync|writeFile|writeFileSync|system|"
    r"exec|execSync|execFile|execFileSync|spawn|spawnSync|popen|child_process|qx|"
    r"shell_exec|passthru|proc_open|fileutils)\b|`"
)
# 12/10 : seules les fonctions de subprocess qui lancent un programme (list2cmdline ne lance rien).
EXEC_PY = re.compile(
    r"os\.(?:system|popen|exec\w*|spawn\w*|posix_spawnp?)|"
    r"subprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)|"
    r"pty\.spawn"
)
SUPPR_PY = {"shutil.rmtree", "os.remove", "os.unlink", "os.rmdir", "os.removedirs"}
# Deplacements Python : la source quitte le depot, equivalent de mv (Fable, passe 4).
DEPLACE_PY = {"shutil.move", "os.replace", "os.rename"}
CHANGE_DOSSIER = {
    "cd",
    "chdir",
    "set-location",
    "sl",
    "pushd",
    "push-location",
    "popd",
    "pop-location",
}
CHANGE_DOSSIER_RE = re.compile(
    r"(?i)(?:^|[\s\x3b&|({])(?:" + "|".join(CHANGE_DOSSIER) + r")(?=\s|$)"
)
# Here-string PowerShell, recrite en citation simple pour rester un seul mot.
ICI = re.compile(r"(?s)@(['\"])\r?\n(.*?)\r?\n\1@")
CITATION = re.compile(r"""'(?:''|[^'])*'|"(?:\\"|""|[^"])*\"""")
# Flux de tube dont le contenu ne se lit pas (sortie d'un programme).
INCONNU = ["*"]
VARIABLE = re.compile(
    r"(?i)\$env:([a-z_][a-z0-9_]*)|%([a-z_][a-z0-9_]*)%|\$\{?([a-z_][a-z0-9_]*)\}?"
)
# Fournisseurs PowerShell qui ne designent pas un fichier : retirer une variable
# d'environnement, une variable, une fonction ou un alias n'efface rien sur disque.
FOURNISSEUR_NON_FICHIER = re.compile(
    r"(?i)^(?:env|variable|function|alias|cert|wsman):"
)
# Les citations restent intactes jusqu'au decoupage, notamment dans les messages Git.
# Les accolades des blocs de script separent les commandes, sauf {} (xargs -I{}, find -exec).
MOTS = re.compile(
    r"""(?:\d+|\*)?>>?&\d+|(?:[^\s'"\x3b&|,<>{}]+|\{\}|'(?:''|[^'])*'|"(?:\\"|""|[^"])*")+|>>?|[\x3b&|,\n{}]"""
)
SEP = {chr(59), "&", "|", "\n", "{", "}"}
# Blocs dont le contenu recoit le flux du tube.
BOUCLES = {"foreach-object", "%", "foreach", "where-object", "?", "where"}
# Blocs crees hors de la ligne lisible et methodes de suppression des objets fichiers.
DYNAMIQUE = re.compile(
    r"(?i)\[scriptblock\]::create|\.(?:invokescript|addscript)\s*\(|"
    r"\.(?:delete|deletesubdirectory|movetorecyclebin)\s*\(|"
    r"(?:^|[\s|{\x3b])(?:%|foreach-object|foreach)\s+(?:-membername\s+)?delete\b"
)
# 12/10 (faux refus) : mots-cles du shell qui precedent une commande executee (do rm ..., then rm ...).
MOTS_CLES = {"do", "then", "else", "elif", "if", "while", "until", "!"}
# Affectation PowerShell collee en tete de segment : $t=Get-X, [xml]$s=Get-Content, \$i= dans une citation bash.
AFFECTATION_PS = re.compile(
    r"(?i)^(?:\[[\w.\[\]]+\])*\\?\$[a-z_][\w:]*(?:\[[^\]]*\])?\+?=(.*)$", re.DOTALL
)
# Here-document bash : <<EOF, <<'EOF', <<"EOF", <<-EOF. Le corps est l'entree standard de la commande.
HEREDOC = re.compile(r"<<(-?)[ \t]*(?:'([^'\n]*)'|\"([^\"\n]*)\"|\\?([\w.\-]+))")
# Here-string bash : <<< mot.
HERESTRING = re.compile(r"""<<<[ \t]*((?:[^\s'"\x3b&|<>]+|'[^']*'|"(?:\\"|[^"])*")+)""")
MARQUE_ENTREE = "\x01"
# Affectation litterale d'une variable locale, seule sur son segment (S="C:/x" && ..., $o = 'x').
AFFECTATION_LOCALE = re.compile(
    r"(?:^|(?<=\n)|(?<=\x3b)|(?<=&&))[ \t]*(?:export[ \t]+)?"
    r"(?:([A-Za-z_]\w*)=|\$([A-Za-z_]\w*)[ \t]*=[ \t]*)"
    r"""('[^'\n]*'|"[^"\n$`]*"|[^\s\x3b&|'"$`()<>{}]*)(?=[ \t]*(?:$|[\n\x3b&|]))"""
)
PARAMETRES_CIBLES = {"-path", "-literalpath", "-filepath", "-destination", "-newname"}
PARAMETRES_VALEURS = {
    "-name",
    "-value",
    "-itemtype",
    "-encoding",
    "-filter",
    "-include",
    "-exclude",
    "-erroraction",
    "-warningaction",
    "-informationaction",
    "-confirm",
}


def deplier(commande: str) -> tuple[str, bool]:
    """Retire les accents graves de PowerShell et resout les variables (Opus, relecture du 04/10).

    Rend la commande depliee et un drapeau vrai si une variable reste inconnue : une cible
    qu'on ne peut pas lire ne peut pas etre declaree hors depot.
    """
    # \` est un accent grave litteral en bash (code Python en citation double) : garde (12/10).
    texte = re.sub(r"(?<!\\)`", "", commande)
    inconnue = False

    def valeur(m: re.Match) -> str:
        nonlocal inconnue
        nom = m.group(1) or m.group(2) or m.group(3)
        if m.group(3) and m.start() and m.string[m.start() - 1] == "\\":
            return m.group(0)  # \$PATH : dollar litteral pour bash, pas une variable
        if nom.lower() in {"_", "psitem"}:
            return m.group(0)  # objet du tube, remplace plus tard par le flux
        if nom in os.environ:
            return os.environ[nom]
        inconnue = True
        return m.group(0)

    return VARIABLE.sub(valeur, texte), inconnue


def _normaliser(chemin: str) -> str:
    chemin = ntpath.normpath(chemin).replace("\\", "/").lower()
    return re.sub(r"^/(?:mnt/)?([a-z])(?=/|$)", r"\1:", chemin)


def _resoudre(chemin: str, cwd: str) -> str:
    return _normaliser(ntpath.join(cwd, _normaliser(chemin)))


RACINE = _normaliser(os.environ.get("GARDE_RACINE") or os.getcwd())
DEPOT = ntpath.basename(RACINE)
PARENT = ntpath.dirname(RACINE).rstrip("/")


def _dans_depot(chemin: str) -> bool:
    return DEPOT in _normaliser(chemin).split("/")


def _racine_ambigue(chemin: str) -> bool:
    # Inclut WSL et les chemins malformes tels que C:/D:/Dep*.
    chemin = _normaliser(chemin)
    if RACINE.startswith(chemin.rstrip("/") + "/"):
        return True  # ancetre de la racine : rm -rf D:/ emporte aussi le depot
    for racine in re.findall(r"(?:^|/)" + re.escape(PARENT) + r"/([^/]*)", chemin):
        if not racine or re.search(r"[*?\[]|~\d", racine):
            return True
    return False


def _temporaire(chemin: str) -> bool:
    chemin = _normaliser(chemin)
    return bool(
        ntpath.isabs(chemin)
        and not VARIABLE.search(chemin)
        and not _dans_depot(chemin)
        and not _racine_ambigue(chemin)
        and re.search(r"(?:^|/)(?:tmp|temp)(?:/|$)", chemin)
    )


def _joker(nom: str, motif: str) -> bool:
    import fnmatch  # import differe : seul un chemin a joker en a besoin

    return fnmatch.fnmatchcase(nom, motif)


def _protege(chemin: str, cwd: str, cwd_inconnu: bool = False) -> bool:
    if cwd_inconnu and not ntpath.isabs(chemin):
        # Un cd peut avoir mene dans n'importe quel sous-dossier du depot.
        chemin = re.sub(r"^(?:\.\.?/)+", "", _normaliser(chemin))
        cwd = RACINE
    chemin = _resoudre(chemin, cwd)
    morceaux = chemin.split("/")
    dans_perimetre = _dans_depot(chemin) or _racine_ambigue(chemin)
    # Les deux configurations comptent hors depot, mais pas dans un dossier temporaire :
    # cp /tmp/src/* "$TEMP/x/" ne touche ni ~/.claude ni ~/.codex (12/10).
    config_hors_depot = not dans_perimetre and not _temporaire(chemin)
    for protege in FICHIERS_PROTEGES:
        if (
            protege in {".claude/settings.json", ".codex/hooks.json"}
            and config_hors_depot
        ) or dans_perimetre:
            for i in range(len(morceaux)):
                suffixe = "/".join(morceaux[i:])
                if suffixe == protege or (
                    any(c in suffixe for c in "*?[") and _joker(protege, suffixe)
                ):
                    return True
        if protege == ".git" and dans_perimetre and protege in morceaux:
            return True
    return False


def _fournisseur_non_fichier(chemin: str) -> bool:
    return bool(FOURNISSEUR_NON_FICHIER.match(chemin.strip().strip("'\"")))


def _refuser_cibles(cibles: list[str], cwd: str, cwd_inconnu: bool) -> bool:
    if cwd_inconnu:
        return True
    # Cible calculee (variable inconnue, expression entre parentheses) : elle peut viser le depot.
    if any(p.startswith("(") or "$" in p for p in cibles):
        return True
    if any(_dans_depot(_resoudre(p, cwd)) or _racine_ambigue(p) for p in cibles):
        return True
    if _dans_depot(cwd):
        return not cibles or not all(_temporaire(p) for p in cibles)
    return False


DECITER = re.compile(r"'((?:''|[^'])*)'|\"((?:\\\"|\"\"|[^\"])*)\"")
REDIRECTION_FD = re.compile(r"(?:\d+|\*)?>>?&\d+")
ALIAS_GIT_SHELL = re.compile(r"(?i)alias\.[^=]+=\s*!")


def _deciter(mot: str) -> str:
    # Chemin court : la plupart des mots n'ont aucune citation (latence).
    if "'" not in mot and '"' not in mot:
        return mot
    return DECITER.sub(
        lambda m: (
            m[1].replace("''", "'")
            if m[1] is not None
            # \$ dans une citation double bash est un dollar (powershell -Command "\$t=...").
            else m[2]
            .replace('\\"', '"')
            .replace('""', '"')
            .replace("\\$", "$")
            .replace("\\`", "`")
        ),
        mot,
    )


def _arguments(args: list[str], verbe: str) -> tuple[list[str], dict[str, list[str]]]:
    """Separe les cibles des valeurs de parametres, sans perdre les listes PowerShell."""
    args = args.copy()
    tableau = False
    for i, arg in enumerate(args):
        if arg.startswith("@("):
            arg, tableau = arg[2:], True
        if tableau and arg.endswith(")"):
            arg, tableau = arg[:-1], False
        args[i] = arg
    positions, nommes = [], {}
    valeurs_options = PARAMETRES_VALEURS.copy()
    if verbe == "truncate":
        valeurs_options.update({"-s", "--size", "-r", "--reference"})
    if verbe in {"mv", "cp"}:
        valeurs_options.update({"-t", "--target-directory"})
    i = 0
    while i < len(args):
        arg = args[i]
        morceaux = re.split(r"[=:]", arg, maxsplit=1)
        nom = morceaux[0].lower()
        if arg == "--":
            positions.extend(p for p in args[i + 1 :] if p != ",")
            break
        if nom in PARAMETRES_CIBLES | valeurs_options:
            if len(morceaux) == 2:
                valeurs = [morceaux[1]]
            else:
                i += 1
                valeurs = args[i : i + 1]
                while i + 2 < len(args) and args[i + 1] == ",":
                    valeurs.append(args[i + 2])
                    i += 2
            nommes[nom] = valeurs
        elif (
            arg != ","
            and not arg.startswith("-")
            and arg.lower() not in {"/s", "/q", "/f", "/y"}
        ):
            premiere_liste = nommes.setdefault("position-cibles", [])
            if not positions or (
                i > 0 and args[i - 1] == "," and len(premiere_liste) == len(positions)
            ):
                premiere_liste.append(arg)
            positions.append(arg)
        i += 1
    return positions, nommes


def _force(args: list[str]) -> bool:
    return any(
        a.lower() in {"-force", "-force:$true", "-force:true", "-force:1"} for a in args
    )


def _retirer_options_git(
    args: list[str], cwd: str, bruts: list[str]
) -> tuple[list[str], str]:
    """Lit les options globales avant le sous-ordre et applique les -C successifs."""
    i, racines = 0, {}
    autostash = False
    while i < len(args) and args[i].startswith("-"):
        arg = args[i]
        nom, egal, valeur = arg.partition("=")
        if nom in {
            "-C",
            "-c",
            "--git-dir",
            "--work-tree",
            "--namespace",
            "--config-env",
        }:
            if not egal:
                i += 1
                valeur = args[i] if i < len(args) else ""
            if nom == "-C":
                if (
                    not egal
                    and i < len(bruts)
                    and (bruts[i] == "~" or bruts[i].startswith(("~/", "~\\")))
                ):
                    valeur = os.path.expanduser("~") + valeur[1:]
                cwd = _resoudre(valeur, cwd)
            elif nom == "-c":
                cle, egal, booleen = valeur.lower().partition("=")
                if cle == "rebase.autostash":
                    autostash = not egal or booleen in {"true", "1", "on", "yes"}
            elif nom in {"--git-dir", "--work-tree"}:
                racines[nom] = valeur
        elif arg.startswith("-C"):
            cwd = _resoudre(arg[2:], cwd)
        i += 1
    suite = args[i:]
    if autostash and suite[:1] == ["rebase"] and "--no-autostash" not in suite:
        suite = [*suite, "--autostash"]
    # Une racine explicite dans le depot compte meme avec un cwd exterieur.
    racines = {nom: _resoudre(valeur, cwd) for nom, valeur in racines.items()}
    if {"--git-dir", "--work-tree"} <= racines.keys():
        cwd = racines["--work-tree"]
        if _dans_depot(cwd) or _racine_ambigue(cwd):
            return suite, cwd
    for racine in racines.values():
        if _dans_depot(racine) or _racine_ambigue(racine):
            cwd = racine
            break
    return suite, cwd


def _config_active_autostash(suite: list[str]) -> bool:
    # shortcut: git config --global hors dépôt échappe au contrôle, revoir si un geste en dépend.
    options = iter(suite)
    for mot in options:
        if mot.startswith(("--get", "--unset")) or mot in {
            "--list",
            "-l",
            "--edit",
            "-e",
            "--rename-section",
            "--remove-section",
        }:
            return False
        if mot in {"-f", "--file", "-t", "--type", "--value", "--comment", "--default"}:
            next(options, None)
            continue
        if mot == "set" or mot.startswith("-"):
            continue
        return mot.lower() in {"rebase.autostash", "merge.autostash"} and next(
            options, ""
        ).lower() not in {"", "false", "0", "off", "no"}
    return False


def _git_destructeur(args: list[str], racine: str, cwd_inconnu: bool) -> bool:
    if not args:
        return False
    ordre, *suite = args
    # 19/11 : Git accepte --autost et peut aussi activer la remise par sa configuration.
    if (
        ordre in {"stash", "merge", "pull"}
        or ordre == "rebase"
        and any(a.startswith("--autost") and "--autostash".startswith(a) for a in suite)
        or ordre == "config"
        and _config_active_autostash(suite)
    ):
        chemin = _normaliser(racine)
        # Les worktrees jetables sous <racine>/.ateliers/ peuvent remiser et fusionner.
        principal = (
            chemin == RACINE or chemin.startswith(RACINE + "/")
        ) and not chemin.startswith(RACINE + "/.ateliers/")
        if principal or cwd_inconnu or _racine_ambigue(racine):
            if ordre in {"pull", "rebase", "config"}:
                return True
            if ordre == "merge":
                return suite not in (["--abort"], ["--continue"])
            if not suite or suite[0] in {"push", "save"} or suite[0].startswith("-"):
                return True
    if ordre == "config":
        # Une lecture explicite ne desarme rien. Ne sauter que les options sans valeur.
        action = next(
            (
                a
                for a in suite
                if a
                not in {
                    "--local",
                    "--global",
                    "--system",
                    "--worktree",
                    "--show-origin",
                    "--show-scope",
                    "-z",
                    "--null",
                    "--includes",
                    "--no-includes",
                }
            ),
            "",
        )
        if action in {"get", "--get", "--get-all", "--get-regexp", "--get-urlmatch"}:
            return False
    options = suite[: suite.index("--")] if "--" in suite else suite
    courts = "".join(
        a[1:] for a in options if a.startswith("-") and not a.startswith("--")
    )
    force = (
        any(
            a.split("=", 1)[0]
            in {"--force", "--force-with-lease", "--force-if-includes"}
            for a in options
        )
        or "f" in courts
    )
    return bool(
        ordre in {"clean", "rm", "restore"}
        or ordre == "reset"
        and "--hard" in options
        or ordre == "checkout"
        and ("--" in suite or "." in suite or force)
        or ordre == "push"
        and (
            force
            or any(a.startswith("+") for a in suite)
            # Suppression d'une branche distante : --delete, -d, refspec a deux-points initial.
            or "--delete" in options
            or "d" in courts
            or "--mirror" in options
            or any(not a.startswith("-") and a.startswith(":") for a in options)
        )
        or ordre == "branch"
        and (bool({"d", "D"} & set(courts)) or force or "--delete" in options)
        # read-tree -u --reset recrit l'index et l'arbre de travail.
        or ordre == "read-tree"
        and "--reset" in options
        # config qui desarme un hook (core.hooksPath, ...) ou pose un alias shell (!...).
        or ordre == "config"
        and (
            any(a.split("=", 1)[0].lower() in GIT_CONFIG_DESARME for a in suite)
            or (
                any(re.match(r"(?i)^alias\.", a) for a in suite)
                and any(v.lstrip().startswith("!") for v in suite)
            )
        )
        or ordre == "update-ref"
        and "d" in courts
        or ordre == "worktree"
        and any(a in {"remove", "prune"} for a in suite)
        or ordre == "stash"
        and any(a in {"drop", "clear"} for a in suite)
        # Reecriture ou purge de l'historique (relecture Antigravity du 05/10).
        or ordre in {"filter-branch", "filter-repo"}
        or ordre == "prune"
        and not {"-n", "--dry-run"} & set(options)
        or ordre == "reflog"
        and any(a in {"expire", "delete"} for a in suite)
        or ordre == "gc"
        and any(a.startswith("--prune=") for a in options)
        or ordre == "rebase"
        and (
            force
            or bool(set("ix") & set(courts))
            or bool(
                {"--root", "--interactive", "--force-rebase", "--no-ff", "--exec"}
                & {a.split("=", 1)[0] for a in options}
            )
        )
        or ordre == "switch"
        and (force or "--discard-changes" in options)
    )


def _python_refuse(code: str, cwd: str, cwd_inconnu: bool) -> bool:
    """Reconnaissance AST des appels litteraux connus, jamais evaluation du code."""
    import ast  # import differe (latence) : seul le code Python en ligne en a besoin

    opaque = _dans_depot(cwd) or cwd_inconnu
    try:
        arbre = ast.parse(code)
    except SyntaxError:
        return opaque

    def litteral(noeud):
        return (
            noeud.value
            if isinstance(noeud, ast.Constant) and isinstance(noeud.value, str)
            else ""
        )

    def chaine(noeud):
        # Chaine ou liste de chaines litterales, recomposee en commande. None si calculee.
        if isinstance(noeud, ast.Constant) and isinstance(noeud.value, str):
            return noeud.value
        if isinstance(noeud, (ast.List, ast.Tuple)) and all(
            isinstance(e, ast.Constant) and isinstance(e.value, str) for e in noeud.elts
        ):
            return " ".join(_citer(e.value) for e in noeud.elts)
        return None

    # import shutil as sh, from os import system : chaque nom local ramene a son module.
    noms = {}
    for noeud in ast.walk(arbre):
        if isinstance(noeud, (ast.Import, ast.ImportFrom)):
            for alias in noeud.names:
                noms[alias.asname or alias.name] = (
                    f"{noeud.module}.{alias.name}"
                    if isinstance(noeud, ast.ImportFrom)
                    else alias.name
                )

    for appel in ast.walk(arbre):
        if not isinstance(appel, ast.Call):
            continue
        brute = re.sub(
            r"""^__import__\(\s*['"]([\w.]+)['"]\s*\)""", r"\1", ast.unparse(appel.func)
        )
        tete, point, reste = brute.partition(".")
        fonction = noms.get(tete, tete) + point + reste
        premier = (
            appel.args[0]
            if appel.args
            else next(
                (
                    k.value
                    for k in appel.keywords
                    if k.arg in {"args", "cmd", "command", "source"}
                ),
                None,
            )
        )
        # Lanceurs : la commande shell ou le code passe a exec est juge comme s'il etait tape.
        if EXEC_PY.fullmatch(fonction) or fonction in {"exec", "eval", "compile"}:
            if re.match(r"os\.(?:exec|spawn|posix_spawn)", fonction):
                liste = next(
                    (a for a in appel.args if isinstance(a, (ast.List, ast.Tuple))),
                    ast.List(elts=appel.args[1:]),
                )
                interne = chaine(liste)
            else:
                interne = chaine(premier) if premier is not None else None
            if interne is None:
                if opaque:
                    return True
            elif (
                _python_refuse(interne, cwd, cwd_inconnu)
                if fonction in {"exec", "eval", "compile"}
                else doit_refuser(interne, cwd, cwd_inconnu)
            ):
                return True
            continue
        if brute.startswith("getattr(") and opaque:
            return True
        cible = litteral(appel.args[0]) if appel.args else ""
        methode = appel.func.attr if isinstance(appel.func, ast.Attribute) else ""
        if methode in {
            "unlink",
            "rmdir",
            "write_text",
            "write_bytes",
            "open",
        } and isinstance(appel.func.value, ast.Call):
            constructeur = appel.func.value
            cible = litteral(constructeur.args[0]) if constructeur.args else ""
        if fonction in DEPLACE_PY and cible and not cwd_inconnu:
            # 12/10 : comme mv, un deplacement litteral qui reste dans le depot est permis,
            # sauf s'il ecrase ou emporte un fichier protege.
            arrivee = litteral(appel.args[1]) if len(appel.args) > 1 else ""
            if not arrivee:
                arrivee = next(
                    (litteral(k.value) for k in appel.keywords if k.arg == "dst"), ""
                )
            if _protege(cible, cwd) or (arrivee and _protege(arrivee, cwd)):
                return True
            depart_depot = _dans_depot(_resoudre(cible, cwd)) or _racine_ambigue(cible)
            if depart_depot and not (arrivee and _dans_depot(_resoudre(arrivee, cwd))):
                return True
            if depart_depot or not _dans_depot(cwd) or _temporaire(cible):
                continue
            # Source absolue hors depot et hors temporaire, lancee du depot : refus comme avant.
            return True
        if (
            fonction in SUPPR_PY
            or fonction in DEPLACE_PY
            or methode in {"unlink", "rmdir"}
        ) and _refuser_cibles([cible] if cible else [], cwd, cwd_inconnu):
            return True
        if fonction == "open" or methode == "open":
            index_mode = 1 if fonction == "open" else 0
            mode = (
                litteral(appel.args[index_mode])
                if len(appel.args) > index_mode
                else "r"
            )
            for motcle in appel.keywords:
                if motcle.arg == "mode":
                    mode = litteral(motcle.value)
            if any(c in mode for c in "wax+") and _protege(cible, cwd, cwd_inconnu):
                return True
        if methode in {"write_text", "write_bytes"} and _protege(
            cible, cwd, cwd_inconnu
        ):
            return True
    return False


def _citer(mot: str) -> str:
    """Recite un mot pour qu'il reste un seul mot dans une commande recomposee."""
    if mot and not re.search(r"""[\s'"\x3b&|,<>{}()]""", mot):
        return mot
    return '"' + mot.replace('"', '""') + '"'


def _vise_depot(texte: str) -> bool:
    return bool(
        re.search(
            r"(?i)" + re.escape(DEPOT) + r"|(?:\b[a-z]:|/mnt/[a-z])[\\/]+[^\\/\s'\"]*[*?~]",
            texte,
        )
    )


def _script_refuse(code: str, cwd: str, cwd_inconnu: bool) -> bool:
    """Code en ligne d'un interprete sans analyseur : refuse s'il detruit ou lance et vise le depot."""
    return bool(SCRIPT_DESTRUCTEUR.search(code)) and (
        _dans_depot(cwd) or cwd_inconnu or _vise_depot(code)
    )


def _entree_refusee(
    pipeline: list[str] | None, cwd: str, cwd_inconnu: bool, langage: str = "shell"
) -> bool:
    """Code lu sur l'entree standard : juge s'il est litteral, opaque sinon."""
    if pipeline is None:
        return False
    if pipeline is INCONNU:
        return _dans_depot(cwd) or cwd_inconnu
    code = pipeline.texte if isinstance(pipeline, Corps) else " ".join(pipeline)
    if langage == "python":
        return _python_refuse(code, cwd, cwd_inconnu)
    if langage == "script":
        return _script_refuse(code, cwd, cwd_inconnu)
    return doit_refuser(code, cwd, cwd_inconnu)


def _option_commande(verbe: str, arg: str) -> bool:
    a = arg.lower()
    if verbe == "cmd":
        return a in {"/c", "/k", "/r"}
    if verbe in {"powershell", "pwsh"}:
        return a in {"-c", "/c", "-cwa", "-commandwithargs"} or (
            len(a) >= 3 and ("-command".startswith(a) or "/command".startswith(a))
        )
    return bool(re.fullmatch(r"-[a-z]*c[a-z]*", a))


def _liste(bruts: list[str], j: int) -> tuple[int, list[str]]:
    """Valeur PowerShell en position j, avec les elements suivants separes par des virgules."""
    valeurs = []
    while j < len(bruts):
        valeurs.append(_deciter(bruts[j]).removeprefix("@(").removesuffix(")"))
        if j + 1 < len(bruts) and bruts[j + 1] == ",":
            j += 2
            continue
        return j + 1, valeurs
    return j, valeurs


def _demarrer_refuse(verbe: str, bruts: list[str], cwd: str, cwd_inconnu: bool) -> bool:
    """Start-Process : programme et arguments rejoints comme Windows les rejoint."""
    exe, liste, i = None, [], 0
    while i < len(bruts):
        nom = bruts[i].lower().split(":", 1)[0]
        if bruts[i].startswith("-") and len(nom) > 1:
            if nom == "-args" or "-argumentlist".startswith(nom):
                i, valeurs = _liste(bruts, i + 1)
                liste += valeurs
            elif nom in {"-path", "-pspath"} or "-filepath".startswith(nom):
                i, valeurs = _liste(bruts, i + 1)
                exe = (valeurs or [""])[0]
            elif len(nom) >= 3 and "-workingdirectory".startswith(nom):
                i, valeurs = _liste(bruts, i + 1)
                dossier = (valeurs or [""])[0]
                if re.search(r"[~$]", dossier):
                    cwd_inconnu = True
                else:
                    cwd = _resoudre(dossier, cwd)
            else:
                valeur = len(nom) >= 3 and any(
                    p.startswith(nom) for p in VALEURS_DEMARRER
                )
                i += 2 if valeur else 1
            continue
        if bruts[i] == ",":
            i += 1
            continue
        i, valeurs = _liste(bruts, i)
        if exe is None:
            exe, valeurs = (valeurs or [""])[0], valeurs[1:]
        liste += valeurs
    if exe is None:
        return False
    if doit_refuser(" ".join([exe, *liste]), cwd, cwd_inconnu):
        return True
    # start de cmd : le premier mot cite est un titre de fenetre.
    return verbe == "start" and doit_refuser(" ".join(liste), cwd, cwd_inconnu)


def _lanceur_refuse(
    verbe: str,
    args: list[str],
    bruts: list[str],
    cwd: str,
    cwd_inconnu: bool,
    pipeline: list[str] | None,
) -> bool | None:
    """Juge la commande qu'un lanceur execute. None : le verbe ne lance rien de connu."""
    # Nom de commande calcule ($cmd docs, & (...) docs) : illisible, opaque depuis le depot.
    calcule = verbe.startswith("$") or verbe[:1] == "(" and verbe.endswith(")")
    # "in" apres une variable est l'entete d'un foreach ($a in ...), pas un appel.
    if calcule and args and args[0].lower() not in OPERATEURS | {"in"}:
        return (_dans_depot(cwd) or cwd_inconnu) or None
    if verbe in COQUILLES:
        for i, arg in enumerate(args):
            if _option_commande(verbe, arg):
                suite = args[i + 1 :]
                if not suite or suite == ["-"]:
                    return _entree_refusee(pipeline, cwd, cwd_inconnu)
                if len(suite) == 1 or verbe not in {"cmd", "powershell", "pwsh"}:
                    return doit_refuser(suite[0], cwd, cwd_inconnu)
                return _segment_refuse(bruts[i + 2 :], cwd, cwd_inconnu)
        if OPAQUE.search(" ".join([verbe, *args])) and (
            _dans_depot(cwd) or cwd_inconnu
        ):
            return True
        positions, k = [], 0
        while k < len(args):
            if args[k].lower() in VALEURS_COQUILLES:
                k += 1
            elif not args[k].startswith(("-", "/")):
                positions.append(k)
            k += 1
        if verbe == "powershell" and positions and "-file" not in map(str.lower, args):
            # Windows PowerShell lit ses arguments libres comme une commande.
            return _segment_refuse(bruts[positions[0] + 1 :], cwd, cwd_inconnu)
        if not positions or {"-", "-s"} & set(args[: positions[0]]):
            return _entree_refusee(pipeline, cwd, cwd_inconnu)
        return False
    if re.fullmatch(r"python[\d.]*w?|py|pypy\d*", verbe):
        i = 0
        while i < len(args):
            a = args[i]
            if re.fullmatch(r"-[bBdEhiIOPqsSuvVx]*c", a):
                return i + 1 < len(args) and _python_refuse(
                    args[i + 1], cwd, cwd_inconnu
                )
            if a == "-":
                break
            if a == "-m" or not a.startswith("-"):
                return False
            i += 2 if a in {"-W", "-X"} else 1
        return _entree_refusee(pipeline, cwd, cwd_inconnu, "python")
    if verbe in INTERPRETES or verbe == "deno":
        if verbe == "deno":
            code = args[1] if args[:1] == ["eval"] and len(args) > 1 else None
        else:
            code = next(
                (
                    args[k + 1]
                    for k, a in enumerate(args[:-1])
                    if re.fullmatch(INTERPRETES[verbe], a)
                ),
                None,
            )
        if code is not None:
            return _script_refuse(code, cwd, cwd_inconnu) or None
        if not [a for a in args if a == "-" or not a.startswith("-")]:
            return _entree_refusee(pipeline, cwd, cwd_inconnu, "script") or None
        return None
    if verbe in PREFIXES:
        i = 0
        while i < len(args):
            a = args[i]
            nom, egal, valeur = a.partition("=")
            if a == "--":
                i += 1
                break
            if verbe == "env" and re.fullmatch(r"[A-Za-z_]\w*=.*", a, re.DOTALL):
                i += 1
                continue
            if verbe == "env" and a in {"-S", "--split-string"}:
                return doit_refuser(" ".join(args[i + 1 :]), cwd, cwd_inconnu)
            if verbe == "command" and a in {"-v", "-V"}:
                return False
            if verbe == "wsl" and a in {"-e", "--exec"}:
                i += 1
                break
            if not a.startswith("-") or a == "-":
                break
            if nom in PREFIXES[verbe]:
                if not egal:
                    i += 1
                    valeur = args[i] if i < len(args) else ""
                if nom in {"--chdir", "--cd"} or (verbe, nom) in {
                    ("env", "-C"),
                    ("sudo", "-D"),
                }:
                    if re.search(r"[~$]", valeur):
                        cwd_inconnu = True
                    else:
                        cwd = _resoudre(valeur, cwd)
            i += 1
        if verbe == "timeout":
            i += 1  # la duree
        interne = bruts[i + 1 :]
        if verbe == "xargs":
            # Les cibles arrivent par le tube : elles s'ajoutent a la commande lancee.
            interne = (interne or ["echo"]) + [_citer(p) for p in pipeline or []]
            pipeline = None
        return bool(interne) and _segment_refuse(interne, cwd, cwd_inconnu, pipeline)
    if verbe in DEMARRER:
        return _demarrer_refuse(verbe, bruts[1:], cwd, cwd_inconnu)
    if verbe == "eval":
        # 12/10 : eval "rm -rf docs" passait, eval n'etant connu d'aucune liste.
        return bool(args) and doit_refuser(" ".join(args), cwd, cwd_inconnu)
    if verbe == "git":
        # git est traite une seule fois dans _segment_refuse, pour ne pas relire deux
        # fois des options eventuellement repetees (gain de latence, passe 4).
        return None
    if verbe == "find":
        racines = args[
            : next(
                (k for k, a in enumerate(args) if a.startswith(("-", "(", "!"))),
                len(args),
            )
        ] or ["."]
        for i, a in enumerate(args):
            if a in {"-exec", "-execdir", "-ok", "-okdir"}:
                fin = next(
                    (
                        k
                        for k in range(i + 1, len(args))
                        if args[k] in {"{}", "\\", "+"}
                    ),
                    len(args),
                )
                interne = bruts[i + 2 : fin + 1] + [_citer(r) for r in racines]
                if _segment_refuse(interne, cwd, cwd_inconnu):
                    return True
        return None
    return None


def _ecrit_dans_depot(chemin: str, cwd: str, cwd_inconnu: bool) -> bool:
    """Un chemin de sortie (telechargeur, extracteur) qui atterrit dans le depot."""
    if cwd_inconnu:
        return True
    return _dans_depot(_resoudre(chemin, cwd)) or _racine_ambigue(chemin)


def _extracteur_refuse(
    verbe: str, args: list[str], cwd: str, cwd_inconnu: bool
) -> bool:
    """Extraction d'archive qui ecrit dans le depot (tar -C, 7z -o, Expand-Archive)."""
    if verbe == "tar":
        modes = args[0] if args and re.fullmatch(r"[a-zA-Z]+", args[0]) else ""
        modes += "".join(a[1:] for a in args if re.fullmatch(r"-[a-zA-Z]+", a))
        if "x" not in modes and not {"--extract", "--get"} & set(args):
            return False
        dossier = None
        for i, a in enumerate(args):
            if a in {"-C", "--directory"} and i + 1 < len(args):
                dossier = args[i + 1]
            elif a.startswith("--directory="):
                dossier = a.split("=", 1)[1]
            elif a.startswith("-C") and len(a) > 2:
                dossier = a[2:]
        return _ecrit_dans_depot(dossier or cwd, cwd, cwd_inconnu)
    if re.fullmatch(r"7za?|7zr", verbe):
        if not (args[:1] and args[0].lower() in {"x", "e"}):
            return False
        for a in args:
            if a.lower().startswith("-o") and len(a) > 2:
                return _ecrit_dans_depot(a[2:], cwd, cwd_inconnu)
        return _ecrit_dans_depot(cwd, cwd, cwd_inconnu)
    if verbe == "expand-archive":
        dest, i = None, 0
        while i < len(args):
            a, base = args[i], args[i].lower().split("=", 1)[0]
            if len(base) >= 2 and "-destinationpath".startswith(base):
                dest = (
                    a.split("=", 1)[1]
                    if "=" in a
                    else (args[i + 1] if i + 1 < len(args) else "")
                )
                i += 1 if "=" in a else 2
                continue
            i += 1
        return _ecrit_dans_depot(dest or cwd, cwd, cwd_inconnu)
    return False


def _telechargeur_refuse(
    verbe: str, args: list[str], cwd: str, cwd_inconnu: bool
) -> bool:
    """Telechargement dont le fichier de sortie atterrit dans le depot."""

    def sortie(courts: set[str], longs: set[str]) -> bool:
        for i, a in enumerate(args):
            base = a.split("=", 1)[0]
            if base in courts or base.lower() in longs:
                val = (
                    a.split("=", 1)[1]
                    if "=" in a
                    else (args[i + 1] if i + 1 < len(args) else "")
                )
                if val and _ecrit_dans_depot(val, cwd, cwd_inconnu):
                    return True
            for court in courts:
                if (
                    a.startswith(court)
                    and len(a) > len(court)
                    and _ecrit_dans_depot(a[len(court) :], cwd, cwd_inconnu)
                ):
                    return True
        return False

    if verbe == "curl":
        return sortie({"-o"}, {"--output"})
    if verbe == "wget":
        return sortie({"-O"}, {"--output-document"})
    if verbe in {"invoke-webrequest", "iwr", "invoke-restmethod", "irm"}:
        return sortie(set(), {"-outfile"})
    if verbe == "certutil" and any(a.lower().startswith("-decode") for a in args):
        positions = [a for a in args if not a.startswith("-")]
        return any(_ecrit_dans_depot(p, cwd, cwd_inconnu) for p in positions[1:])
    return False


def _flux(segment: list[str]) -> list[str]:
    """Ce qu'un segment envoie dans le tube : chaines litterales lisibles, sinon INCONNU."""
    mots = [_deciter(m) for m in segment]
    verbe = mots[0].lower()
    if verbe in {"get-item", "get-childitem", "gi", "gci", "ls", "dir"}:
        positions, nommes = _arguments(mots[1:], verbe)
        return nommes.get("-literalpath", nommes.get("-path", positions or ["*"]))
    if verbe in {"echo", "write-output", "write", "printf"}:
        return mots[1:]
    if segment[0][:1] in {"'", '"'}:
        return mots
    return INCONNU


def _masquer(texte: str, garder_doubles: bool = False) -> str:
    """Blanchit les citations a longueur egale, sauf les doubles si demande."""
    return CITATION.sub(
        lambda m: m[0] if garder_doubles and m[0][0] == '"' else " " * len(m[0]), texte
    )


def _sous_commandes(texte: str, mode: str = "tout"):
    """Contenus executes : $( ) partout sauf en citation simple, ( ) hors citations.

    mode « dollar » : seulement les $( ). Mode « parentheses » : seulement les ( ) qui ne
    sont pas des $( ), celles-ci etant jugees a leur place dans la ligne (12/10).
    """
    passes = []
    if mode != "parentheses":
        passes.append((_masquer(texte, True), "$("))
    if mode != "dollar":
        passes.append((_masquer(texte), "("))
    for masque, ouvrant in passes:
        i = masque.find(ouvrant)
        while i >= 0:
            debut = j = i + len(ouvrant)
            profondeur = 1
            while j < len(masque) and profondeur:
                profondeur += {"(": 1, ")": -1}.get(masque[j], 0)
                j += 1
            if profondeur:
                break
            if not (mode == "parentheses" and i and masque[i - 1] == "$"):
                yield texte[debut : j - 1]
            i = masque.find(ouvrant, j)


def _segment_refuse(
    bruts: list[str], cwd: str, cwd_inconnu: bool, pipeline: list[str] | None = None
) -> bool:
    # Retirer uniquement les redirections, jamais les arguments qui les suivent.
    sans_redirection = []
    i = 0
    while i < len(bruts):
        brut = bruts[i]
        if brut in {">", ">>"}:
            if i + 1 < len(bruts) and _protege(
                _deciter(bruts[i + 1]), cwd, cwd_inconnu
            ):
                return True
            if sans_redirection and (
                sans_redirection[-1].isdigit() or sans_redirection[-1] == "*"
            ):
                sans_redirection.pop()
            i += 2
            continue
        if ">" not in brut or not REDIRECTION_FD.fullmatch(brut):
            sans_redirection.append(brut)
        i += 1
    bruts = sans_redirection
    # Affectations en tete : FOO=1 rm ..., $x = Remove-Item ... executent la suite.
    # Mots-cles (do rm ..., then rm ...) et affectations collees ($t=Get-X) aussi (12/10).
    while bruts:
        tete = _deciter(bruts[0])
        if len(bruts) > 1 and (
            tete.lower() in MOTS_CLES
            or re.fullmatch(r"[A-Za-z_]\w*=.*", tete, re.DOTALL)
        ):
            bruts = bruts[1:]
            continue
        affectation = AFFECTATION_PS.match(bruts[0])
        if not affectation:
            break
        reste = affectation[1]
        if reste[:1] in {"'", '"'}:
            return False  # une chaine affectee n'est pas executee
        bruts = ([reste] if reste else []) + bruts[1:]
    if not bruts:
        return False
    if len(bruts) > 2 and bruts[0].startswith("$") and bruts[1] in {"=", "+="}:
        bruts = bruts[2:]
        if bruts[0][:1] in {"'", '"'}:
            return False  # une chaine affectee n'est pas executee
    mots = [_deciter(m) for m in bruts]
    if not mots:
        return False
    verbe = ntpath.basename(mots[0]).lower().removesuffix(".exe")
    args = mots[1:]
    lance = _lanceur_refuse(verbe, args, bruts, cwd, cwd_inconnu, pipeline)
    if lance is not None:
        return lance
    if verbe in {"iex", "invoke-expression"}:
        return _dans_depot(cwd) or cwd_inconnu or any(_dans_depot(a) for a in args)
    if verbe == "git":
        suite, racine = _retirer_options_git(args, cwd, bruts[1:])
        if not (cwd_inconnu or _dans_depot(racine) or _racine_ambigue(racine)):
            return False
        # Alias a point d'exclamation : git lance une commande shell illisible ici.
        if "alias." in " ".join(args).lower() and any(
            ALIAS_GIT_SHELL.match(a) for a in args
        ):
            return True
        interne: list[str] = []
        if suite[:1] == ["submodule"] and "foreach" in suite:
            interne = [
                a
                for a in suite[suite.index("foreach") + 1 :]
                if a not in {"--recursive", "-q", "--quiet"}
            ]
        if suite[:2] == ["bisect", "run"]:
            interne = suite[2:]
        if interne:
            commande = (
                interne[0] if len(interne) == 1 else " ".join(map(_citer, interne))
            )
            return doit_refuser(commande, racine, cwd_inconnu)
        return _git_destructeur(suite, racine, cwd_inconnu)
    jointes = " ".join(mots)
    dotnet = re.match(
        r"(?i)^\[(?:system\.)?io\.(?:file|directory)\]::"
        r"(delete|deletesubdirectory|writealltext|writeallbytes|writealllines|"
        r"appendalltext|appendalllines|create|createtext|openwrite|opentext)"
        r"\s*\(\s*(.*?)\s*(?:,|\)|$)",
        jointes,
    )
    if dotnet:
        methode, cible = dotnet[1].lower(), dotnet[2]
        if methode in {"delete", "deletesubdirectory"}:
            return _refuser_cibles([cible], cwd, cwd_inconnu)
        # WriteAll*, AppendAll*, Create, OpenWrite : ecriture, refusee sur un protege.
        return _protege(cible, cwd, cwd_inconnu)
    dl = TELECHARGE_NET.search(jointes)
    if dl:
        return _ecrit_dans_depot(dl[1], cwd, cwd_inconnu)
    if verbe in EXTRACTEURS:
        return _extracteur_refuse(verbe, args, cwd, cwd_inconnu)
    if verbe in TELECHARGEURS:
        return _telechargeur_refuse(verbe, args, cwd, cwd_inconnu)
    positions, nommes = _arguments(args, verbe)
    if verbe in {"remove-itemproperty", "rp", "clear-itemproperty", "clp"}:
        viseurs = nommes.get("-literalpath", nommes.get("-path", positions))
        return any(_protege(c, cwd, cwd_inconnu) for c in viseurs)
    cibles = nommes.get("-literalpath", nommes.get("-path", positions))
    if pipeline is not None:
        # $_ et $PSItem designent ce qui arrive par le tube.
        cibles = [
            p
            for c in cibles
            for p in (pipeline if re.match(r"(?i)\$(?:_|psitem)\b", c) else [c])
        ]
    if verbe in SUPPRESSIONS or verbe == "truncate":
        liste = cibles or list(pipeline or [])
        reels = [c for c in liste if not _fournisseur_non_fichier(c)]
        if liste and not reels:
            # Seuls des fournisseurs non-fichier (Env:, Variable:, Function:, Alias:).
            return False
        return _refuser_cibles(reels, cwd, cwd_inconnu)
    if verbe == "find" and "-delete" in args:
        racines = args[
            : next(
                (i for i, a in enumerate(args) if a.startswith(("-", "("))), len(args)
            )
        ]
        return _refuser_cibles(racines or ["."], cwd, cwd_inconnu)
    if verbe == "robocopy" and any(a.lower() in {"/mir", "/purge"} for a in args):
        return _refuser_cibles(args[1:2], cwd, cwd_inconnu)
    # Ecrasement des fichiers proteges par tee, dd ou une edition en place.
    en_place = any(re.fullmatch(r"-[a-zA-Z]*i.*|--in-place.*", a) for a in args)
    if verbe == "tee" or verbe in {"sed", "perl", "ruby"} and en_place:
        return any(_protege(c, cwd, cwd_inconnu) for c in positions)
    if verbe == "dd":
        return any(
            _protege(a[3:], cwd, cwd_inconnu) for a in args if a.startswith("of=")
        )
    if verbe in DEPLACEMENTS | COPIES | RENOMME:
        sources = nommes.get("-literalpath", nommes.get("-path", positions[:-1]))
        destinations = nommes.get(
            "-destination",
            nommes.get(
                "-newname",
                nommes.get("-t", nommes.get("--target-directory", positions[-1:])),
            ),
        )
        if any(
            n in nommes
            for n in ("-destination", "-newname", "-t", "--target-directory")
        ):
            sources = nommes.get("-literalpath", nommes.get("-path", positions))
        sources = sources or pipeline or []
        # Copie et deplacement ecrasent sans option (Copy-Item, cp, mv) : jamais sur un protege.
        for destination in destinations if verbe not in RENOMME else []:
            if _protege(destination, cwd, cwd_inconnu):
                return True
            dossier = destination.endswith(("/", "\\")) or os.path.isdir(
                _resoudre(destination, cwd)
            )
            if dossier and any(
                _protege(ntpath.join(destination, ntpath.basename(s)), cwd, cwd_inconnu)
                for s in sources
            ):
                return True
        if verbe in DEPLACEMENTS:
            if cwd_inconnu:
                return True
            if any(
                _dans_depot(_resoudre(s, cwd)) or _racine_ambigue(s) for s in sources
            ):
                return not destinations or any(
                    not _dans_depot(_resoudre(d, cwd)) for d in destinations
                )
            return False
        if verbe in RENOMME:
            if any(_protege(s, cwd, cwd_inconnu) for s in sources):
                return True
            return any(
                _protege(d, ntpath.dirname(_resoudre(s, cwd)), cwd_inconnu)
                for s in sources
                for d in destinations
            )
        return False
    if verbe in ECRITURES:
        if verbe == "new-item" and not _force(args):
            return False
        cibles = nommes.get(
            "-filepath",
            nommes.get(
                "-literalpath", nommes.get("-path", nommes.get("position-cibles", []))
            ),
        )
        if verbe == "new-item" and "-name" in nommes:
            cibles = [
                ntpath.join(c, nom) for c in cibles or ["."] for nom in nommes["-name"]
            ]
        return any(_protege(c, cwd, cwd_inconnu) for c in cibles)
    return False


def _definit_alias(segment: list[str]) -> dict[str, str]:
    """Alias cree dans la commande (Set-Alias, New-Alias, alias bash) : nom -> cible."""
    if not segment:
        return {}
    verbe = ntpath.basename(_deciter(segment[0])).lower().removesuffix(".exe")
    if verbe not in ALIAS_DEF and verbe != "alias":
        return {}  # chemin court : ne decite pas toute la ligne (latence)
    mots = [_deciter(m) for m in segment]
    if verbe in ALIAS_DEF:
        positions, nommes = _arguments(mots[1:], verbe)
        nom = (nommes.get("-name") or positions[:1] or [""])[0]
        cible = (nommes.get("-value") or positions[1:2] or [""])[0]
        return {nom.lower(): cible} if nom and cible else {}
    if verbe == "alias":
        aliases = {}
        for a in mots[1:]:
            nom, egal, val = a.partition("=")
            if egal and val:
                aliases[nom.lower()] = val
        return aliases
    return {}


class Corps(list):
    """Entree standard ecrite dans la commande (here-document, here-string).

    Liste de mots pour xargs ou une suppression, texte brut avec ses sauts de ligne pour un
    interprete (python - <<'EOF'). Le corps d'un cat > fichier <<'EOF' n'est jamais execute.
    """

    def __init__(self, texte: str):
        super().__init__(texte.split())
        self.texte = texte


def _extraire_entrees(texte: str) -> tuple[str, list[tuple[str, bool]]]:
    """Retire les corps des here-documents et here-strings, remplaces par une marque.

    12/10 : le corps etait decoupe comme des commandes shell. Une ligne Python « (c.get(x) or '') »,
    un tableau Markdown « (a) VM ... » ou un mot « sh » en debut de ligne faisaient refuser un simple
    cat > fichier <<'EOF'. Rend le texte et la liste (corps, cite) : cite vaut faux si le shell
    developpe encore les $( ) du corps (delimiteur sans citation, here-string en citation double).
    """
    if "<<" not in texte:
        return texte, []
    sortie, corps, attente = [], [], []
    i = debut = 0
    n, citation = len(texte), None
    while i < n:
        c = texte[i]
        if citation:
            if c == "\\" and citation == '"':
                i += 2
                continue
            if c == citation:
                citation = None
            i += 1
            continue
        if c in "'\"":
            citation = c
        elif c == "\\":
            i += 2
            continue
        elif c == "#" and (i == 0 or texte[i - 1] in " \t\n\x3b&|("):
            fin = texte.find("\n", i)
            i = n if fin < 0 else fin
            continue
        elif texte.startswith("<<<", i):
            m = HERESTRING.match(texte, i)
            if m:
                sortie += [texte[debut:i], f" {MARQUE_ENTREE}{len(corps)} "]
                corps.append((_deciter(m[1]), not m[1].startswith('"')))
                i = debut = m.end()
                continue
            i += 3
            continue
        elif texte.startswith("<<", i):
            m = HEREDOC.match(texte, i)
            if m:
                delimiteur = next(g for g in (m[2], m[3], m[4]) if g is not None)
                cite = m[4] is None or "\\" in m[0]
                sortie += [
                    texte[debut:i],
                    f" {MARQUE_ENTREE}{len(corps) + len(attente)} ",
                ]
                attente.append((delimiteur, m[1] == "-", cite))
                i = debut = m.end()
                continue
        elif c == "\n" and attente:
            sortie.append(texte[debut : i + 1])
            j = i + 1
            for delimiteur, tabulations, cite in attente:
                lignes = []
                while j < n:
                    fin = texte.find("\n", j)
                    fin = n if fin < 0 else fin
                    ligne = texte[j:fin]
                    j = fin + 1
                    lue = ligne.lstrip("\t") if tabulations else ligne
                    if lue.rstrip("\r") == delimiteur:
                        break
                    lignes.append(ligne)
                corps.append(("\n".join(lignes), cite))
            attente = []
            i = debut = min(j, n)
            continue
        i += 1
    sortie.append(texte[debut:])
    corps += [("", cite) for _, _, cite in attente]
    return "".join(sortie), corps


def _variables_locales(texte: str) -> str:
    """Remplace $NOM par sa valeur quand NOM recoit une seule affectation litterale sur la ligne.

    12/10 : S="C:/.../scratchpad" && curl -o "$S/x.json" etait refuse, faute de savoir que $S
    sort du depot. Prudence : une variable affectee deux fois, lue par for, read ou foreach, ou
    affectee sous condition (||, then, do) reste inconnue. Seules les occurrences qui suivent
    l'affectation sont remplacees.
    """
    if "$" not in texte or "=" not in texte:
        return texte
    # Compte sur le texte sans citations : un S=1 dans un python -c "..." n'affecte pas le shell.
    masque = _masquer(texte)
    remplacements: dict[str, tuple[str, int, bool]] = {}
    for m in list(AFFECTATION_LOCALE.finditer(texte)):
        nom, ps = (m[1], False) if m[1] else (m[2], True)
        position = m.start(1) if m[1] else m.start(2)
        if masque[position] != texte[position]:
            continue  # affectation dans une citation
        drapeau = "(?i)" if ps else ""
        nom_re = re.escape(nom)
        affectations = re.findall(
            drapeau + rf"(?<![\w.\-])(?:\$)?{nom_re}(?:\+|:)?[ \t]*=(?!=)", masque
        )
        if len(affectations) != 1 or re.search(
            drapeau
            + rf"\b(?:for|select|foreach|read|mapfile|readarray|getopts)\b[^\n\x3b&|]*?\$?\b{nom_re}\b"
            + rf"|printf\s+-v\s+{nom_re}\b|\$\{{{nom_re}:?[=?+\-]|\${nom_re}(?:\+\+|--)",
            masque,
        ):
            continue
        remplacements[nom.lower() if ps else nom] = (_deciter(m[3]), m.end(), ps)
    if not remplacements:
        return texte

    def remplacer(r: re.Match) -> str:
        nom = r[1] or r[2]
        info = remplacements.get(nom)
        if info is None:
            info = remplacements.get(nom.lower())
            if info is None or not info[2]:
                return r[0]
        return info[0] if r.start() >= info[1] else r[0]

    return re.sub(r"\$(?:\{(\w+)\}|(\w+))", remplacer, texte)


SOUS = re.compile(r"\$__sous__(\d+)")


def _neutraliser_dollar(texte: str) -> tuple[str, list[str]]:
    """Remplace chaque $( ) par une variable inconnue numerotee, et rend leurs contenus.

    Le contenu est juge au moment ou son segment s'execute, dans le dossier courant de la
    ligne. Sans cela n=$(find "$d" -name x | wc -l) laissait un segment « "$d" -name x » pris
    pour un nom de commande calcule, et un $(curl -o x) apres un cd partait d'un dossier inconnu.
    """
    if "$(" not in texte:
        return texte, []
    masque = _masquer(texte, True)
    morceaux, contenus, debut, i = [], [], 0, masque.find("$(")
    while i >= 0:
        j, profondeur = i + 2, 1
        while j < len(masque) and profondeur:
            profondeur += {"(": 1, ")": -1}.get(masque[j], 0)
            j += 1
        if profondeur:
            break
        morceaux += [texte[debut:i], f"$__sous__{len(contenus)}"]
        contenus.append(texte[i + 2 : j - 1])
        debut = j
        i = masque.find("$(", j)
    return "".join(morceaux) + texte[debut:], contenus


def _cible_cd(segment: list[str], cwd: str) -> str | None:
    """Dossier vise par un cd litteral. None s'il ne se lit pas (variable, joker, cd -, popd)."""
    mots = [_deciter(m) for m in segment]
    if mots[0].lower() in {"popd", "pop-location"}:
        return None
    args = [m for m in mots[1:] if m.lower() not in {"/d", "-path", "-literalpath"}]
    if len(args) != 1 or args[0].startswith("-"):
        return None
    cible = args[0]
    if re.search(r"[$*?\[\]`(){}%]", cible):
        return None
    if cible.startswith("~"):
        if cible[1:2] not in {"", "/", "\\"}:
            return None
        cible = os.path.expanduser("~") + cible[1:]
    resolu = _resoudre(cible, cwd)
    if _racine_ambigue(cible) or _racine_ambigue(resolu):
        return None
    return resolu


def _changer_dossier(
    segment: list[str], contextes: list[tuple[str, bool]]
) -> tuple[list[tuple[str, bool]], bool]:
    """Contextes (dossier, inconnu) apres un cd, et vrai si le cd reussit a coup sur.

    12/10 : tout cd rendait le dossier inconnu, et un curl -o /tmp/x lance apres
    cd <racine> etait refuse. Un cd litteral fixe le dossier. Il ne reussit a coup sur
    que si le dossier existe deja : sinon l'appelant garde aussi l'ancien dossier.
    """
    nouveaux, certain = [], True
    for dossier, inconnu in contextes:
        cible = _cible_cd(segment, dossier)
        brut = _deciter(segment[-1]) if len(segment) > 1 else ""
        if cible is None or (inconnu and not ntpath.isabs(_normaliser(brut))):
            nouveaux.append((dossier, True))
            continue
        nouveaux.append((cible, False))
        certain = certain and os.path.isdir(cible)
    return nouveaux, certain


def _unir(*listes: list[tuple[str, bool]]) -> list[tuple[str, bool]]:
    vus: list[tuple[str, bool]] = []
    for liste in listes:
        vus += [c for c in liste if c not in vus]
    return vus


def _corps_refuse(contenu: str, cwd: str, cwd_inconnu: bool) -> bool:
    """$( ) d'un corps que le shell developpe : jugees comme des sous-commandes."""
    return "$(" in contenu and any(
        doit_refuser(s, cwd, cwd_inconnu) for s in _sous_commandes(contenu, "dollar")
    )


def doit_refuser(commande: str, cwd: str = "", cwd_inconnu: bool = False) -> bool:
    return bool(regle_refus(commande, cwd, cwd_inconnu))


def regle_refus(commande: str, cwd: str = "", cwd_inconnu: bool = False) -> str:
    """Premiere branche de refus de cet appel, chaine vide si la commande est permise."""
    # Corps des here-documents retires d'abord : ce sont des donnees, ou l'entree d'un interprete.
    texte, corps = _extraire_entrees(commande)
    texte, _ = deplier(texte)
    texte = ICI.sub(lambda m: m[1] + m[2].replace(m[1], m[1] * 2) + m[1], texte)
    texte = _variables_locales(texte)
    # Masque calcule une seule fois : sur une entree longue (options git repetees),
    # chaque passage de _masquer coutait, et il tournait quatre fois par appel.
    masque = _masquer(texte)
    # Sous-commandes ( ) : jugees seules, dossier inconnu si un cd figure sur la ligne.
    # Les $( ) sont jugees plus bas, a leur place, dans le dossier courant de la ligne.
    inconnu = cwd_inconnu or bool(CHANGE_DOSSIER_RE.search(masque))
    if any(not cite and _corps_refuse(c, cwd, inconnu) for c, cite in corps):
        return "corps"
    if "(" in texte and any(
        doit_refuser(s, cwd, inconnu) for s in _sous_commandes(texte, "parentheses")
    ):
        return "parentheses"
    if DYNAMIQUE.search(masque) and (_dans_depot(cwd) or inconnu or _vise_depot(texte)):
        return "dynamique"
    texte, sous = _neutraliser_dollar(texte)
    segment, pipeline, pile = [], None, []
    alias: dict[str, str] = {}
    # Dossiers possibles du segment courant. Un cd vers un dossier absent peut echouer :
    # apres lui, la suite de la chaine && part du dossier vise, le reste des deux.
    contextes = [(cwd, cwd_inconnu)]
    attente = None  # (contextes si le cd echoue, cd sur, segment qui suit le cd)
    separateur, entree = "\n", None
    for mot in [*MOTS.findall(texte), "\n"]:
        if mot not in SEP:
            if corps and mot.startswith(MARQUE_ENTREE):
                entree = Corps(corps[int(mot[1:])][0])
                continue
            if not segment and attente:
                echecs, certain, juste_apres = attente
                if separateur == "&&":
                    attente = (echecs, certain, False)
                else:
                    if not certain or (juste_apres and separateur in {"|", "||"}):
                        contextes = _unir(contextes, echecs)
                    attente = None
            segment.append(mot)
            continue
        verbe = _deciter(segment[0]).lower() if segment else ""
        if sous and segment:
            for n in SOUS.findall(" ".join(segment)):
                if any(doit_refuser(sous[int(n)], d, i) for d, i in contextes):
                    return "sous_commande"
        if verbe in CHANGE_DOSSIER:
            nouveaux, certain = _changer_dossier(segment, contextes)
            if attente:
                # cd a && cd b : si a echoue, on reste au depart. Les deux echecs comptent.
                attente = (_unir(contextes, attente[0]), certain and attente[1], True)
            else:
                attente = (contextes, certain, True)
            contextes = nouveaux
        elif segment:
            flux = entree if entree is not None else pipeline
            alias.update(_definit_alias(segment))
            if verbe in alias:
                # Alias defini plus tot sur la ligne : juger la commande qu'il porte.
                reste = " ".join(segment[1:])
                porte = alias[verbe] + (" " + reste if reste else "")
                if any(doit_refuser(porte, d, i) for d, i in contextes):
                    return "alias"
            elif any(_segment_refuse(segment, d, i, flux) for d, i in contextes):
                return "segment"
        separateur = separateur + mot if not segment and mot in "&|" else mot
        entree = None
        if mot == "{":
            # Le bloc d'un ForEach-Object recoit le flux, les autres blocs partent de rien.
            pile.append(pipeline)
            pipeline = pipeline if verbe in BOUCLES else None
        elif mot == "}":
            pipeline = pile.pop() if pile else None
        elif mot == "|":
            pipeline = _flux(segment) if segment else pipeline
        else:
            pipeline = None
        segment = []
    return ""


ACCENTS_GRAVES = re.compile(r"(?<!\\)`((?:\\`|[^`])*)(?<!\\)`")


def accents_graves_refuses(commande: str, cwd: str) -> bool:
    """Outil Bash seulement : `commande` est une substitution, executee comme $( ).

    12/10 : echo `rm -rf docs` passait, l'accent grave etant retire comme l'echappement de
    PowerShell. Sous PowerShell il reste un echappement : ce controle ne s'y applique pas.
    """
    if "`" not in commande:
        return False
    texte, _ = _extraire_entrees(commande)
    masque = _masquer(texte, True)
    inconnu = bool(CHANGE_DOSSIER_RE.search(_masquer(texte)))
    return any(
        doit_refuser(texte[m.start(1) : m.end(1)], cwd, inconnu)
        for m in ACCENTS_GRAVES.finditer(masque)
    )


def outil(entree: str) -> str:
    try:
        return str(json.loads(entree or "{}").get("tool_name") or "")
    except (ValueError, AttributeError):
        return ""


def lire(entree: str) -> tuple[str, str]:
    donnees = json.loads(entree or "{}")
    outil = donnees.get("tool_input") or {}
    # 15/10 : Antigravity (agy) passe {"toolCall": {"name": "run_command", "args": {"CommandLine", "Cwd"}}}.
    args_agy = (donnees.get("toolCall") or {}).get("args") or {}
    if args_agy and not outil:
        outil = {
            "command": args_agy.get("CommandLine") or "",
            "cwd": args_agy.get("Cwd") or "",
        }
    commande = outil.get("command") or outil.get("cmd") or ""
    if isinstance(commande, list):
        commande = " ".join(map(str, commande))
    # Repli : le hook herite du dossier de la session (Codex ne transmet pas toujours cwd).
    cwd = outil.get("workdir") or outil.get("cwd") or donnees.get("cwd") or os.getcwd()
    return str(commande), str(cwd)


def refuser(mode: str, raison: str = MESSAGE) -> int:
    if mode == "hermes":
        # 16/10 : Hermes 0.18 (agent/shell_hooks.py) lit stdin {"tool_name", "tool_input", "cwd"} et
        # bloque un pre_tool_call sur {"decision": "block", "reason"} en stdout.
        print(json.dumps({"decision": "block", "reason": raison}, ensure_ascii=False))
        return 0
    if mode == "antigravity":
        # Contrat PreToolUse d'agy (docs agy-customizations/hooks.md) : decision deny sur stdout, code 0.
        print(json.dumps({"decision": "deny", "reason": raison}, ensure_ascii=False))
        return 0
    if mode == "codex":
        # 05/10 : Codex 0.160 ne bloque pas sur {"continue": false} (doc des hooks : « parsed but not
        # supported yet », le hook passe en echec et la commande part). Essai reel : rmdir sous le depot
        # execute malgre le refus. Forme de refus documentee : hookSpecificOutput.permissionDecision deny,
        # en code 0 : le meme JSON en code 2 passe aussi en echec (essai du 05/10, « PreToolUse Failed »).
        # Preuve : codex exec --dangerously-bypass-hook-trust sur un rmdir inexistant rend « Blocked ».
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": raison,
                    }
                },
                ensure_ascii=False,
            )
        )
        return 0
    print(raison, file=sys.stderr)
    return 2


def categories_trace(mode: str, regle: str) -> tuple[str, str]:
    moteurs = {"claude", "codex", "antigravity", "hermes"}
    regles = {
        "alias",
        "corps",
        "dynamique",
        "parentheses",
        "segment",
        "sous_commande",
        "accents_graves",
        "panne",
    }
    return (
        mode if mode in moteurs else "inconnu",
        regle if regle in regles else "inconnu",
    )


def tracer_refus(mode: str, regle: str) -> None:
    # La mesure ne doit jamais modifier le verdict ni le protocole du hook.
    try:
        from datetime import datetime, timezone

        mode, regle = categories_trace(mode, regle)
        trace = os.environ.get("GARDE_TRACE") or TRACE
        os.makedirs(os.path.dirname(os.path.abspath(trace)), exist_ok=True)
        with open(trace, "a", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {
                        "le": datetime.now(timezone.utc).isoformat(),
                        "mode": mode,
                        "regle": regle,
                    },
                    ensure_ascii=True,
                )
                + "\n"
            )
    except Exception:  # noqa: BLE001, S110  la trace ne change pas le refus
        pass


def bilan(jours: int) -> int:
    from collections import Counter
    from datetime import datetime, timedelta, timezone

    maintenant = datetime.now(timezone.utc)
    debut = maintenant - timedelta(days=jours)
    comptes = Counter()
    sans_date = invalides = 0
    try:
        with open(os.environ.get("GARDE_TRACE") or TRACE, encoding="utf-8") as f:
            for ligne in f:
                try:
                    refus = json.loads(ligne)
                    if not isinstance(refus, dict):
                        raise TypeError("objet attendu")
                    if "le" not in refus:
                        sans_date += 1
                        continue
                    date = datetime.fromisoformat(refus["le"])
                    mode, regle = refus["mode"], refus["regle"]
                    if date.tzinfo is None or not all(
                        isinstance(v, str) and v for v in (mode, regle)
                    ):
                        raise ValueError("date ou categorie invalide")
                    if debut <= date <= maintenant:
                        mode, regle = categories_trace(mode, regle)
                        comptes[regle, mode] += 1
                except (ValueError, TypeError, KeyError):
                    invalides += 1
    except (OSError, UnicodeError) as exc:
        print(f"Trace illisible ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "jours": jours,
                "total": sum(comptes.values()),
                "refus": [
                    {"regle": regle, "mode": mode, "compte": compte}
                    for (regle, mode), compte in sorted(comptes.items())
                ],
                "sans_date": sans_date,
                "invalides": invalides,
            },
            ensure_ascii=True,
            indent=2,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args and args[0] == "--bilan":
        try:
            if len(args) != 2 or int(args[1]) <= 0:
                raise ValueError("nombre de jours positif attendu")
            return bilan(int(args[1]))
        except (ValueError, OverflowError):
            print(
                "Usage : garde_suppression.py --bilan <jours positifs>", file=sys.stderr
            )
            return 2
    mode = args[0] if args else "claude"
    try:
        if not DEPOT or not (RACINE.startswith("/") or ntpath.isabs(RACINE)):
            # Racine relative ou disque entier : rien de lisible a proteger, la garde refuse tout.
            raise ValueError("GARDE_RACINE doit etre le chemin absolu d'un dossier")
        entree = sys.stdin.read()
        commande, cwd = lire(entree)
        regle = regle_refus(commande, cwd)
        if (
            not regle
            and outil(entree) == "Bash"
            and accents_graves_refuses(commande, cwd)
        ):
            regle = "accents_graves"
        if regle:
            tracer_refus(mode, regle)
            mots = MOTS.findall(commande.strip())
            if mots and not any(mot in SEP for mot in mots):
                verbe = ntpath.basename(_deciter(mots[0])).lower().removesuffix(".exe")
                if verbe in TELECHARGEURS or verbe in EXTRACTEURS:
                    return refuser(
                        mode,
                        "TELECHARGEMENT OU EXTRACTION BLOQUE par le hook anti-suppression. "
                        "Verifier la destination avant de reprendre.",
                    )
            return refuser(mode)
        if mode == "antigravity":
            # « ask » laisse la decision a la politique d'agy (toolPermission), sans forcer d'approbation.
            print(json.dumps({"decision": "ask"}))
        return 0
    except Exception as exc:  # noqa: BLE001  une garde en panne refuse
        tracer_refus(mode, "panne")
        return refuser(
            mode,
            f"Garde anti-suppression en panne ({type(exc).__name__}) : commande refusee par prudence.",
        )


if __name__ == "__main__":
    sys.exit(main())
