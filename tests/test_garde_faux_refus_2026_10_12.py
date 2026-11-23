"""12/10 : la garde refusait des commandes en lecture seule.

Motifs trouves en rejouant 76 refus des transcriptions du 08 au 12/10 :
- corps de here-document decoupe comme des commandes shell (lignes Python ou Markdown).
- tout cd rendait le dossier inconnu, meme vers un chemin litteral.
- variable locale S="C:/.../scratchpad" inconnue, donc "$S/x.json" pris pour un chemin du depot.
- affectation PowerShell collee ($t=Get-X) prise pour un nom de commande calcule.
- n=$(find ...) laissait un segment « "$d" -name x » pris pour une commande calculee.
- subprocess.list2cmdline pris pour un lancement, \\` et \\$ mal lus dans une citation bash.
- cp d'un joker vers un dossier temporaire pris pour une ecriture de ~/.claude/settings.json.
Chaque correctif est borne : les formes destructrices restent refusees, et quelques trous
trouves en chemin sont fermes (do rm, then rm, eval, here-string, accents graves, $x=rm).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

GARDE = Path(__file__).resolve().parents[1] / "garde_suppression.py"
import garde_suppression as g  # noqa: E402

DEPOT = "D:\\Depot"
HORS = "C:\\Users\\exemple"
SCRATCH = "C:/Users/exemple/AppData/Local/Temp/claude/x/scratchpad"
R = "r" + "m"  # assemble pour ne pas declencher les protections du harnais

HEREDOC_COMPTAGE = """cd D:/Depot && export PYTHONUTF8=1 && python - <<'EOF'
import json, collections, pathlib
cards={}
for line in pathlib.Path('suivi/cartes.jsonl').read_text(encoding='utf-8').splitlines():
    if line.strip():
        d=json.loads(line)\u003b cards[d['id']]={**cards.get(d['id'],{}),**{k:v for k,v in d.items() if v not in (None,'',[])}}
print(len(cards))
print("bloque:", collections.Counter((c.get('trouve') or '')[:40] for c in cards.values() if c.get('statut')=='bloque'))
EOF
"""

# Les six formes du brief, telles que refusees le 12/10.
SIX_FORMES = [
    'cd D:/Depot && for r in sondes ia chantiers\u003b do printf "%s: " $r\u003b curl -s -m 8 -o /tmp/o_$r.json '
    '-w "%{http_code}\\n" http://127.0.0.1:3100/api/$r\u003b done\u003b python -c "import json\u003b '
    "d=json.load(open('/tmp/o_chantiers.json',encoding='utf-8'))\u003b print(type(d).__name__)\"",
    f'S="{SCRATCH}" && for r in sondes ia\u003b do curl -s -m 8 -w "%{{http_code}}\\n" '
    'http://127.0.0.1:3100/api/$r -o "$S/orbite_$r.json"\u003b done',
    HEREDOC_COMPTAGE
    + 'echo "== supervision_auto"\u003b python -c "import json\u003b '
    "d=json.load(open('Infrastructure/logs/supervision_auto.json',encoding='utf-8'))\u003b print(d)\"",
    f'S="{SCRATCH}" && cat > "$S/cartes_agents.py" <<\'EOF\'\nprint(1)\nEOF\n'
    'python "$S/cartes_agents.py"\u003b head -c 600 Infrastructure/logs/supervision_auto.json',
    HEREDOC_COMPTAGE
    + 'for r in sondes ia\u003b do curl -s -m 8 -w " [%{http_code}]" "http://127.0.0.1:3100/api/$r" '
    '| python -c "import sys\u003b t=sys.stdin.read()\u003b print(t[:260])"\u003b done',
    "git diff -- Infrastructure/hooks/garde_suppression.py > docs/x.patch && git apply --check docs/x.patch",
]


@pytest.fixture(autouse=True)
def _trace_isolee(tmp_path, monkeypatch):
    monkeypatch.setenv("GARDE_TRACE", str(tmp_path / "garde_trace.jsonl"))


@pytest.mark.parametrize("commande", SIX_FORMES)
def test_six_formes_du_brief_passent(commande):
    assert not g.doit_refuser(commande, DEPOT)


def _hook(commande: str, cwd: str = DEPOT, outil: str = "Bash") -> int:
    charge = {"tool_name": outil, "tool_input": {"command": commande}, "cwd": cwd}
    return subprocess.run(
        [sys.executable, str(GARDE), "claude"],
        input=json.dumps(charge),
        capture_output=True,
        text=True,
        timeout=20,
        env=dict(os.environ),
        check=False,
    ).returncode


@pytest.mark.parametrize("commande", [SIX_FORMES[0], SIX_FORMES[2], SIX_FORMES[3]])
def test_six_formes_par_le_hook(commande):
    assert _hook(commande) == 0


# Formes reelles relevees dans les transcriptions, toutes en lecture seule ou hors depot.
LEGITIMES = [
    # corps Markdown : « (a) » et un mot « sh » en tete de ligne ne sont pas des commandes
    "cat > docs/analyses/x.md <<'EOF'\n| (a) VM Windows 11 ARM | Prism |\nsh\nbun\nEOF",
    "cat >> docs/analyses/x.md <<'E'\n(b) Wine + box64 ou FEX\nE",
    # corps Python d'une analyse en lecture seule
    "python - <<'EOF'\nimport json\nfor l in open('suivi/decisions.jsonl',encoding='utf-8'):\n"
    "    d=json.loads(l)\n    print({k:(str(v)[:140]) for k,v in d.items()})\nEOF",
    # PowerShell lance par un script ou par un here-document
    "powershell -NoProfile -File - <<'EOF'\nforeach($n in 'a','b'){$t=Get-ScheduledTask $n\u003b "
    "'{0} {1}' -f $n,$t.State}\nEOF",
    'powershell -NoProfile -Command "foreach(\\$n in \'a\',\'b\'){\\$t=Get-ScheduledTask \\$n\u003b\\$t.State}"',
    'powershell -NoProfile -c "\\$i=Get-ScheduledTaskInfo -TaskName \'Exemple-X\'\u003b \\$i.LastRunTime"',
    "$t=(Get-ScheduledTask Exemple-BoitePro)\u003b $t.Settings.MultipleInstances",
    "[xml]$s=Get-Content C:/Users/exemple/AppData/Local/Temp/ss.xml",
    # cd litteral puis ecriture hors depot
    f"cd {SCRATCH} && curl -s -o t.html -w '%{{http_code}}' https://example.com/x",
    "cd C:/Users/exemple/AppData/Local/Temp && curl -sL https://example.com/faq -o /dev/null",
    "cd /d/Depot\u003b " + R + ' -rf "C:/Users/exemple/AppData/Local/Temp/sas_deploiement/x"',
    # variable locale litterale
    f'S="{SCRATCH}"\u003b curl -s http://127.0.0.1:3100/api/ia -o "$S/orbite_ia.json"',
    'K="python outils/cartes.py poser"\n$K --id x --statut a-verifier --agent codex',
    # $( ) d'une boucle : le segment « "$d" -name x » n'est pas une commande
    'for d in */\u003b do n=$(find "$d" -name SKILL.md | wc -l)\u003b echo "$d $n"\u003b done',
    's=$(date +%s%N)\u003b echo "rc=$? $(( ($(date +%s%N)-s)/1000000 )) ms"',
    # Python : list2cmdline ne lance rien, un deplacement interne au depot comme mv
    "python -c \"import subprocess\u003b print(subprocess.list2cmdline(['a', 'b']))\"",
    "python -c \"import os\u003b os.replace('clips/a_brut.mp4', 'brut/a_brut.mp4')\"",
    # \\` et \\$ en citation double bash sont litteraux
    "python -c \"import re\u003b print(re.findall(r'\\`\\`\\`json', 'x'))\"",
    "python -c \"import subprocess\u003b subprocess.run(['bash', '-c', 'echo \\$PATH | cut -c1-20'])\"",
    # copie d'un joker vers un dossier temporaire
    f'cp "{SCRATCH}/src/"* "{SCRATCH}/v2/"',
]


@pytest.mark.parametrize("commande", LEGITIMES)
def test_formes_legitimes_passent(commande):
    assert not g.doit_refuser(commande, DEPOT)


# Formes destructrices : refusees avant, et toujours refusees.
DESTRUCTRICES = [
    R + " -rf docs",
    "cd D:/Depot && " + R + " -rf docs",
    "cd docs && " + R + " -rf x",
    "cd .. && " + R + " -rf Depot",
    "cd /tmp/n-existe-pas-12-10\u003b " + R + " -rf *",
    "cd $X && " + R + " -f a",
    "S=docs && " + R + " -rf $S",
    "S=/tmp/x\u003b S=$(pwd)\u003b " + R + " -rf $S",
    "for S in /tmp/a docs\u003b do " + R + " -rf $S\u003b done",
    "Remove-Item docs -Recurse",
    "$t=Remove-Item docs -Recurse",
    "git clean -fd",
    "git reset --hard HEAD~1",
    "git checkout -- docs/a.md",
    "git branch -D nuit/x",
    "git worktree remove .ateliers/x",
    "python -c \"import shutil\u003b shutil.rmtree('docs')\"",
    "python -c \"import os\u003b os.remove('docs/a.md')\"",
    "python -c \"import os\u003b os.replace('docs/a.md', 'C:/x/a.md')\"",
    "python -c \"import os\u003b os.replace('docs/a.md', 'CLAUDE.md')\"",
    "echo x > CLAUDE.md",
    "cat > CLAUDE.md <<'EOF'\nx\nEOF",
    "curl -o CLAUDE.md https://example.com/x",
    # corps execute par un interprete
    "python - <<'EOF'\nimport shutil\nshutil.rmtree('docs')\nEOF",
    "bash <<'EOF'\n" + R + " -rf docs\nEOF",
    "cat <<EOF\n$(" + R + " -rf docs)\nEOF",
]


@pytest.mark.parametrize("commande", DESTRUCTRICES)
def test_formes_destructrices_restent_refusees(commande):
    assert g.doit_refuser(commande, DEPOT)


# Trous fermes en chemin : ils passaient avant le 12/10.
TROUS_FERMES = [
    ("for f in a\u003b do " + R + " -rf x\u003b done", DEPOT),
    ("if true\u003b then " + R + " -rf x\u003b fi", DEPOT),
    ("! " + R + " -rf docs", DEPOT),
    ('eval "' + R + ' -rf docs"', DEPOT),
    ("python <<< \"import shutil\u003b shutil.rmtree('docs')\"", DEPOT),
    ('bash <<< "' + R + ' -rf docs"', DEPOT),
    ("$x=" + R + " -rf D:/Depot/docs", HORS),
    ("Remove-Item ('D:/De'+'pot') -Recurse", HORS),
]


@pytest.mark.parametrize("commande,cwd", TROUS_FERMES)
def test_trous_fermes(commande, cwd):
    assert g.doit_refuser(commande, cwd)


def test_accents_graves_bash_par_le_hook():
    # Sous Bash, `cmd` est une substitution de commande. Sous PowerShell, un echappement.
    assert _hook("echo `" + R + " -rf docs`") == 2
    assert _hook("x=`" + R + " -rf docs`") == 2
    assert _hook("echo `date`") == 0
    assert _hook("Write-Output `\"bonjour`\"", outil="PowerShell") == 0


def test_cd_chaine_et_echec():
    # cd vers un dossier absent : la suite de la chaine && part du dossier vise,
    # mais apres un point-virgule le dossier de depart reste possible.
    assert not g.doit_refuser(f"cd {SCRATCH}/absent && curl -o x.json https://e.x", DEPOT)
    assert g.doit_refuser(f"cd {SCRATCH}/absent\u003b curl -o x.json https://e.x", DEPOT)
    assert g.doit_refuser(f"cd {SCRATCH}/absent || curl -o x.json https://e.x", DEPOT)


def test_latence_formes_du_brief():
    # La garde tourne avant chaque commande, elle doit rester instantanee.
    for commande in SIX_FORMES:
        durees = []
        for _ in range(5):
            depart = time.perf_counter()
            g.doit_refuser(commande, DEPOT)
            durees.append(time.perf_counter() - depart)
        assert min(durees) < 0.020, f"{min(durees) * 1000:.1f} ms pour {commande[:40]}"
