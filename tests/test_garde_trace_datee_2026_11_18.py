"""Trace des refus multi-moteurs et bilan, sans modifier les verdicts."""

import io
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import garde_suppression as g

DEPOT = "D:/Depot"
MODES = ["claude", "codex", "antigravity", "hermes"]


@pytest.fixture
def trace(tmp_path, monkeypatch):
    chemin = tmp_path / "hooks" / "garde_trace.jsonl"
    monkeypatch.setenv("GARDE_TRACE", str(chemin))
    return chemin


def lancer(monkeypatch, mode, commande, outil="PowerShell"):
    charge = {
        "tool_name": outil,
        "tool_input": {"command": commande},
        "cwd": DEPOT,
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(charge)))
    return g.main([mode])


def verifier_refus(mode, code, sortie):
    if mode == "claude":
        assert code == 2
        assert "SUPPRESSION BLOQUEE" in sortie.err
        assert sortie.out == ""
    else:
        assert code == 0
        resultat = json.loads(sortie.out)
        if mode == "codex":
            assert resultat["hookSpecificOutput"]["permissionDecision"] == "deny"
        else:
            assert resultat["decision"] == ("block" if mode == "hermes" else "deny")
        assert sortie.err == ""


@pytest.mark.parametrize("mode", MODES)
def test_refus_date_et_ajoute_sans_ecraser(trace, monkeypatch, capsys, mode):
    commande = "git clean -fd " + "x" * 250
    avant = datetime.now(timezone.utc)
    for _ in range(2):
        code = lancer(monkeypatch, mode, commande)
        verifier_refus(mode, code, capsys.readouterr())
    lignes = [
        json.loads(ligne) for ligne in trace.read_text(encoding="utf-8").splitlines()
    ]
    assert len(lignes) == 2
    for ligne in lignes:
        assert set(ligne) == {"le", "mode", "regle"}
        date = datetime.fromisoformat(ligne["le"])
        assert date.utcoffset() == timedelta(0)
        assert avant <= date <= datetime.now(timezone.utc)
        assert ligne["mode"] == mode
        assert ligne["regle"] == "segment"
    contenu = trace.read_text(encoding="utf-8")
    assert DEPOT not in contenu and "x" * 20 not in contenu


def test_argument_de_mode_inattendu_non_journalise(trace, monkeypatch, capsys):
    mode = "etiquette-fictive-privee"
    lancer(monkeypatch, mode, "git clean -fd")
    capsys.readouterr()
    contenu = trace.read_text(encoding="utf-8")
    assert json.loads(contenu)["mode"] == "inconnu"
    assert mode not in contenu


@pytest.mark.parametrize("mode", MODES)
def test_commande_permise_sans_trace(trace, monkeypatch, capsys, mode):
    assert lancer(monkeypatch, mode, "git status") == 0
    sortie = capsys.readouterr()
    assert sortie.err == ""
    assert sortie.out == ('{"decision": "ask"}\n' if mode == "antigravity" else "")
    assert not trace.exists()


@pytest.mark.parametrize("mode", MODES)
def test_trace_inaccessible_ne_change_pas_le_refus(tmp_path, monkeypatch, capsys, mode):
    monkeypatch.setenv("GARDE_TRACE", str(tmp_path))
    code = lancer(monkeypatch, mode, "git clean -fd")
    verifier_refus(mode, code, capsys.readouterr())


@pytest.mark.parametrize(
    ("commande", "regle"),
    [
        ("cat <<EOF\n$(git clean -fd)\nEOF", "corps"),
        ("(git clean -fd)", "parentheses"),
        ("Get-ChildItem docs | ForEach-Object -MemberName Delete", "dynamique"),
        ("echo $(git clean -fd)", "sous_commande"),
        ("Set-Alias vider Remove-Item\nvider docs", "alias"),
        ("git clean -fd", "segment"),
        ("git status", ""),
    ],
)
def test_branche_et_api_booleenne(commande, regle):
    assert g.regle_refus(commande, DEPOT) == regle
    assert g.doit_refuser(commande, DEPOT) is bool(regle)


def test_accents_graves_bash_identifies(trace, monkeypatch, capsys):
    code = lancer(monkeypatch, "claude", "echo `git clean -fd`", outil="Bash")
    verifier_refus("claude", code, capsys.readouterr())
    assert json.loads(trace.read_text(encoding="utf-8"))["regle"] == "accents_graves"


@pytest.mark.parametrize("mode", MODES)
def test_panne_tracee_sans_copier_entree_invalide(trace, monkeypatch, capsys, mode):
    monkeypatch.setattr(sys, "stdin", io.StringIO("{json invalide"))
    assert g.main([mode]) == (2 if mode == "claude" else 0)
    assert "en panne" in "".join(capsys.readouterr())
    ligne = json.loads(trace.read_text(encoding="utf-8"))
    assert ligne["regle"] == "panne"
    assert ligne["mode"] == mode
    assert set(ligne) == {"le", "mode", "regle"}


def test_bilan_filtre_et_compte_sans_modifier_la_trace(trace, monkeypatch, capsys):
    maintenant = datetime.now(timezone.utc)

    def ligne(jours, mode="claude", regle="segment"):
        return json.dumps(
            {
                "le": (maintenant - timedelta(days=jours)).isoformat(),
                "mode": mode,
                "regle": regle,
            }
        )

    contenu = (
        "\n".join(
            [
                ligne(1),
                ligne(2),
                ligne(3, "codex"),
                ligne(4, "claude", "dynamique"),
                ligne(8),
                ligne(-1),
                json.dumps({"cwd": DEPOT, "commande": "ancienne"}),
                "{tronque",
                "[]",
                ligne(1, mode=[]),
                json.dumps({"le": "2026-11-18", "mode": "claude", "regle": "segment"}),
            ]
        )
        + "\n"
    )
    trace.parent.mkdir()
    trace.write_text(contenu, encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", None)
    assert g.main(["--bilan", "7"]) == 0
    sortie = capsys.readouterr()
    assert sortie.err == ""
    assert json.loads(sortie.out) == {
        "jours": 7,
        "total": 4,
        "refus": [
            {"regle": "dynamique", "mode": "claude", "compte": 1},
            {"regle": "segment", "mode": "claude", "compte": 2},
            {"regle": "segment", "mode": "codex", "compte": 1},
        ],
        "sans_date": 1,
        "invalides": 4,
    }
    assert trace.read_text(encoding="utf-8") == contenu


def test_bilan_ne_reproduit_pas_les_categories_libres_historiques(trace, capsys):
    texte = "libelle-fictif-prive"
    entree = {
        "le": datetime.now(timezone.utc).isoformat(),
        "mode": texte,
        "regle": texte,
    }
    trace.parent.mkdir()
    trace.write_text(json.dumps(entree), encoding="utf-8")
    assert g.main(["--bilan", "1"]) == 0
    sortie = capsys.readouterr().out
    assert texte not in sortie
    assert json.loads(sortie)["refus"] == [
        {"regle": "inconnu", "mode": "inconnu", "compte": 1}
    ]


@pytest.mark.parametrize(
    "arguments", [["--bilan"], ["--bilan", "0"], ["--bilan", "-1"], ["--bilan", "abc"]]
)
def test_bilan_arguments_invalides(trace, monkeypatch, capsys, arguments):
    monkeypatch.setattr(sys, "stdin", None)
    assert g.main(arguments) == 2
    assert "Usage" in capsys.readouterr().err
    assert not trace.exists()


def test_bilan_trace_absente(trace, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", None)
    assert g.main(["--bilan", "7"]) == 1
    assert "Trace illisible" in capsys.readouterr().err
    assert not trace.exists()
