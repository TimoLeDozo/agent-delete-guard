"""Les lectures explicites de la configuration Git ne desarment pas la garde."""

import io
import json
import sys
from pathlib import Path

import pytest

GARDE = Path(__file__).resolve().parents[1] / "garde_suppression.py"
import garde_suppression as g

DEPOT = "D:/Depot"


def test_lire_le_chemin_des_hooks_est_permis():
    assert not g.doit_refuser("git config --show-origin --get core.hooksPath", DEPOT)


@pytest.mark.parametrize("cle", ["core.hooksPath", "core.fsmonitor", "core.sshCommand"])
@pytest.mark.parametrize(
    "options",
    ["--get", "--show-origin --get", "--global --show-scope --get-all", "get"],
)
def test_lectures_explicites_des_cles_protegees(cle, options):
    assert not g.doit_refuser(f"git config {options} {cle}", DEPOT)


@pytest.mark.parametrize(
    "commande",
    [
        "git config --get-regexp core.hooksPath",
        "git config --get-urlmatch core.sshCommand https://example.test",
        "git config --local --null --includes --get core.hooksPath",
        "git config --system --no-includes --get core.hooksPath",
        "git config --worktree -z --get core.hooksPath",
    ],
)
def test_options_de_lecture_sans_valeur(commande):
    assert not g.doit_refuser(commande, DEPOT)


@pytest.mark.parametrize(
    "commande",
    [
        "git config core.hooksPath /tmp/hooks",
        "git config set core.hooksPath /tmp/hooks",
        "git config --global core.fsmonitor /tmp/commande",
        "git config core.sshCommand ssh",
        "git config --unset core.hooksPath",
        "git config --replace-all core.hooksPath /tmp/hooks",
        "git config --comment --get core.hooksPath /tmp/hooks",
        "git config --comment get core.hooksPath /tmp/hooks",
        "git config --file --get core.hooksPath /tmp/hooks",
        "git config -- core.hooksPath --get",
        "git config core.hooksPath get",
        "git config --get core.hooksPath > CLAUDE.md",
        "git config --get core.hooksPath && Remove-Item docs -Recurse",
        "git config --get core.hooksPath\nrm -rf docs",
        "git config --get core.hooksPath && git clean -fd",
        "git config --get core.hooksPath && git reset --hard",
    ],
)
def test_ecritures_et_suppressions_restent_refusees(commande):
    assert g.doit_refuser(commande, DEPOT)


@pytest.mark.parametrize("mode", ["claude", "codex", "antigravity", "hermes"])
@pytest.mark.parametrize("ecriture", [False, True], ids=["lecture", "ecriture"])
def test_contrat_hook(monkeypatch, capsys, tmp_path, mode, ecriture):
    commande = (
        "git config core.hooksPath /tmp/hooks"
        if ecriture
        else "git config --show-origin --get core.hooksPath"
    )
    charge = {
        "tool_name": "PowerShell",
        "tool_input": {"command": commande},
        "cwd": DEPOT,
    }
    monkeypatch.setenv("GARDE_TRACE", str(tmp_path / "trace.jsonl"))
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(charge)))
    retour = g.main([mode])
    sortie = capsys.readouterr()
    if not ecriture:
        assert retour == 0
        assert not sortie.err
        if mode == "antigravity":
            assert json.loads(sortie.out) == {"decision": "ask"}
        else:
            assert not sortie.out
    elif mode == "claude":
        assert retour == 2
        assert "SUPPRESSION BLOQUEE" in sortie.err
    else:
        assert retour == 0
        decision = json.loads(sortie.out)
        if mode == "codex":
            assert decision["hookSpecificOutput"]["permissionDecision"] == "deny"
        else:
            assert decision["decision"] == ("block" if mode == "hermes" else "deny")
