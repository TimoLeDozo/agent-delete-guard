"""Garde anti-suppression en hook pre_tool_call d'Hermes Agent (16/10) : meme garde que les autres moteurs."""

import io
import json
import sys
from pathlib import Path

import garde_suppression as g


def _jouer(monkeypatch, capsys, commande, cwd="/home/agent/ateliers/x/Depot"):
    charge = {
        "hook_event_name": "pre_tool_call",
        "tool_name": "terminal",
        "tool_input": {"command": commande},
        "cwd": cwd,
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(charge)))
    code = g.main(["hermes"])
    return code, capsys.readouterr().out.strip()


def test_suppression_dans_l_atelier_bloquee(monkeypatch, capsys):
    code, sortie = _jouer(monkeypatch, capsys, "rm -rf Infrastructure")
    assert code == 0 and json.loads(sortie)["decision"] == "block"


def test_commande_ordinaire_passe_en_silence(monkeypatch, capsys):
    assert _jouer(monkeypatch, capsys, "python -m pytest tests -q") == (0, "")


def test_garde_en_panne_bloque(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("{pas du json"))
    assert json.loads(capsys.readouterr().out or "{}") == {} and g.main(["hermes"]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "block"
