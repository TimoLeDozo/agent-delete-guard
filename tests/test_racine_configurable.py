"""La racine protegee vient de GARDE_RACINE, lue au lancement du hook."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

GARDE = Path(__file__).resolve().parents[1] / "garde_suppression.py"
R = "r" + "m"


def _hook(racine: str, commande: str, cwd: str) -> int:
    env = {**os.environ, "GARDE_RACINE": racine, "GARDE_TRACE": os.devnull}
    charge = {"tool_name": "Bash", "tool_input": {"command": commande}, "cwd": cwd}
    return subprocess.run(
        [sys.executable, str(GARDE), "claude"],
        input=json.dumps(charge),
        capture_output=True,
        text=True,
        timeout=20,
        env=env,
        check=False,
    ).returncode


@pytest.fixture
def depot(tmp_path):
    (tmp_path / "projet-garde" / "docs").mkdir(parents=True)
    (tmp_path / "ailleurs").mkdir()
    return tmp_path


def test_suppression_sous_la_racine_refusee(depot):
    racine = str(depot / "projet-garde")
    assert _hook(racine, R + " -rf docs", racine) == 2
    assert _hook(racine, "git status", racine) == 0


def test_meme_commande_hors_racine_permise(depot):
    racine = str(depot / "projet-garde")
    assert _hook(racine, R + " -rf docs", str(depot / "ailleurs")) == 0


def test_cible_absolue_et_ancetre_refusees(depot):
    racine = str(depot / "projet-garde")
    ailleurs = str(depot / "ailleurs")
    assert _hook(racine, f"{R} -rf {racine}/docs", ailleurs) == 2
    assert _hook(racine, f"{R} -rf {depot}", ailleurs) == 2


def test_racine_relative_refuse_tout(depot):
    assert _hook("projet-garde", "git status", str(depot)) == 2
