"""Racine protegee des tests : un chemin fictif, fixe avant l'import de la garde.

La garde ne touche jamais le disque, sauf os.path.isdir sur une cible de cd ou de copie :
un dossier absent la rend seulement plus prudente.
"""

import os
import sys
from pathlib import Path

os.environ["GARDE_RACINE"] = "D:/Depot"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
