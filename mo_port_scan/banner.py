"""Startup banner (original ASCII radar art)."""

from __future__ import annotations

from typing import Callable

from .utils import BOLD, CYAN, DIM, GREEN

ART = r"""
            ooooooooooooo
        ooooo     |     ooooo
      ooo         |         ooo
    oo          .....          oo
  ooo      .*.... | ......     /ooo
 oo      ...      |      ...//    oo
 o      ..      .....     /*.      o
oo     ..     ... | ...//   ..     oo
o      .     .    | // .     .      o
o------.-----.----+----.-----.------o
o      .     .    |    .     .  *   o
oo    *..     ... | ...     ..     oo
 o      ..      .....      ..      o
 oo      ...      |      ...      oo
  ooo      ...... | ...*..      ooo
    oo          .....          oo
      ooo         |         ooo
        ooooo     |     ooooo
            ooooooooooooo
""".strip("\n")

TAGLINE = "Fast TCP/UDP port scanner  |  service detection  |  reports"


def render_banner(version: str, c: Callable[[str, str], str]) -> str:
    title = f"Mo-port-scan v{version}"
    art = "\n".join(c(line, GREEN) for line in ART.splitlines())
    return "\n".join([
        art,
        "",
        c(title.center(38), BOLD + ";" + CYAN),
        c(TAGLINE, DIM),
        "",
    ])
