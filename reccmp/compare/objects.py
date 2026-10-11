"""Finds the parts of the recompiled binary that came from the object file
compiled from a given source file."""

import bisect
from pathlib import PurePath, PureWindowsPath
from reccmp.cvdump import CvdumpAnalysis
from reccmp.formats import PEImage
from .lines import LinesDb


class ObjectDataRegions:
    """Maps a local source file to the address ranges its object file(s)
    contributed to the non-code sections of the recompiled binary.
    Uses SECTION CONTRIBUTIONS from the PDB, and MODULES if available."""

    def __init__(
        self, cvdump_analysis: CvdumpAnalysis, lines_db: LinesDb, recomp_bin: PEImage
    ):
        self._lines_db = lines_db
        self._cache: dict[PurePath, list[range]] = {}

        code_ranges = [region.range for region in recomp_bin.get_code_regions()]

        # Sorted (start, end, module id) of every contribution, to find the module for an address.
        self._contribs: list[tuple[int, int, int]] = []
        self._data_by_module: dict[int, list[range]] = {}

        for ref in cvdump_analysis.parser.sizerefs:
            if not recomp_bin.is_valid_section(ref.section):
                continue

            start = recomp_bin.get_abs_addr(ref.section, ref.offset)
            self._contribs.append((start, start + ref.size, ref.module))

            if not any(start in code_range for code_range in code_ranges):
                self._data_by_module.setdefault(ref.module, []).append(
                    range(start, start + ref.size)
                )

        self._contribs.sort()

        self._modules_by_stem: dict[str, list[int]] = {}
        for module in cvdump_analysis.parser.modules:
            # e.g. "main.obj" or "CMakeFiles/game.dir/src/main.cpp.obj"
            stem = PureWindowsPath(module.obj).name.lower().split(".")[0]
            self._modules_by_stem.setdefault(stem, []).append(module.id)

    def _module_at(self, addr: int) -> int | None:
        i = bisect.bisect_right(self._contribs, (addr, float("inf"), 0)) - 1
        if i < 0:
            return None

        start, end, module = self._contribs[i]
        return module if start <= addr < end else None

    def _modules_for_file(self, local_path: PurePath) -> set[int]:
        # The PDB does not name the source file of a module, but the line
        # numbers lead from the file to its code and from there to the module.
        # A header can lead to many modules.
        modules = set()
        for addr in self._lines_db.addresses_for_path(local_path):
            module = self._module_at(addr)
            if module is not None:
                modules.add(module)

        if modules:
            return modules

        # Agent's choice: a file without code (e.g. only data tables) has no
        # line numbers, so fall back to a module whose object file has the
        # same name. Used only if the name is unique. The alternative is to
        # leave such files without a module.
        candidates = self._modules_by_stem.get(local_path.stem.lower(), [])
        return set(candidates) if len(candidates) == 1 else set()

    def get(self, local_path: str | PurePath) -> list[range]:
        if not isinstance(local_path, PurePath):
            local_path = PurePath(local_path)

        if local_path not in self._cache:
            self._cache[local_path] = sorted(
                (
                    range_
                    for module in self._modules_for_file(local_path)
                    for range_ in self._data_by_module.get(module, [])
                ),
                key=lambda range_: range_.start,
            )

        return self._cache[local_path]
