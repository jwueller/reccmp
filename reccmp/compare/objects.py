"""Finds the parts of the recompiled binary that came from the object file
compiled from a given source file."""

import bisect
import re
from pathlib import PurePath, PureWindowsPath
from reccmp.cvdump import CvdumpAnalysis
from reccmp.formats import PEImage
from .lines import LinesDb


def _normalize(name: str) -> str:
    """Build systems differ in how they join the file name and its extension."""
    return re.sub(r"[^a-z0-9]", "_", name.lower())


class ObjectDataRegions:
    """Maps a local source file to the address ranges its object file(s)
    contributed to the data sections of the recompiled binary.
    Uses SECTION CONTRIBUTIONS from the PDB, and MODULES if available."""

    def __init__(
        self, cvdump_analysis: CvdumpAnalysis, lines_db: LinesDb, recomp_bin: PEImage
    ):
        self._lines_db = lines_db
        self._cache: dict[PurePath, list[range]] = {}

        data_ranges = [region.range for region in recomp_bin.get_data_regions()]

        # Sorted (start, end, module id) of every contribution, to find the module for an address.
        self._contribs: list[tuple[int, int, int]] = []
        self._data_by_module: dict[int, list[range]] = {}

        for ref in cvdump_analysis.parser.sizerefs:
            if not recomp_bin.is_valid_section(ref.section):
                continue

            start = recomp_bin.get_abs_addr(ref.section, ref.offset)
            self._contribs.append((start, start + ref.size, ref.module))

            if any(start in data_range for data_range in data_ranges):
                self._data_by_module.setdefault(ref.module, []).append(
                    range(start, start + ref.size)
                )

        self._contribs.sort()

        # Object file name without its extension -> module ids.
        self._modules_by_name: dict[str, list[int]] = {}
        for module in cvdump_analysis.parser.modules:
            name = PureWindowsPath(module.obj).stem
            self._modules_by_name.setdefault(_normalize(name), []).append(module.id)

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

        # A file without code (e.g. only data tables) has no line numbers, so
        # fall back to a module whose object file is named after the file:
        # with its extension (main.cpp.obj, main_cpp.obj) or without
        # (main.obj). Used only if the name is unique.
        for name in (local_path.name, local_path.stem):
            candidates = self._modules_by_name.get(_normalize(name), [])
            if len(candidates) == 1:
                return set(candidates)

        return set()

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
