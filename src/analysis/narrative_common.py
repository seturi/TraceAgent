"""The bilingual interpretation record shared by every analysis narrator.

NTFS operations (:mod:`analysis.ntfs.narrative`) and AI-agent sessions
(:mod:`analysis.session_narrative`) read completely different evidence, but they
answer the same question — *who did what* — and have to render identically in
the UI and in an exported report.  Keeping the record here stops the two
narrators from drifting into two subtly different shapes.
"""

from __future__ import annotations

from dataclasses import dataclass

Language = str  # "ko" | "en"


@dataclass(frozen=True, slots=True)
class Narrative:
    """A bilingual interpretation: one headline plus supporting detail lines."""

    headline_ko: str
    headline_en: str
    detail_ko: tuple[str, ...] = ()
    detail_en: tuple[str, ...] = ()
    key: str = ""  # stable interpretation id, e.g. "atomic_replace"

    def headline(self, language: Language = "ko") -> str:
        return self.headline_ko if language == "ko" else self.headline_en

    def details(self, language: Language = "ko") -> tuple[str, ...]:
        return self.detail_ko if language == "ko" else self.detail_en

    def text(self, language: Language = "ko") -> str:
        return "\n".join((self.headline(language), *self.details(language)))

    def bilingual(self, *, english_first: bool = False) -> str:
        """Both headlines, one per line.

        The NTFS evidence table leads with Korean because the column it sits in
        is Korean-first; the local-artifact interpretation leads with English.
        Making the order the caller's choice means neither has to reassemble the
        string by hand.
        """
        if english_first:
            return f"{self.headline_en}\n{self.headline_ko}"
        return f"{self.headline_ko}\n{self.headline_en}"