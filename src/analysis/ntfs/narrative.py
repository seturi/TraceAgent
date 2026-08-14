"""Plain-language (Korean/English) interpretation of NTFS file operations.

The reconstructed USN flow (``File_Created -> Data_Added -> File_Closed``) is
precise but unreadable: it says *which bits NTFS set*, not *what a person or an
agent actually did*.  This module turns one :class:`~analysis.ntfs.signatures.FileOperation`
into a sentence an investigator (or a court report) can read — "the AI agent
rewrote the document by writing a temp file and swapping it over the original" —
in both Korean and English.

Interpretation happens at three levels:

``_interpret``
    Recognises the *composite pattern* the whole flow forms (atomic replace,
    truncate-and-rewrite, Recycle Bin delete, timestamp-only touch, ...) and
    states what it means, not just what it was.
``_flow_steps``
    Narrates the individual reasons in order, collapsing the rename old/new pair
    into a single "renamed A -> B" step.
``summarize_file``
    Rolls every operation on one file/folder up into a single headline, and
    still says something useful for files that only survive in ``$MFT`` /
    ``$LogFile`` with no USN history left.

Kept free of any ``dissect``/Qt dependency so the wording can be unit-tested.
"""

from __future__ import annotations

from dataclasses import dataclass

from analysis.narrative_common import Language, Narrative
from analysis.ntfs.signatures import (
    FileOperation,
    has_app_temp,
    has_download_temp,
    has_tmp_rename,
    is_user_doc_path,
)
from core.models import ActorClass

__all__ = [
    "BEHAVIOR_LABELS",
    "Language",
    "Narrative",
    "REASON_PHRASES",
    "behavior_label",
    "describe_operation",
    "reason_phrase",
    "summarize_file",
]

# Behavior code -> short (Korean, English) label, used when chaining several
# operations into one file-level headline.
BEHAVIOR_LABELS: dict[str, tuple[str, str]] = {
    "create": ("생성", "create"),
    "modify": ("수정", "modify"),
    "rename": ("이름 변경", "rename"),
    "move": ("이동", "move"),
    "copy": ("복사", "copy"),
    "delete_permanent": ("완전 삭제", "permanent delete"),
    "delete_recycle": ("휴지통 이동", "move to Recycle Bin"),
    "metadata_change": ("속성 변경", "metadata change"),
    "logfile_recovered": ("$LogFile 복구", "recovered from $LogFile"),
}

# USN reason (friendly name) -> (Korean, English) narration of that single step.
_STEP_PHRASES: dict[str, tuple[str, str]] = {
    "File_Created": ("파일이 새로 만들어졌습니다", "the file was created"),
    "Data_Added": ("데이터가 뒤에 덧붙여졌습니다", "data was appended"),
    "Data_Overwritten": ("기존 데이터가 덮어써졌습니다", "existing data was overwritten"),
    "Data_Truncated": ("파일 내용이 잘려 나갔습니다", "the file was truncated"),
    "File_Renamed_Old": ("이전 이름이 해제되었습니다", "the old name was released"),
    "File_Renamed_New": ("새 이름이 부여되었습니다", "a new name was assigned"),
    "File_Deleted": ("파일이 삭제되었습니다", "the file was deleted"),
    "File_Closed": ("파일 핸들이 닫혔습니다(작업 종료)", "the file handle was closed (operation finished)"),
    "Basic_Info_Changed": ("타임스탬프·속성이 변경되었습니다", "timestamps/attributes were changed"),
    "Access_Right_Changed": ("접근 권한(ACL)이 변경되었습니다", "access rights (ACL) were changed"),
    "Object_ID_Changed": ("객체 ID가 변경되었습니다", "the object ID was changed"),
    "EA_Changed": ("확장 속성이 변경되었습니다", "extended attributes were changed"),
    "Stream_Changed": ("대체 데이터 스트림이 변경되었습니다", "an alternate data stream was changed"),
    "Hard_Link_Changed": ("하드링크가 변경되었습니다", "a hard link was changed"),
    "Compression_Changed": ("압축 속성이 변경되었습니다", "the compression attribute was changed"),
    "Encryption_Changed": ("암호화 속성이 변경되었습니다", "the encryption attribute was changed"),
    "Reparse_Point_Changed": ("재분석 지점이 변경되었습니다", "the reparse point was changed"),
    "Indexable_Changed": ("색인 대상 여부가 변경되었습니다", "the indexing flag was changed"),
    "Integrity_Changed": ("무결성 속성이 변경되었습니다", "the integrity attribute was changed"),
    "Transacted_Changed": ("트랜잭션 상태가 변경되었습니다", "the transacted state was changed"),
}

# Attribution reason code -> (Korean, English) phrase.  Shared with the report
# exporters so the evidence wording is identical in the UI and in the report.
REASON_PHRASES: dict[str, tuple[str, str]] = {
    "interactive_app_temp": (
        "대화형 응용프로그램의 임시/잠금 파일",
        "interactive application temp file",
    ),
    "recycle_bin_move": ("휴지통으로 이동", "Recycle Bin move"),
    "os_or_app_background_path": (
        "운영체제·응용프로그램의 배경 활동 경로",
        "OS/application background activity",
    ),
    "atomic_tmp_rename_write": (
        "임시 파일에 기록 후 이름 교체(원자적 쓰기) — AI 에이전트 패턴",
        "atomic temp-file-then-rename write (AI-agent pattern)",
    ),
    "data_truncate_add_overwrite": (
        "내용을 비우고 다시 쓰는 재작성 패턴",
        "truncate-then-rewrite pattern",
    ),
    "object_id_then_data": (
        "객체 ID 변경 후 데이터 기록",
        "object-ID change followed by data write",
    ),
    "copy_with_basic_info_change": (
        "속성까지 함께 복제된 복사",
        "copy with attribute change",
    ),
    "copy_ambiguous": (
        "복사 — 파일시스템 기록만으로는 행위자 판별 불가",
        "copy, actor not determinable from filesystem alone",
    ),
    "directory_operation": (
        "폴더 조작 — 내용 쓰기 시그니처를 적용할 수 없음",
        "directory operation, content-write signatures do not apply",
    ),
    "unresolved_path": (
        "경로 미해석 — 배경 활동 여부를 배제할 수 없음",
        "path unresolved, background activity cannot be excluded",
    ),
    "permanent_delete_ambiguous": (
        "완전 삭제 — 파일시스템 기록만으로는 행위자 판별 불가",
        "permanent delete, actor not determinable from filesystem alone",
    ),
    "direct_operation_ambiguous": (
        "직접 조작 — 파일시스템 기록만으로는 행위자 판별 불가",
        "direct operation, actor not determinable from filesystem alone",
    ),
    "no_strong_signature": ("뚜렷한 시그니처 없음", "no strong signature"),
    "browser_or_messenger_download": (
        "브라우저·메신저의 다운로드 중 임시 이름",
        "browser/messenger in-progress download marker",
    ),
    "session_log_path_match": (
        "에이전트 세션 로그의 경로 일치",
        "session-log path match",
    ),
    "session_log_basename_match": (
        "에이전트 세션 로그의 파일명 일치",
        "session-log filename match",
    ),
    "session_log_command_match": (
        "에이전트 세션 로그의 명령어 일치",
        "session-log command match",
    ),
    "tool": ("도구", "tool"),
    "signature_service_conflict": (
        "파일시스템 시그니처와 상충",
        "conflicts with the filesystem signature",
    ),
}


def reason_phrase(code: str, language: Language = "en") -> str:
    """Translate an attribution reason code (optionally ``base:detail``)."""
    base, _, detail = code.partition(":")
    phrases = REASON_PHRASES.get(base)
    if phrases is None:
        label = base.replace("_", " ")
    else:
        label = phrases[0] if language == "ko" else phrases[1]
    return f"{label} ({detail})" if detail else label


def behavior_label(code: str, language: Language = "en") -> str:
    labels = BEHAVIOR_LABELS.get(code)
    if labels is None:
        return code
    return labels[0] if language == "ko" else labels[1]


@dataclass(frozen=True, slots=True)
class _Interpretation:
    """What the whole flow means.

    ``action_ko``/``action_en`` are ``str.format`` templates for the headline
    predicate.  They take the target as a placeholder rather than appending it,
    because the target's position differs per verb ("moved {target} to …" vs
    "renamed {target}") and Korean needs a different particle per verb:
    ``{target}`` is the bare noun phrase ("\"x.docx\" 파일"), ``{target_o}`` the
    same phrase with its object particle already attached ("… 파일을").
    """

    key: str
    action_ko: str
    action_en: str
    note_ko: str
    note_en: str


# --------------------------------------------------------------------------- #
# Actor and target wording
# --------------------------------------------------------------------------- #
def _actor_phrase(actor_class: ActorClass, service: str | None) -> tuple[str, str]:
    if actor_class == ActorClass.AI_AGENT:
        if service:
            return f"AI 에이전트({service})가", f"The AI agent ({service})"
        return "AI 에이전트가", "An AI agent"
    if actor_class == ActorClass.HUMAN:
        return "사용자가 직접", "A human user"
    if actor_class == ActorClass.SYSTEM:
        return "운영체제 또는 응용프로그램이", "The OS or an application"
    return "확인되지 않은 주체가", "An undetermined actor"


@dataclass(frozen=True, slots=True)
class _Target:
    """The operated-on item, pre-rendered in every form the templates need."""

    ko: str  # '"report.docx" 파일'
    ko_object: str  # '"report.docx" 파일을'
    ko_topic: str  # '"report.docx" 파일은'
    en: str  # 'the file "report.docx"'


def _target_of(name: str, is_directory: bool | None = None) -> _Target:
    """Build the target phrases for ``name``.

    Placing a Korean noun ("파일"/"폴더") before the particle keeps the particle
    fixed, so a file name ending in any character — Hangul, Latin, digit — still
    reads naturally without per-name particle inflection.  ``is_directory`` comes
    from FILE_ATTRIBUTE_DIRECTORY when known; the extension check is only a
    fallback for names recovered without their attributes.
    """
    folder = is_directory if is_directory is not None else ("." not in name.strip("."))
    if folder:
        noun_ko, obj, topic, noun_en = "폴더", "를", "는", "folder"
    else:
        noun_ko, obj, topic, noun_en = "파일", "을", "은", "file"
    base = f'"{name}" {noun_ko}'
    return _Target(
        ko=base,
        ko_object=f"{base}{obj}",
        ko_topic=f"{base}{topic}",
        en=f'the {noun_en} "{name}"',
    )


def _display_name(op: FileOperation) -> str:
    """The file name to show — original casing where the record preserved it.

    ``op.basename`` comes from the normalized (lower-cased) path, so prefer the
    matching raw ``$FILE_NAME`` entry when there is one.
    """
    basename = op.basename
    if basename:
        for name in op.filenames:
            if name and name.lower() == basename:
                return name
        return basename
    for name in op.filenames:
        if name:
            return name
    return "(이름 미상)"


def _rename_names(op: FileOperation) -> tuple[str | None, str | None]:
    names = [name for name in op.filenames if name]
    if len(names) < 2:
        return None, None
    return names[0], names[-1]


def _directories(op: FileOperation) -> tuple[str, ...]:
    dirs: list[str] = []
    for path in op.paths:
        parent = path.rsplit("/", 1)[0] if "/" in path else ""
        if parent and parent not in dirs:
            dirs.append(parent)
    return tuple(dirs)


# --------------------------------------------------------------------------- #
# Level 1: what does the whole flow mean?
# --------------------------------------------------------------------------- #
def _interpret(op: FileOperation, behavior: str) -> _Interpretation:
    """Recognise the composite pattern the operation forms.

    Ordered most-specific first: a pattern that identifies *how* the write was
    performed (interactive app, atomic replace) outranks the generic behavior
    classification, because that is what actually discriminates the actor.
    """
    reasons = op.reasons
    application = has_app_temp(op)

    if application is not None:
        return _Interpretation(
            "interactive_app_edit",
            "{target_o} " + application + "에서 직접 열어 편집한 뒤 저장했습니다.",
            "opened, edited and saved {target} in " + application,
            f"{application}에서만 만들어지는 임시/잠금 파일이 같은 흐름 안에서 함께 관찰되었습니다. "
            "사람이 데스크톱 응용프로그램의 창을 열어 문서를 편집하고 저장할 때만 남는 흔적입니다.",
            f"Temp/lock files that only {application} creates were observed within the same flow — "
            "a trace left only when a person opens a document in the desktop application, edits it and saves.",
        )

    if has_download_temp(op) and is_user_doc_path(op):
        return _Interpretation(
            "download_completed",
            "{target_o} 웹 브라우저 또는 메신저를 통해 내려받았습니다.",
            "downloaded {target} through a web browser or messenger",
            "전송 중 임시 이름(.crdownload/.part 등)으로 만들어진 뒤 완료 시점에 최종 이름으로 바뀌었습니다. "
            "사람이 다운로드 UI를 조작할 때만 남는 흔적으로, 파일 API로 직접 파일을 쓰는 AI 에이전트는 이 형태를 만들지 않습니다.",
            "It was created under an in-progress name (.crdownload/.part) and renamed to its final name on "
            "completion — a trace left only when a person drives a download UI. An AI agent writing through a file "
            "API never produces this shape.",
        )

    if behavior == "delete_recycle":
        return _Interpretation(
            "recycle_delete",
            "{target_o} 휴지통으로 옮겨 삭제했습니다.",
            "deleted {target} by moving it to the Recycle Bin",
            "파일이 $Recycle.Bin 아래로 이름이 바뀌어 옮겨졌습니다. 데이터 자체는 아직 볼륨에 남아 있어 복구 가능하며, "
            "탐색기에서 Delete 키로 삭제하는 일반적인 방식에 해당합니다. Linux 샌드박스에서 동작하는 에이전트는 이 경로를 사용할 수 없습니다.",
            "The file was renamed into $Recycle.Bin. Its data is still on the volume and recoverable; this is the "
            "ordinary Explorer Delete-key path, which an agent confined to a Linux sandbox cannot use.",
        )

    if has_tmp_rename(op):
        return _Interpretation(
            "atomic_replace",
            "{target_o} 임시 파일에 새 내용을 기록한 뒤 원본과 바꿔치기하는 방식으로 수정했습니다.",
            "rewrote {target} with an atomic temp-file-then-rename replace",
            "새 내용을 별도의 임시(.tmp) 파일에 끝까지 기록한 다음, 원본을 치우고 임시 파일의 이름을 원본 이름으로 바꿨습니다. "
            "중간에 중단되어도 원본이 깨지지 않도록 하는 원자적 저장 방식으로, 파일 API로 안전 저장을 수행하는 "
            "AI 코딩 에이전트에서 전형적으로 관찰되며 사람의 GUI 저장에서는 잘 나타나지 않습니다.",
            "The new contents were written in full to a separate temporary (.tmp) file, then the original was "
            "removed and the temp file renamed over it. This atomic save keeps the original intact if the write is "
            "interrupted; it is characteristic of AI coding agents writing through file APIs, and rarely appears "
            "when a person saves from a GUI editor.",
        )

    if behavior == "delete_permanent":
        return _Interpretation(
            "permanent_delete",
            "{target_o} 휴지통을 거치지 않고 완전히 삭제했습니다.",
            "permanently deleted {target}, bypassing the Recycle Bin",
            "휴지통 경유 흔적 없이 곧바로 삭제되었습니다. Shift+Delete 같은 사용자의 영구 삭제와 프로그램·스크립트의 삭제 호출은 "
            "파일시스템 기록만으로는 구분되지 않으므로, 행위자 판단은 세션 로그 교차분석에 의존합니다.",
            "It was deleted outright with no Recycle Bin stage. A user's Shift+Delete and a program's or script's "
            "delete call are indistinguishable from the filesystem record alone, so the actor call relies on "
            "session-log cross-analysis.",
        )

    if behavior == "copy":
        return _Interpretation(
            "copy_in",
            "{target_o} 다른 위치에서 복사해 왔습니다.",
            "created {target} as a copy of another file",
            "파일이 만들어진 직후 내용이 한 번에 덮어써지고 타임스탬프·속성까지 함께 맞춰졌습니다. "
            "새로 작성한 것이 아니라 기존 파일을 복사해 온 동작입니다. 다만 탐색기 복사·설치 프로그램·에이전트의 복사 호출이 "
            "모두 같은 흔적을 남기므로, 누가 복사했는지는 이 흐름만으로 판단할 수 없습니다.",
            "Right after creation the contents were overwritten in one go and the timestamps/attributes were set to "
            "match — the file was copied rather than authored. Explorer copy/paste, an installer and an agent's copy "
            "call all leave this same trace, so the flow alone does not say who did it.",
        )

    if behavior == "move":
        dirs = _directories(op)
        if len(dirs) >= 2:
            note_ko = f'"{dirs[0]}" 에서 "{dirs[-1]}" 로 옮겨졌습니다. 파일 내용은 그대로이고 상위 디렉터리만 바뀌었습니다.'
            note_en = (
                f'It moved from "{dirs[0]}" to "{dirs[-1]}". The contents are unchanged; only the parent directory differs.'
            )
        else:
            note_ko = "이름 변경 기록의 상위 디렉터리가 서로 달라 이동으로 판단했습니다. 내용 변경은 관찰되지 않았습니다."
            note_en = (
                "The rename records point at different parent directories, so this is a move. No content change was observed."
            )
        return _Interpretation(
            "move",
            "{target_o} 다른 폴더로 이동했습니다.",
            "moved {target} to a different folder",
            note_ko,
            note_en,
        )

    if behavior == "rename":
        old, new = _rename_names(op)
        if old and new:
            note_ko = f'같은 폴더 안에서 이름만 "{old}" → "{new}" 로 바뀌었습니다. 내용 변경은 관찰되지 않았습니다.'
            note_en = f'Only the name changed within the same folder: "{old}" -> "{new}". No content change was observed.'
        else:
            note_ko = "같은 폴더 안에서 이름만 바뀌었습니다. 내용 변경은 관찰되지 않았습니다."
            note_en = "Only the name changed within the same folder. No content change was observed."
        return _Interpretation(
            "rename", "{target}의 이름을 바꿨습니다.", "renamed {target}", note_ko, note_en
        )

    if {"Data_Truncated", "Data_Added", "Data_Overwritten"} <= reasons:
        return _Interpretation(
            "full_rewrite",
            "{target}의 기존 내용을 모두 비운 뒤 통째로 다시 기록했습니다.",
            "truncated {target} and rewrote it end to end",
            "잘라내기 → 덧붙이기 → 덮어쓰기가 한 흐름 안에서 이어졌습니다. 일부만 고친 것이 아니라 파일 전체가 새 내용으로 교체되었으며, "
            "docx·xlsx처럼 압축 컨테이너 형식의 문서를 프로그램이 통째로 다시 저장할 때 나타나는 흐름입니다.",
            "Truncate -> append -> overwrite ran as one flow: the file was replaced wholesale rather than partially "
            "edited. This is how a program re-saves a compressed container document such as .docx or .xlsx.",
        )

    if "File_Created" in reasons:
        if reasons & {"Data_Added", "Data_Overwritten"}:
            return _Interpretation(
                "create_and_write",
                "{target_o} 새로 만들고 내용을 기록했습니다.",
                "created {target} and wrote its contents",
                "파일 생성 직후 같은 흐름 안에서 데이터가 기록되었습니다. 빈 파일만 만들어 둔 것이 아니라 실제 내용이 저장되었습니다.",
                "Data was written in the same flow immediately after creation — an actual authored file, not an empty placeholder.",
            )
        return _Interpretation(
            "create_only",
            "{target_o} 새로 만들었습니다(내용 기록은 관찰되지 않음).",
            "created {target}, with no content write observed",
            "생성 기록만 있고 데이터 기록 이유가 뒤따르지 않았습니다. 빈 파일·자리 표시자이거나, 내용 기록 부분이 저널에서 이미 밀려났을 수 있습니다.",
            "Only a create record appears, with no data-write reason following. Either an empty placeholder, or the "
            "write records have already wrapped out of the journal.",
        )

    data_reasons = reasons & {"Data_Added", "Data_Overwritten", "Data_Truncated"}
    if data_reasons == {"Data_Added"}:
        return _Interpretation(
            "append",
            "{target}의 기존 내용 뒤에 데이터를 덧붙였습니다.",
            "appended data to {target}",
            "기존 내용을 그대로 둔 채 파일 끝에 데이터가 추가되었습니다. 로그 기록이나 이어쓰기에서 나타나는 형태입니다.",
            "Data was added at the end while the existing contents were left in place — the shape of log writing or an append.",
        )
    if data_reasons == {"Data_Overwritten"}:
        return _Interpretation(
            "overwrite_in_place",
            "{target}의 기존 내용 일부를 제자리에서 덮어썼습니다.",
            "overwrote part of {target} in place",
            "파일 크기 변화 없이 기존 영역이 덮어써졌습니다. 전체 재작성이 아니라 부분 수정에 해당합니다.",
            "Existing regions were overwritten without a size change — a partial edit rather than a full rewrite.",
        )
    if data_reasons == {"Data_Truncated"}:
        return _Interpretation(
            "truncate",
            "{target}의 내용을 잘라내 크기를 줄였습니다.",
            "truncated {target}, reducing its size",
            "새 데이터 기록 없이 파일이 잘렸습니다. 내용 비우기이거나, 이어질 재작성의 앞부분만 저널에 남은 경우일 수 있습니다.",
            "The file was truncated with no following data write — a clearing, or only the first half of a rewrite still in the journal.",
        )
    if data_reasons:
        return _Interpretation(
            "modify",
            "{target}의 내용을 수정했습니다.",
            "modified the contents of {target}",
            "데이터 영역이 변경되었습니다. 다만 흐름이 특정 응용프로그램·에이전트의 저장 패턴과 일치하지는 않습니다.",
            "The data area changed, but the flow does not match any specific application or agent save pattern.",
        )

    if reasons and reasons <= {"Basic_Info_Changed", "File_Closed"}:
        return _Interpretation(
            "timestamp_only",
            "{target}의 내용은 건드리지 않고 타임스탬프·속성만 변경했습니다.",
            "changed only the timestamps/attributes of {target}, leaving its contents untouched",
            "데이터 기록 이유 없이 $STANDARD_INFORMATION 계열 정보만 변경되었습니다. 백업·동기화 도구의 정상적인 속성 변경일 수도 있으나, "
            "시간 정보를 위조하는 타임스탬프 조작(timestomping) 가능성도 함께 검토해야 합니다.",
            "Only $STANDARD_INFORMATION-class fields changed, with no data-write reason. This can be a backup or sync "
            "tool touching attributes, but timestamp forgery (timestomping) should also be considered.",
        )

    if reasons and reasons <= {"Access_Right_Changed", "File_Closed"}:
        return _Interpretation(
            "security_only",
            "{target}의 접근 권한(ACL)만 변경했습니다.",
            "changed only the access rights (ACL) of {target}",
            "파일 내용은 그대로이고 보안 기술자만 바뀌었습니다. 권한 상승이나 접근 차단·개방 목적의 조작일 수 있습니다.",
            "The contents are unchanged; only the security descriptor was modified — possibly to widen or restrict access.",
        )

    return _Interpretation(
        "metadata_change",
        "{target}의 메타데이터를 변경했습니다.",
        "changed the metadata of {target}",
        "내용 변경 없이 속성·부가 정보만 바뀌었습니다. 단독으로는 의미를 특정하기 어려워 전후 이벤트와 함께 판단해야 합니다.",
        "Attributes or ancillary information changed without a content change. On its own this is not conclusive; read "
        "it together with the surrounding events.",
    )


# --------------------------------------------------------------------------- #
# Level 2: narrate the individual steps
# --------------------------------------------------------------------------- #
_MAX_STEPS = 10


def _flow_steps(op: FileOperation) -> tuple[tuple[str, str], ...]:
    """Narrate the reason flow in order, collapsing the rename old/new pair."""
    flow = tuple(op.reason_flow)
    rename_pair = "File_Renamed_Old" in flow and "File_Renamed_New" in flow
    old, new = _rename_names(op) if rename_pair else (None, None)
    steps: list[tuple[str, str]] = []
    rename_done = False
    previous: str | None = None
    for reason in flow:
        if reason == previous:
            continue  # the same reason repeating adds nothing to the story
        previous = reason
        if rename_pair and reason in {"File_Renamed_Old", "File_Renamed_New"}:
            if rename_done:
                continue
            rename_done = True
            if old and new:
                steps.append(
                    (f'이름이 바뀌었습니다: "{old}" → "{new}"', f'it was renamed: "{old}" -> "{new}"')
                )
            else:
                steps.append(("이름이 바뀌었습니다", "it was renamed"))
            continue
        steps.append(_STEP_PHRASES.get(reason, (reason.replace("_", " "), reason.replace("_", " "))))
    return tuple(steps[:_MAX_STEPS])


def _duration_phrase(op: FileOperation) -> tuple[str, str] | None:
    seconds = (op.end - op.start).total_seconds()
    if seconds < 0.5:
        return None
    if seconds < 60:
        return f"{seconds:.1f}초", f"{seconds:.1f} seconds"
    minutes = seconds / 60
    return f"{minutes:.1f}분", f"{minutes:.1f} minutes"


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def describe_operation(
    op: FileOperation,
    *,
    actor_class: ActorClass,
    behavior: str,
    service: str | None = None,
    reasons: tuple[str, ...] = (),
    matched_tool: str | None = None,
    matched_session: str | None = None,
) -> Narrative:
    """Interpret one reconstructed file operation as a bilingual narrative."""
    interpretation = _interpret(op, behavior)
    actor_ko, actor_en = _actor_phrase(actor_class, service)
    target = _target_of(_display_name(op), op.is_directory)

    headline_ko = (
        f"{actor_ko} "
        + interpretation.action_ko.format(target=target.ko, target_o=target.ko_object)
    )
    headline_en = f"{actor_en} " + interpretation.action_en.format(target=target.en) + "."

    detail_ko = [f"해석: {interpretation.note_ko}"]
    detail_en = [f"Interpretation: {interpretation.note_en}"]

    steps = _flow_steps(op)
    if steps:
        detail_ko.append("관찰된 순서: " + " → ".join(step[0] for step in steps))
        detail_en.append("Observed sequence: " + " -> ".join(step[1] for step in steps))

    duration = _duration_phrase(op)
    if duration is not None:
        detail_ko.append(f"소요 시간: {duration[0]}")
        detail_en.append(f"Duration: {duration[1]}")

    if reasons:
        detail_ko.append("근거: " + ", ".join(reason_phrase(code, "ko") for code in reasons))
        detail_en.append("Evidence: " + ", ".join(reason_phrase(code, "en") for code in reasons))

    if matched_tool or matched_session:
        tool = matched_tool or "(도구 미상)"
        session = matched_session or "-"
        detail_ko.append(
            f"교차 확인: 같은 시각 {service or 'AI 에이전트'} 세션 로그의 '{tool}' 도구 호출과 일치합니다 (세션 {session})."
        )
        detail_en.append(
            f"Cross-check: it matches a '{matched_tool or 'unknown'}' tool call in the "
            f"{service or 'AI agent'} session log at the same time (session {session})."
        )

    return Narrative(
        headline_ko=headline_ko,
        headline_en=headline_en,
        detail_ko=tuple(detail_ko),
        detail_en=tuple(detail_en),
        key=interpretation.key,
    )


def summarize_file(
    *,
    display_name: str,
    actor_class: ActorClass,
    service: str | None,
    narratives: tuple[Narrative, ...] = (),
    behaviors: tuple[str, ...] = (),
    mft_count: int = 0,
    logfile_count: int = 0,
    logfile_operations: tuple[str, ...] = (),
    matched_service: str | None = None,
    is_directory: bool | None = None,
) -> Narrative:
    """Roll every operation on one file/folder up into a single interpretation.

    With no USN operations at all — the file survives only in ``$MFT`` or
    ``$LogFile`` because its journal history has wrapped — this still states what
    *can* be said, rather than leaving the entry blank.
    """
    actor_ko, actor_en = _actor_phrase(actor_class, service)
    target = _target_of(display_name, is_directory)

    if len(narratives) == 1:
        base = narratives[0]
        return _with_recovery_note(base, mft_count, logfile_count)

    if narratives:
        chain_ko = " → ".join(
            dict.fromkeys(behavior_label(code, "ko") for code in behaviors)
        ) or "여러 작업"
        chain_en = " -> ".join(
            dict.fromkeys(behavior_label(code, "en") for code in behaviors)
        ) or "several operations"
        headline_ko = (
            f"{actor_ko} {target.ko_object} 대상으로 "
            f"{len(narratives)}건의 작업을 수행했습니다: {chain_ko}."
        )
        headline_en = (
            f"{actor_en} performed {len(narratives)} operations on {target.en}: {chain_en}."
        )
        detail_ko = [f"{index}. {item.headline_ko}" for index, item in enumerate(narratives, start=1)]
        detail_en = [f"{index}. {item.headline_en}" for index, item in enumerate(narratives, start=1)]
        return _with_recovery_note(
            Narrative(headline_ko, headline_en, tuple(detail_ko), tuple(detail_en), key="multi_operation"),
            mft_count,
            logfile_count,
        )

    # No USN operations: describe what the recovery artifacts alone support.
    recovered_ko = [label for label, count in (("$MFT", mft_count), ("$LogFile", logfile_count)) if count]
    where_ko = " · ".join(recovered_ko) or "다른 아티팩트"
    operations = tuple(dict.fromkeys(logfile_operations))
    if operations:
        ops_ko = ", ".join(behavior_label(op, "ko") if op in BEHAVIOR_LABELS else op for op in operations)
        ops_en = ", ".join(operations)
        op_note_ko = f" $LogFile 인덱스 기록상 관찰된 동작은 {ops_ko} 입니다."
        op_note_en = f" The index records in $LogFile show: {ops_en}."
    else:
        op_note_ko = ""
        op_note_en = ""

    if matched_service:
        headline_ko = (
            f"{target.ko_topic} USN 저널에서는 사라졌지만 {where_ko}에 흔적이 남아 있으며, "
            f"{matched_service} 세션 로그의 동일 경로 기록과 일치합니다."
        )
        headline_en = (
            f"{target.en[0].upper() + target.en[1:]} no longer appears in the USN journal, but "
            f"survives in {where_ko}, and matches a same-path record in the "
            f"{matched_service} session log."
        )
        note_ko = (
            "USN 저널이 순환 기록으로 덮어써져 조작 이력 자체는 남지 않았습니다. 그러나 파일의 존재와 "
            "$FILE_NAME 타임스탬프가 남아 있고, 에이전트 세션 로그가 같은 경로를 기록하고 있어 "
            "해당 에이전트가 이 파일을 다뤘다고 볼 수 있습니다." + op_note_ko
        )
        note_en = (
            "The USN journal has wrapped, so the operation history itself is gone. The file's existence and its "
            "$FILE_NAME timestamps remain, and the agent session log records the same path — supporting the reading "
            "that this agent handled the file." + op_note_en
        )
        key = "recovered_with_session_match"
    else:
        headline_ko = (
            f"{target.ko_topic} {where_ko}에서만 복구되었습니다 — "
            "어떤 작업이 있었는지는 파일시스템 기록만으로 판단할 수 없습니다."
        )
        headline_en = (
            f"{target.en[0].upper() + target.en[1:]} was recovered from {where_ko} only — "
            "what was done to it cannot be determined from the filesystem records alone."
        )
        note_ko = (
            "USN 저널에 해당 파일의 조작 이력이 남아 있지 않습니다(순환 기록으로 덮어써졌거나 저널이 초기화된 경우). "
            "파일이 존재했다는 사실과 $FILE_NAME 타임스탬프는 확인되지만, 누가 무엇을 했는지는 확정할 수 없습니다." + op_note_ko
        )
        note_en = (
            "No operation history for this file remains in the USN journal (wrapped or reset). Its existence and "
            "$FILE_NAME timestamps are confirmed, but who did what to it cannot be established." + op_note_en
        )
        key = "recovered_only"

    return Narrative(headline_ko, headline_en, (f"해석: {note_ko}",), (f"Interpretation: {note_en}",), key=key)


def _with_recovery_note(base: Narrative, mft_count: int, logfile_count: int) -> Narrative:
    """Append the corroborating-artifact line to an operation-backed narrative."""
    extras = [label for label, count in (("$MFT", mft_count), ("$LogFile", logfile_count)) if count]
    if not extras:
        return base
    joined = " · ".join(extras)
    return Narrative(
        headline_ko=base.headline_ko,
        headline_en=base.headline_en,
        detail_ko=base.detail_ko + (f"보강: {joined} 기록에서도 같은 파일이 확인되어 USN 판단을 뒷받침합니다.",),
        detail_en=base.detail_en + (f"Corroboration: the same file also appears in {joined}, supporting the USN reading.",),
        key=base.key,
    )
