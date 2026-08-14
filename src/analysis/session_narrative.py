"""Plain-language (English/Korean) interpretation of AI-agent session evidence.

The Local artifacts screen reconstructs a conversation faithfully — prompt,
reasoning, tool call, tool result — but a reviewer still has to translate
``claude_tool_call / Write / {"file_path": "...\\test.txt"}`` in their head into
"the agent wrote this file".  This module does that translation, at two levels:

``describe_event``
    One parsed event -> one sentence naming *the actor* and *what they did*,
    with the concrete object (file, command, query) they did it to.
``summarize_session``
    Every event of one session rolled up into a headline — "the user and the AI
    agent carried out 5 operations: prompt -> file write -> shell command" —
    followed by the numbered steps behind it.

Two deliberate restraints, for the same reason the NTFS narrator states what a
USN flow *means* rather than which bits it set:

* A session log records that a write tool ran, not that the file came into
  existence, so a ``Write`` is narrated as "wrote", never "created".  Creation
  is an NTFS finding (``File_Created``), and only :mod:`analysis.ntfs.narrative`
  is entitled to claim it.
* The actor comes from the record's own ``actor`` field, not from what the tool
  usually implies — a tool call inside a transcript the user pasted is still
  attributed to whoever the parser said produced it.

Kept free of any Qt dependency so the wording can be unit-tested.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from analysis.narrative_common import Narrative
from core.models import NormalizedEvent

# Behavior code -> short (Korean, English) label, used when chaining several
# steps into one session headline.
BEHAVIOR_LABELS: dict[str, tuple[str, str]] = {
    "prompt": ("프롬프트 입력", "prompt"),
    "reply": ("에이전트 응답", "agent reply"),
    "reasoning": ("내부 추론", "internal reasoning"),
    "file_read": ("파일 읽기", "file read"),
    "file_write": ("파일 작성", "file write"),
    "file_edit": ("파일 수정", "file edit"),
    "file_delete": ("파일 삭제", "file delete"),
    "shell": ("명령 실행", "shell command"),
    "search": ("검색", "search"),
    "web": ("웹 접근", "web access"),
    "plan": ("계획 갱신", "plan update"),
    "subagent": ("하위 에이전트 작업", "sub-agent task"),
    "mcp": ("MCP 도구 호출", "MCP tool call"),
    "tool_call": ("도구 호출", "tool call"),
    "tool_result": ("도구 결과", "tool result"),
    "log": ("애플리케이션 로그", "application log"),
    "record": ("기록", "record"),
}

_FILE_BEHAVIORS = ("file_read", "file_write", "file_edit", "file_delete")

# Tool name -> behavior.  Every name here is one a parser in this project
# actually emits: Claude Code/Cowork pass the raw ``tool_use`` block name
# (Read/Write/Edit/Bash/...), Codex passes either a function-call name or an
# ``event_msg`` tool family (exec_command/patch/mcp_tool_call/web_search — see
# ``parsers.codex._TOOL_FAMILY_HINTS``), and Antigravity passes its brain step
# type (WRITE_FILE/RUN_COMMAND/... — see ``parsers.antigravity._ACTION_TYPES``).
_TOOL_BEHAVIORS: dict[str, str] = {
    "read": "file_read",
    "read_file": "file_read",
    "read_many_files": "file_read",
    "notebookread": "file_read",
    "view": "file_read",
    "view_image": "file_read",
    "write": "file_write",
    "write_file": "file_write",
    "create_file": "file_write",
    "create": "file_write",
    "edit": "file_edit",
    "edit_file": "file_edit",
    "multiedit": "file_edit",
    "notebookedit": "file_edit",
    "str_replace": "file_edit",
    "str_replace_editor": "file_edit",
    "apply_patch": "file_edit",
    "patch": "file_edit",
    "code_action": "file_edit",
    "delete": "file_delete",
    "delete_file": "file_delete",
    "remove": "file_delete",
    "bash": "shell",
    "bashoutput": "shell",
    "killshell": "shell",
    "shell": "shell",
    "exec": "shell",
    "exec_command": "shell",
    "command": "shell",
    "run_command": "shell",
    "run_terminal_cmd": "shell",
    "terminal": "shell",
    "glob": "search",
    "grep": "search",
    "search": "search",
    "find": "search",
    "ls": "search",
    "list_directory": "search",
    "codebase_search": "search",
    "webfetch": "web",
    "websearch": "web",
    "web_search": "web",
    "fetch": "web",
    "browser_action": "web",
    "todowrite": "plan",
    "update_plan": "plan",
    "exitplanmode": "plan",
    "task": "subagent",
    "agent": "subagent",
    "dispatch_agent": "subagent",
    "mcp_tool_call": "mcp",
}

# Checked only after an exact match fails, so "todowrite" stays a plan update
# instead of matching the "write" fragment.  Order is significance, not length:
# a name containing both "write" and "read" is a write.
_TOOL_FRAGMENTS: tuple[tuple[str, str], ...] = (
    ("patch", "file_edit"),
    ("edit", "file_edit"),
    ("replace", "file_edit"),
    ("delete", "file_delete"),
    ("write", "file_write"),
    ("create", "file_write"),
    ("read", "file_read"),
    ("exec", "shell"),
    ("shell", "shell"),
    ("bash", "shell"),
    ("command", "shell"),
    ("terminal", "shell"),
    ("browser", "web"),
    ("web", "web"),
    ("http", "web"),
    ("fetch", "web"),
    ("search", "search"),
    ("grep", "search"),
    ("glob", "search"),
    ("list", "search"),
    ("plan", "plan"),
    ("todo", "plan"),
    ("agent", "subagent"),
)

# `apply_patch` carries its target in the patch header rather than in a path
# field, e.g. "*** Update File: src/app.py".  Verified against real Codex
# `event_msg.patch_apply_begin` records, whose `changes` text starts this way.
_PATCH_FILE_PATTERN = re.compile(
    r"\*\*\*\s*(?:Add|Update|Delete|Move)\s+File:\s*(?P<path>[^\r\n]+)"
)
# A last-resort path grab from free text: a drive-letter path, or a
# separator-joined name with a short extension.  Deliberately conservative —
# a wrong file name in a forensic narrative is worse than none.
_PATH_LIKE_PATTERN = re.compile(
    r"[A-Za-z]:[\\/][^\s\"'|,;]+|(?:[\w.\-]+[\\/])+[\w.\-]+\.\w{1,8}"
)

# A step names the action and the thing it acted on, then stops: the object is
# quoted inside the sentence rather than appended after it, and the output the
# action produced is not narrated at all.  The conversation timeline beside the
# panel is where a reviewer reads content; this panel is the index over it.
_OBJECT_LIMIT = 60  # characters of the quoted command/query inside a sentence
_MAX_STEPS = 12  # numbered steps shown before the roll-up says "and N more"
_MAX_CHAIN = 6  # behaviors named in the headline chain
_MAX_FILES = 8  # files named in the "files touched" line

# Records that only report the aftermath of an action — a tool's output, an
# application log line.  Still narratable one at a time in the event inspector,
# but never a step of their own in a session roll-up.
_AFTERMATH_BEHAVIORS = frozenset({"tool_result", "log"})


@dataclass(frozen=True, slots=True)
class _Step:
    """One interpreted event: its sentence, its behavior, and what it touched."""

    narrative: Narrative
    behavior: str
    file_target: str | None


def behavior_label(code: str, language: str = "en") -> str:
    labels = BEHAVIOR_LABELS.get(code)
    if labels is None:
        return code
    return labels[0] if language == "ko" else labels[1]


def event_kind(event: NormalizedEvent) -> str:
    """Classify a local-artifact event into a display kind.

    Shared with the UI (which adds its own marker per kind) so the conversation
    view and this interpretation can never disagree about what an event is.
    """
    event_type = (event.event_type or "").lower()
    actor = (event.actor or "").lower()
    if "log" in event_type:
        return "log"
    if (
        "tool_result" in event_type
        or "function_call_output" in event_type
        or "custom_tool_call_output" in event_type
        or "tool-result" in event_type
    ):
        return "result"
    if "tool_use" in event_type or "tool_call" in event_type or (
        "function_call" in event_type and "output" not in event_type
    ):
        return "tool"
    if "thinking" in event_type or "reasoning" in event_type:
        return "thinking"
    if actor == "user" or "user" in event_type or "prompt" in event_type:
        return "prompt"
    if actor == "assistant" or "assistant" in event_type or "message" in event_type:
        return "message"
    return "event"


def describe_event(event: NormalizedEvent) -> Narrative:
    """Interpret one session record as a bilingual sentence."""
    return _interpret_event(event).narrative


def summarize_session(
    *,
    service: str,
    events: tuple[NormalizedEvent, ...],
    hidden_count: int = 0,
) -> Narrative:
    """Roll one session's events up into a headline plus numbered steps.

    ``events`` is the list the reviewer is actually looking at, already filtered
    by the screen's low-signal policy; ``hidden_count`` is what that policy held
    back, stated in the output so the interpretation never reads as if it
    covered records it never saw.
    """
    if not events:
        return _empty_session(service, hidden_count)

    steps: list[list] = []  # [_Step, repeat count], collapsed while walking
    behaviors: list[str] = []
    files: list[str] = []
    has_user = False
    has_agent = False
    actions = 0
    for event in events:
        step = _interpret_event(event)
        actor = (event.actor or "").lower()
        if step.behavior == "prompt" or actor == "user":
            has_user = True
        elif actor in {"assistant", "model", "agent"} or step.behavior != "log":
            has_agent = True
        if step.file_target and step.file_target not in files:
            files.append(step.file_target)
        # A tool's output and an application log are the trace an action left
        # behind, not an action of their own — they would double the step count
        # while adding nothing about who did what.
        if step.behavior in _AFTERMATH_BEHAVIORS:
            continue
        actions += 1
        behaviors.append(step.behavior)
        # Collapse only sentences that are word-for-word identical, so a run of
        # reasoning steps folds into one line while two writes to different
        # files stay separate.
        if steps and steps[-1][0].narrative.headline_en == step.narrative.headline_en:
            steps[-1][1] += 1
            continue
        steps.append([step, 1])

    if not steps:
        return _empty_session(service, hidden_count)

    subject_en, subject_ko = _session_subject(service, has_user, has_agent)
    chain = list(dict.fromkeys(behaviors))[:_MAX_CHAIN]
    chain_en = " -> ".join(behavior_label(code, "en") for code in chain)
    chain_ko = " → ".join(behavior_label(code, "ko") for code in chain)
    if len(dict.fromkeys(behaviors)) > _MAX_CHAIN:
        chain_en += " -> …"
        chain_ko += " → …"

    headline_en = (
        f"In this {service} session, {subject_en} carried out "
        f"{actions} operations: {chain_en}."
    )
    headline_ko = (
        f"이 세션({service})에서 {subject_ko} "
        f"{actions}건의 작업을 수행했습니다: {chain_ko}."
    )

    detail_en: list[str] = []
    detail_ko: list[str] = []
    for index, (step, repeat) in enumerate(steps[:_MAX_STEPS], start=1):
        suffix_en = f" (×{repeat})" if repeat > 1 else ""
        suffix_ko = f" ({repeat}회)" if repeat > 1 else ""
        detail_en.append(f"{index}. {step.narrative.headline_en}{suffix_en}")
        detail_ko.append(f"{index}. {step.narrative.headline_ko}{suffix_ko}")
    if len(steps) > _MAX_STEPS:
        remaining = len(steps) - _MAX_STEPS
        detail_en.append(f"… and {remaining} more step(s); see the conversation timeline.")
        detail_ko.append(f"… 외 {remaining}단계가 더 있습니다. 대화 타임라인에서 확인하세요.")
    if files:
        shown = files[:_MAX_FILES]
        more_en = f" (+{len(files) - len(shown)} more)" if len(files) > len(shown) else ""
        more_ko = f" (외 {len(files) - len(shown)}건)" if len(files) > len(shown) else ""
        detail_en.append(f"· Files touched ({len(files)}): {', '.join(shown)}{more_en}")
        detail_ko.append(f"· 조작된 파일 {len(files)}건: {', '.join(shown)}{more_ko}")
    if hidden_count:
        detail_en.append(
            f"· {hidden_count} low-signal record(s) are filtered out of this interpretation."
        )
        detail_ko.append(f"· 저신호 기록 {hidden_count}건은 이 해석에서 제외되었습니다.")

    return Narrative(
        headline_ko=headline_ko,
        headline_en=headline_en,
        detail_ko=tuple(detail_ko),
        detail_en=tuple(detail_en),
        key="session_summary",
    )


# --------------------------------------------------------------------------- #
# Event-level interpretation
# --------------------------------------------------------------------------- #
def _interpret_event(event: NormalizedEvent) -> _Step:
    behavior = _behavior_of(event)
    actor_en, actor_ko = _actor_phrase(event)
    service = event.service or "the agent"
    tool = (event.tool_name or "").strip()
    file_target = _file_target(event) if behavior in _FILE_BEHAVIORS else None

    if behavior == "prompt":
        en = f"{actor_en} sent a prompt to {service}."
        ko = f"{actor_ko} {service}에 프롬프트를 입력했습니다."
    elif behavior == "reply":
        en = f"{actor_en} replied."
        ko = f"{actor_ko} 응답했습니다."
    elif behavior == "reasoning":
        en = f"{actor_en} reasoned internally."
        ko = f"{actor_ko} 내부 추론을 수행했습니다."
    elif behavior in _FILE_BEHAVIORS:
        en, ko = _file_sentence(behavior, actor_en, actor_ko, file_target)
    elif behavior == "shell":
        command = _oneline(event.command or event.result, _OBJECT_LIMIT)
        if command:
            en = f'{actor_en} ran the command "{command}".'
            ko = f'{actor_ko} "{command}" 명령을 실행했습니다.'
        else:
            en = f"{actor_en} ran a shell command."
            ko = f"{actor_ko} 셸 명령을 실행했습니다."
    elif behavior == "search":
        query = _oneline(event.command or event.path, _OBJECT_LIMIT)
        if query:
            en = f'{actor_en} searched for "{query}".'
            ko = f'{actor_ko} "{query}" 조건으로 검색했습니다.'
        else:
            en = f"{actor_en} searched the workspace."
            ko = f"{actor_ko} 작업 공간을 검색했습니다."
    elif behavior == "web":
        target = _oneline(event.command or event.path, _OBJECT_LIMIT)
        if target:
            en = f'{actor_en} accessed "{target}".'
            ko = f'{actor_ko} "{target}" 주소에 접근했습니다.'
        else:
            en = f"{actor_en} accessed the web."
            ko = f"{actor_ko} 웹에 접근했습니다."
    elif behavior == "plan":
        en = f"{actor_en} updated its task plan."
        ko = f"{actor_ko} 작업 계획을 갱신했습니다."
    elif behavior == "subagent":
        en = f"{actor_en} delegated work to a sub-agent."
        ko = f"{actor_ko} 하위 에이전트에 작업을 위임했습니다."
    elif behavior == "mcp" and tool.lower() in {"mcp", "mcp_tool_call"}:
        # Codex records only the tool *family* for MCP calls, so there is no
        # individual tool name to quote.
        en = f"{actor_en} called an MCP tool."
        ko = f"{actor_ko} MCP 도구를 호출했습니다."
    elif behavior == "mcp":
        _, name = _mcp_names(tool)
        en = f'{actor_en} called the MCP tool "{name}".'
        ko = f'{actor_ko} MCP "{name}" 도구를 호출했습니다.'
    elif behavior == "tool_call":
        name = tool or "unnamed"
        en = f'{actor_en} called the "{name}" tool.'
        ko = f'{actor_ko} "{name}" 도구를 호출했습니다.'
    elif behavior == "tool_result":
        # Never str.capitalize() here — it would lower-case the tool's own name.
        subject_en = f'The "{tool}" tool' if tool else "A tool"
        subject_ko = f'"{tool}" 도구가' if tool else "도구가"
        en = f"{subject_en} returned its output."
        ko = f"{subject_ko} 결과를 반환했습니다."
    elif behavior == "log":
        en = f"{actor_en} recorded a log entry."
        ko = f"{actor_ko} 로그를 기록했습니다."
    else:
        en = f'{actor_en} left a "{event.event_type}" record.'
        ko = f'{actor_ko} "{event.event_type}" 기록을 남겼습니다.'

    return _Step(
        narrative=Narrative(headline_ko=ko, headline_en=en, key=behavior),
        behavior=behavior,
        file_target=file_target,
    )


def _behavior_of(event: NormalizedEvent) -> str:
    kind = event_kind(event)
    if kind == "prompt":
        return "prompt"
    if kind == "thinking":
        return "reasoning"
    if kind == "log":
        return "log"
    if kind == "result":
        return "tool_result"
    if kind == "tool":
        return _behavior_for_tool(event.tool_name)
    # Antigravity records an action as a normal assistant step whose type is the
    # action itself (WRITE_FILE, RUN_COMMAND, ...), so a named tool on an
    # otherwise plain message still describes a tool call, not a reply.
    if event.tool_name:
        return _behavior_for_tool(event.tool_name)
    if kind == "message":
        return "reply"
    return "record"


def _behavior_for_tool(tool_name: str | None) -> str:
    name = (tool_name or "").strip().lower()
    if not name:
        return "tool_call"
    if name.startswith("mcp__") or name.startswith("mcp_"):
        return _TOOL_BEHAVIORS.get(name, "mcp")
    behavior = _TOOL_BEHAVIORS.get(name)
    if behavior is not None:
        return behavior
    # Codex prefixes some families ("step_type:WRITE_FILE"), and agents namespace
    # their tools ("functions.read_file") — match on the fragments too.
    for fragment, fragment_behavior in _TOOL_FRAGMENTS:
        if fragment in name:
            return fragment_behavior
    return "tool_call"


def _file_sentence(
    behavior: str,
    actor_en: str,
    actor_ko: str,
    file_target: str | None,
) -> tuple[str, str]:
    """Word a file operation: who acted, on which file, and nothing further."""
    target_en = f'the file "{file_target}"' if file_target else "a file"
    target_ko = f'"{file_target}" 파일을' if file_target else "파일을"
    verbs = {
        # "wrote", never "created": the session log proves the write tool ran,
        # not that the file did not exist beforehand.
        "file_write": ("wrote", "작성했습니다"),
        "file_edit": ("modified", "수정했습니다"),
        "file_read": ("read", "읽었습니다"),
        "file_delete": ("deleted", "삭제했습니다"),
    }
    verb_en, verb_ko = verbs[behavior]
    return (
        f"{actor_en} {verb_en} {target_en}.",
        f"{actor_ko} {target_ko} {verb_ko}.",
    )


def _actor_phrase(event: NormalizedEvent) -> tuple[str, str]:
    """(English, Korean) subject phrase, taken from the record's own actor."""
    actor = (event.actor or "").lower()
    service = event.service
    if actor == "user":
        return "The user", "사용자가 직접"
    if actor in {"assistant", "model", "agent"}:
        if service:
            return f"The AI agent ({service})", f"AI 에이전트({service})가"
        return "The AI agent", "AI 에이전트가"
    if actor == "tool":
        return "The tool", "도구가"
    if actor == "system":
        return "The OS or an application", "운영체제 또는 응용프로그램이"
    # No actor recorded: a session artifact is still the product's own log, so
    # name the product rather than claiming an undetermined actor.  The Korean
    # side appends a noun so the subject particle stays fixed whatever the
    # service name ends in — the same device _target_of uses for file names.
    if service:
        return service, f"{service} 애플리케이션이"
    return "An undetermined actor", "확인되지 않은 주체가"


def _mcp_names(tool: str) -> tuple[str | None, str]:
    """Split an ``mcp__<server>__<tool>`` name into its readable halves."""
    if not tool:
        return None, "unnamed"
    parts = [part for part in tool.split("__") if part]
    if len(parts) >= 3 and parts[0].lower() == "mcp":
        return parts[1], "__".join(parts[2:])
    return None, tool


def _file_target(event: NormalizedEvent) -> str | None:
    """The file name the operation acted on, in its original casing."""
    for candidate in (event.path, _path_from_text(event.command), _path_from_text(event.result)):
        name = _basename(candidate)
        if name:
            return name
    return None


def _path_from_text(text: str | None) -> str | None:
    if not text:
        return None
    patch = _PATCH_FILE_PATTERN.search(text)
    if patch is not None:
        return patch.group("path").strip()
    match = _PATH_LIKE_PATTERN.search(text)
    return match.group(0) if match is not None else None


def _basename(path: str | None) -> str | None:
    """Last component of a path, without lower-casing it for display."""
    if not path:
        return None
    cleaned = str(path).strip().strip("\"'").rstrip("\\/")
    if not cleaned:
        return None
    for separator in ("\\", "/"):
        cleaned = cleaned.rsplit(separator, 1)[-1]
    return cleaned or None


def _session_subject(service: str, has_user: bool, has_agent: bool) -> tuple[str, str]:
    agent_en = f"the AI agent ({service})"
    agent_ko = f"AI 에이전트({service})가"
    if has_user and has_agent:
        return f"the user and {agent_en}", f"사용자와 AI 에이전트({service})가"
    if has_agent:
        return agent_en, agent_ko
    if has_user:
        return "the user", "사용자가 직접"
    return "an undetermined actor", "확인되지 않은 주체가"


def _empty_session(service: str, hidden_count: int) -> Narrative:
    detail_en: tuple[str, ...] = ()
    detail_ko: tuple[str, ...] = ()
    if hidden_count:
        detail_en = (
            f"· {hidden_count} low-signal record(s) are filtered out of this interpretation.",
        )
        detail_ko = (f"· 저신호 기록 {hidden_count}건은 이 해석에서 제외되었습니다.",)
    return Narrative(
        headline_ko=f"이 세션({service})에는 해석할 수 있는 활동이 없습니다.",
        headline_en=f"This {service} session contains no interpretable activity.",
        detail_ko=detail_ko,
        detail_en=detail_en,
        key="session_empty",
    )


def _oneline(text: object, limit: int) -> str:
    if not text:
        return ""
    collapsed = " ".join(str(text).split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"