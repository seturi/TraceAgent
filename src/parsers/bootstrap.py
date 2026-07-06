from parsers.antigravity import AntigravityParser
from parsers.chatgpt import ChatGPTParser
from parsers.claude_code import ClaudeCodeParser
from parsers.claude_cowork import ClaudeCoworkParser
from parsers.codex import CodexParser
from parsers.ntfs.logfile import NtfsLogFileParser
from parsers.ntfs.mft import NtfsMftParser
from parsers.ntfs.usn import NtfsUsnParser
from parsers.registry import ParserRegistry


def create_default_parser_registry() -> ParserRegistry:
    """Create the parser set exposed by the desktop application."""
    return ParserRegistry(
        (
            ClaudeCodeParser(),
            ClaudeCoworkParser(),
            ChatGPTParser(),
            AntigravityParser(),
            CodexParser(),
            NtfsUsnParser(),
            NtfsLogFileParser(),
            NtfsMftParser(),
        )
    )
