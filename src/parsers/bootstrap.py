from parsers.claude_code import ClaudeCodeParser
from parsers.registry import ParserRegistry


def create_default_parser_registry() -> ParserRegistry:
    """Create the parser set exposed by the desktop application."""
    return ParserRegistry((ClaudeCodeParser(),))
