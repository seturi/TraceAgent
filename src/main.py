import sys

from app import main

# On Korean-locale Windows the console defaults to cp949, so printing a
# traceback or log line that contains non-cp949 text (e.g. a path with Korean
# characters) itself raises UnicodeEncodeError and masks the real message.
# Force UTF-8 on the standard streams so console output never fails to encode.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


if __name__ == "__main__":
    raise SystemExit(main())
