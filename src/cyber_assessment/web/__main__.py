"""Start the local-only Flask application."""

from __future__ import annotations

from . import create_app

WEB_HOST = "127.0.0.1"
WEB_PORT = 5000


def main() -> None:
    app = create_app()
    app.run(
        host=WEB_HOST,
        port=WEB_PORT,
        debug=False,
        use_reloader=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
