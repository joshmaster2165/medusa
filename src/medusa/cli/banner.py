"""Medusa CLI banner and ASCII art."""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

MEDUSA_ART = r"""

                                               .-+%@@+..
                                   ...         =+*@@@@@%.     ..
                                  .+@:.        .+*=+:.@@*   ..+%-.
                                 :*#%#-  .   .*@%#*#@%*@#.   ++%#*.
                                 -@@@*-+@@*-.*@#    -@*%+#@%+:%@@#:
                                 -%@+%@#++%@==@@=-=##@=#@#++%@#=@*.
                                 .=#@@-.  =@@..**##*@*.@%:  .+@@*-.
                            .-+++-:*@#@@@%@@=... :#*:..*@@%@@@*@*.-+++:.
                      .+:..=%@#*#@%%%..-==+*%#+*-..+*+%#*+==-.:@%%@#*%@%-..-+.
                      -@+==%%:  .=@@@:  :#%=+%@%+--*%%#++%*:  :%#@=.  -@#+=#@:
                      ##%%%@=.  .*@#%#.=@*=%%=.::.:::.=@#-#%-.@%*@+.  .#@%@*%=
                      -@@%*%@++*@@*:-#%@+-+%##%:-**--%##%+-*@%%::#@%*-*@%*@@@.
                       .=%@@*@@%#-..+@%:++=--..#@@@@*.:--+*+-@@+..=%%@@#%@%=. .
                    -%+     :*%%@%%@%- :%%=-*+@@@@@@@#+*:+@#. -@@#%@%%*.     *%:.
                  .-+%*%: .+@%::=@%-  *@%=@@@@@@@@@@@@@@@%*%@-  -@@=::@%=  =@%**:
                    +@@@* :#@: .-@%-*@@=:#%**@@@@@@@@@@+*@*:*@@+-@@-  :@#. #@@%:
                    ..%@%..*@%-:*@@@@:=++..... :@@@@: .....-#:-@@@%+:-@@*.-@@#.
                       *@@@%**%@#-  .%@ :@@@@@@#@@@#%@@@@@#::%%. .=#%%+#%@@@-
                        .-%@@#.    .#@ --%@@@@@@@@@@@@@@@@++:.@#.    :%@@#:
                          ..-%@@@@%%@%:@==@@@@@@@@@@@@@@@@+*@-+@@@@@@@%:..
                     ..:+%@@@%*...=@+%@*.:#@@@@@:..=@@@@@*.=%@%#%= .:#%@@@#=:.
                   .:#%-@@*:.    .*@-.@@-:*#@@@@%##%@@@@**.*@# -@+.    .-#@*-@+.
                   -#+=%#-       :%%: +@#-:%@@@%@@%@%@@@#:=%@: -@*.      .=#%-**:
                     :.          .*@=:%@*@+:#@@@@##@@@@#:+@%@+:=@+.          :.
                                  :*@@%=:%@=.*@@@@@@@@*.=@#:+%@%+.
                       .=+#%@@@#-.      .=@+. .+****=. :%@=.      :=%@@@##+-.
                       ***@@@#*@@@*:    :#@=.*:      -*.+@*.    :*@@%**@@%**=
                        :-...  .=%@@%##@@@=. %@*:  -#@* .*@@#++%@@#-. ...:-.
                                 .:=++++-.  .%@@@%%@@@%   .-++++=:.
                                         .-=.%@@@@@@@@@.+-
                                        .=#:+@@@@@@@@@@:-%=.
                                        -@#:=@@@@@@@@@@--@#:
                                        :%@#:.-=#%%*=:.:%@*.
                                        .:#@@@%#*++*#%@@@#:
                                          .:=#@@@@@@@@#-..
                                               ......
                                                      """

MEDUSA_LETTERS = r"""
 ███╗   ███╗███████╗██████╗ ██╗   ██╗███████╗ █████╗
 ████╗ ████║██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
 ██╔████╔██║█████╗  ██║  ██║██║   ██║███████╗███████║
 ██║╚██╔╝██║██╔══╝  ██║  ██║██║   ██║╚════██║██╔══██║
 ██║ ╚═╝ ██║███████╗██████╔╝╚██████╔╝███████║██║  ██║
 ╚═╝     ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝"""


def _count_checks() -> tuple[int, int]:
    """Count available checks and categories (cached)."""
    try:
        from medusa.core.registry import CheckRegistry

        registry = CheckRegistry()
        registry.discover_checks()
        all_checks = registry.get_checks()
        # Exclude the AI-only category from the static count display
        static = [c for c in all_checks if not c.metadata().check_id.startswith("ai")]
        static_cats = {c.metadata().category for c in static}
        return len(static), len(static_cats)
    except Exception:
        return 435, 24  # fallback


def print_banner(console: Console, version: str) -> None:
    """Print the Medusa ASCII art banner to the console."""
    num_checks, num_cats = _count_checks()

    # Snake head art in bright green
    art_text = Text(MEDUSA_ART, style="bold green")
    console.print(art_text, highlight=False)

    # Block letters in green
    letters_text = Text(MEDUSA_LETTERS, style="green")
    console.print(letters_text, highlight=False)
    console.print()

    # Tagline
    console.print(
        "  [bold bright_green]MCP Security Scanner[/bold bright_green]",
        highlight=False,
    )
    console.print(
        f"  [dim green]v{version} | {num_checks} static checks + AI"
        f" | {num_cats} categories | OWASP MCP Top 10[/dim green]",
        highlight=False,
    )
    console.print(
        "  [dim]──────────────────────────────────────────────────────[/dim]",
        highlight=False,
    )
    console.print()
