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
    """Count available static checks and categories.

    Returns (check_count, category_count).
    """
    try:
        from medusa.core.registry import CheckRegistry

        registry = CheckRegistry()
        registry.discover_checks()
        all_checks = registry.get_checks()
        static = [c for c in all_checks if not c.metadata().check_id.startswith("ai")]
        cats = {c.metadata().category for c in static}
        return len(static), len(cats)
    except Exception:
        return 559, 26  # fallback


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
        f"  [dim green]v{version} | {num_checks} checks"
        f" | {num_cats} categories"
        f" | AI reasoning engine | OWASP MCP Top 10"
        f"[/dim green]",
        highlight=False,
    )
    console.print(
        "  [dim]──────────────────────────────────────────────────────────────────────────[/dim]",
        highlight=False,
    )
    console.print()
