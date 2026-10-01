"""
TraxerTool - modules/ui.py
Utilidades visuales: colores ANSI, banner, tablas e inputs con estilo.
No depende de librerías externas para que funcione out-of-the-box
en Termux, Kali, Debian, etc.
"""

import shutil

COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def c(text, color):
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def ok(text):
    print(c(f"[+] {text}", "green"))


def warn(text):
    print(c(f"[!] {text}", "yellow"))


def error(text):
    print(c(f"[x] {text}", "red"))


def info(text):
    print(c(f"[*] {text}", "cyan"))


BANNER = r"""
 _______                          _____           _
|__   __|                        |_   _|         | |
   | |_ __ __ ___  _____ _ __      | |  ___   ___ | |
   | | '__/ _` \ \/ / _ \ '__|     | | / _ \ / _ \| |
   | | | | (_| |>  <  __/ |       _| || (_) | (_) | |
   |_|_|  \__,_/_/\_\___|_|      |_____\___/ \___/|_|
"""


def print_banner():
    width = shutil.get_terminal_size((80, 20)).columns
    print(c(BANNER, "cyan"))
    linea = "═" * min(width, 58)
    print(c(linea, "magenta"))
    print(c("      Multitool de Ciberseguridad y Hacking Ético", "bold"))
    print(c("           by Traxer  •  youtube.com", "dim"))
    print(c(linea, "magenta"))
    print(c("  Úsala solo en sistemas propios o con autorización.", "yellow"))
    print(c(linea, "magenta"))


def print_table(headers, rows):
    if not rows:
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def fmt_row(row, color=None):
        cells = [str(cell).ljust(widths[i]) for i, cell in enumerate(row)]
        line = " │ ".join(cells)
        return c(line, color) if color else line

    print(fmt_row(headers, "bold"))
    print("─┼─".join("─" * w for w in widths))
    for row in rows:
        print(fmt_row(row))
    print()


def pause():
    input(c("\nPresiona ENTER para continuar...", "dim"))


def ask(prompt):
    return input(c(f"➜ {prompt}: ", "cyan")).strip()
