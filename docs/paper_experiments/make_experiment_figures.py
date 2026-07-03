from __future__ import annotations

import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SUITES = ["banking", "slack", "travel", "workspace"]
COLORS = {
    "deepseek-v4-flash": "#1f77b4",
    "qwen-plus": "#d62728",
    "MELON": "#2ca02c",
    "Progent": "#9467bd",
    "DRIFT": "#ff7f0e",
    "RepoShield": "#111827",
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def scale(value: float, lo: float, hi: float, a: float, b: float) -> float:
    if hi == lo:
        return (a + b) / 2
    return a + (value - lo) * (b - a) / (hi - lo)


def line_chart_by_suite(rows: list[dict[str, str]], metric: str, title: str, out: Path) -> None:
    width, height = 780, 420
    left, right, top, bottom = 76, 36, 54, 74
    plot_w, plot_h = width - left - right, height - top - bottom
    values = [float(row[metric]) for row in rows]
    y_min = 0.0
    y_max = 100.0 if max(values) > 20 else max(5.0, max(values) * 1.25)
    x_pos = {suite: left + idx * plot_w / (len(SUITES) - 1) for idx, suite in enumerate(SUITES)}
    y_pos = lambda value: top + plot_h - scale(value, y_min, y_max, 0, plot_h)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{left}" y="30" font-family="Arial" font-size="20" font-weight="700" fill="#111827">{title}</text>',
        f'<line x1="{left}" y1="{top + plot_h}" x2="{left + plot_w}" y2="{top + plot_h}" stroke="#374151" stroke-width="1"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h}" stroke="#374151" stroke-width="1"/>',
    ]
    for tick in range(0, 101, 20):
        y = y_pos(float(tick))
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left + plot_w}" y2="{y:.1f}" stroke="#e5e7eb" stroke-width="1"/>')
        parts.append(f'<text x="{left - 10}" y="{y + 4:.1f}" text-anchor="end" font-family="Arial" font-size="12" fill="#4b5563">{tick}%</text>')
    for suite in SUITES:
        x = x_pos[suite]
        parts.append(f'<text x="{x:.1f}" y="{height - 34}" text-anchor="middle" font-family="Arial" font-size="13" fill="#111827">{suite}</text>')

    for model in ["deepseek-v4-flash", "qwen-plus"]:
        series = [row for row in rows if row["model"] == model]
        points = [(x_pos[row["suite"]], y_pos(float(row[metric]))) for row in series]
        path = " ".join(("M" if idx == 0 else "L") + f" {x:.1f} {y:.1f}" for idx, (x, y) in enumerate(points))
        color = COLORS[model]
        parts.append(f'<path d="{path}" fill="none" stroke="{color}" stroke-width="3"/>')
        for row, (x, y) in zip(series, points):
            value = float(row[metric])
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4.5" fill="{color}"/>')
            parts.append(f'<text x="{x:.1f}" y="{y - 10:.1f}" text-anchor="middle" font-family="Arial" font-size="12" fill="{color}">{value:.2f}</text>')

    legend_y = height - 14
    for idx, model in enumerate(["deepseek-v4-flash", "qwen-plus"]):
        x = left + idx * 190
        parts.append(f'<line x1="{x}" y1="{legend_y}" x2="{x + 26}" y2="{legend_y}" stroke="{COLORS[model]}" stroke-width="3"/>')
        parts.append(f'<text x="{x + 34}" y="{legend_y + 4}" font-family="Arial" font-size="12" fill="#111827">{model}</text>')
    parts.append("</svg>")
    out.write_text("\n".join(parts) + "\n", encoding="utf-8")


def line_chart_overall(rows: list[dict[str, str]], metric: str, title: str, out: Path) -> None:
    width, height = 760, 420
    left, right, top, bottom = 76, 36, 54, 86
    plot_w, plot_h = width - left - right, height - top - bottom
    defenses = ["MELON", "Progent", "DRIFT", "RepoShield"]
    models = ["deepseek-v4-flash", "qwen-plus"]
    y_pos = lambda value: top + plot_h - scale(value, 0, 100, 0, plot_h)
    x_pos = {defense: left + idx * plot_w / (len(defenses) - 1) for idx, defense in enumerate(defenses)}
    lookup = {(row["defense"], row["model"]): float(row[metric]) for row in rows}

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{left}" y="30" font-family="Arial" font-size="20" font-weight="700" fill="#111827">{title}</text>',
        f'<line x1="{left}" y1="{top + plot_h}" x2="{left + plot_w}" y2="{top + plot_h}" stroke="#374151" stroke-width="1"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h}" stroke="#374151" stroke-width="1"/>',
    ]
    for tick in range(0, 101, 20):
        y = y_pos(float(tick))
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left + plot_w}" y2="{y:.1f}" stroke="#e5e7eb" stroke-width="1"/>')
        parts.append(f'<text x="{left - 10}" y="{y + 4:.1f}" text-anchor="end" font-family="Arial" font-size="12" fill="#4b5563">{tick}%</text>')
    for defense in defenses:
        x = x_pos[defense]
        parts.append(f'<text x="{x:.1f}" y="{height - 44}" text-anchor="middle" font-family="Arial" font-size="13" fill="#111827">{defense}</text>')
    for model in models:
        points = [(x_pos[defense], y_pos(lookup[(defense, model)])) for defense in defenses]
        color = COLORS[model]
        path = " ".join(("M" if idx == 0 else "L") + f" {x:.1f} {y:.1f}" for idx, (x, y) in enumerate(points))
        parts.append(f'<path d="{path}" fill="none" stroke="{color}" stroke-width="3"/>')
        for defense, (x, y) in zip(defenses, points):
            value = lookup[(defense, model)]
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4.5" fill="{color}"/>')
            parts.append(f'<text x="{x:.1f}" y="{y - 10:.1f}" text-anchor="middle" font-family="Arial" font-size="12" fill="{color}">{value:.2f}</text>')
    legend_y = height - 18
    for idx, model in enumerate(models):
        x = left + idx * 190
        parts.append(f'<line x1="{x}" y1="{legend_y}" x2="{x + 26}" y2="{legend_y}" stroke="{COLORS[model]}" stroke-width="3"/>')
        parts.append(f'<text x="{x + 34}" y="{legend_y + 4}" font-family="Arial" font-size="12" fill="#111827">{model}</text>')
    parts.append("</svg>")
    out.write_text("\n".join(parts) + "\n", encoding="utf-8")


def main() -> None:
    scenario = read_csv(ROOT / "scenario_by_suite.csv")
    overall = read_csv(ROOT / "baseline_overall_comparison.csv")
    line_chart_by_suite(scenario, "secure_utility", "RepoShield Secure Utility by AgentDojo Suite", ROOT / "fig_suite_secure_utility.svg")
    line_chart_by_suite(scenario, "asr", "RepoShield ASR by AgentDojo Suite", ROOT / "fig_suite_asr.svg")
    line_chart_overall(overall, "secure_utility", "Secure Utility across Defenses", ROOT / "fig_overall_secure_utility.svg")


if __name__ == "__main__":
    main()
