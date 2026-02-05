#!/usr/bin/env python3

import argparse
import json
import math
import os
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Any,
    Callable,
    DefaultDict,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
)

# Force a non-interactive backend (CI/headless friendly).
import matplotlib

matplotlib.use("Agg")  # noqa: E402

import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker as mticker  # noqa: E402


@dataclass(frozen=True)
class MetricSpec:
    key: str
    title: str
    y_label: str
    convert: Callable[[int], float]


def _ns_to_s(value_ns: int) -> float:
    return float(value_ns) / 1e9


def _bytes_to_kib(value_bytes: int) -> float:
    return float(value_bytes) / 1024.0


def _bytes_to_mib(value_bytes: int) -> float:
    return float(value_bytes) / (1024.0 * 1024.0)


METRICS: Sequence[MetricSpec] = (
    MetricSpec(
        key="proof_duration",
        title="Proving time",
        y_label="seconds",
        convert=_ns_to_s,
    ),
    MetricSpec(
        key="verify_duration",
        title="Verify time",
        y_label="seconds",
        convert=_ns_to_s,
    ),
    MetricSpec(
        key="peak_memory",
        title="Peak memory",
        y_label="MiB",
        convert=_bytes_to_mib,
    ),
    MetricSpec(
        key="proof_size",
        title="Proof size",
        y_label="KiB",
        convert=_bytes_to_kib,
    ),
    MetricSpec(
        key="preprocessing_size",
        title="Preprocessing size",
        y_label="KiB",
        convert=_bytes_to_kib,
    ),
)


def _is_time_metric(metric: MetricSpec) -> bool:
    return metric.key in ("proof_duration", "verify_duration")


def _format_seconds_tick(seconds: float) -> str:
    if not math.isfinite(seconds) or seconds <= 0.0:
        return ""

    def fmt_number(x: float) -> str:
        if abs(x - round(x)) < 1e-9:
            return str(int(round(x)))
        return f"{x:.3g}"

    if seconds < 1e-3:
        return f"{fmt_number(seconds * 1e6)}µs"
    if seconds < 1.0:
        return f"{fmt_number(seconds * 1e3)}ms"
    if seconds < 60.0:
        return f"{fmt_number(seconds)}s"
    if seconds < 3600.0:
        return f"{fmt_number(seconds / 60.0)}m"
    return f"{fmt_number(seconds / 3600.0)}h"


def _format_binary_units_from_bytes(value_bytes: float) -> str:
    if not math.isfinite(value_bytes) or value_bytes <= 0.0:
        return ""

    units = ("B", "KiB", "MiB", "GiB", "TiB")
    unit_index = 0
    v = float(value_bytes)
    while v >= 1024.0 and unit_index < len(units) - 1:
        v /= 1024.0
        unit_index += 1

    if abs(v - round(v)) < 1e-9:
        num = str(int(round(v)))
    else:
        num = f"{v:.3g}"
    return f"{num} {units[unit_index]}"


def _format_binary_tick(value_in_axis_units: float, axis_unit: str) -> str:
    if axis_unit == "KiB":
        value_bytes = value_in_axis_units * 1024.0
    elif axis_unit == "MiB":
        value_bytes = value_in_axis_units * 1024.0 * 1024.0
    else:
        # Fallback: treat as already-bytes.
        value_bytes = value_in_axis_units
    return _format_binary_units_from_bytes(value_bytes)


def _configure_log_y_axis(
    ax: Any, metric: MetricSpec, y_min: float, y_max: float
) -> None:
    if not (math.isfinite(y_min) and math.isfinite(y_max)):
        return
    if y_min <= 0.0 or y_max <= 0.0:
        return
    if y_min > y_max:
        y_min, y_max = y_max, y_min

    if _is_time_metric(metric):
        ax.set_yscale("log", base=10)

        # Expand limits to nice decades so ticks like 1ms / 10ms
        # appear when the data is in the few-ms range.
        lower_decade = 10.0 ** math.floor(math.log10(y_min))
        upper_decade = 10.0 ** math.ceil(math.log10(y_max))
        ax.set_ylim(bottom=lower_decade, top=upper_decade)

        ax.yaxis.set_major_locator(
            mticker.LogLocator(base=10.0, subs=(1.0,), numticks=100)
        )
        ax.yaxis.set_major_formatter(
            mticker.FuncFormatter(lambda y, _pos: _format_seconds_tick(float(y)))
        )
    else:
        # Sizes/memory look nicer in powers-of-two.
        ax.set_yscale("log", base=2)

        # Expand limits to include one power-of-two below min so ticks like
        # 64/128/256/512 KiB show up even if the data starts above 128 KiB.
        lower_pow = math.floor(math.log2(y_min)) - 1
        upper_pow = math.ceil(math.log2(y_max)) + 0
        ax.set_ylim(bottom=2.0**lower_pow, top=2.0**upper_pow)

        ax.yaxis.set_major_locator(
            mticker.LogLocator(base=2.0, subs=(1.0,), numticks=200)
        )
        ax.yaxis.set_major_formatter(
            mticker.FuncFormatter(
                lambda y, _pos, unit=metric.y_label: _format_binary_tick(float(y), unit)
            )
        )

    # Avoid clutter from minor ticks/labels.
    ax.yaxis.set_minor_locator(mticker.NullLocator())
    ax.yaxis.set_minor_formatter(mticker.NullFormatter())


def _series_label(row: Dict[str, Any]) -> str:
    name = str(row.get("name", ""))
    feat = row.get("feat")
    if feat is None or feat == "":
        return name
    return f"{name}[{feat}]"


def _load_rows(path: Path) -> List[Dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise SystemExit(f"Input file not found: {path}") from e
    except json.JSONDecodeError as e:
        raise SystemExit(f"Invalid JSON in {path}: {e}") from e

    if not isinstance(raw, list):
        raise SystemExit(f"Expected a JSON array in {path}, got {type(raw).__name__}")

    rows: List[Dict[str, Any]] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            raise SystemExit(
                f"Expected array of objects in {path}; entry {idx} is {type(item).__name__}"
            )
        rows.append(item)
    return rows


def _ensure_out_dir(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)


def _sorted_unique(values: Iterable[int]) -> List[int]:
    return sorted(set(values))


def _filter_rows(
    rows: List[Dict[str, Any]], targets: Optional[Sequence[str]]
) -> List[Dict[str, Any]]:
    if not targets:
        return rows
    allowed = {t.strip() for t in targets if t.strip()}
    if not allowed:
        return rows
    return [r for r in rows if str(r.get("target", "")) in allowed]


def _plot_metric(
    *,
    target: str,
    metric: MetricSpec,
    input_sizes: Sequence[int],
    series_to_values: Dict[str, Dict[int, float]],
    out_path: Path,
    title_prefix: str,
    log_y: bool,
) -> None:
    fig, ax = plt.subplots(figsize=(10, 6))

    plotted_values: List[float] = []

    for series, values_by_input in sorted(
        series_to_values.items(), key=lambda kv: kv[0]
    ):
        ys: List[float] = []
        xs: List[int] = []
        for input_size in input_sizes:
            if input_size not in values_by_input:
                continue
            y = values_by_input[input_size]
            if log_y and (not math.isfinite(y) or y <= 0.0):
                continue
            xs.append(input_size)
            ys.append(y)
            plotted_values.append(y)

        if not xs:
            continue

        ax.plot(xs, ys, marker="o", linewidth=2, markersize=4, label=series)

    ax.set_title(f"{title_prefix} — {target} — {metric.title}")
    ax.set_xlabel("input_size")
    ax.set_ylabel(metric.y_label)
    if log_y:
        if plotted_values:
            _configure_log_y_axis(ax, metric, min(plotted_values), max(plotted_values))
    ax.grid(True, which="major", linestyle="-", linewidth=0.5, alpha=0.5)

    # Only show legend if there is something to show.
    handles, labels = ax.get_legend_handles_labels()
    if labels:
        ax.legend(
            loc="upper left",
            bbox_to_anchor=(1.02, 1.0),
            borderaxespad=0.0,
            frameon=False,
        )
        fig.tight_layout(rect=(0, 0, 0.78, 1))
    else:
        fig.tight_layout()

    fig.savefig(out_path, dpi=200)
    plt.close(fig)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate PNG plots from a collected_benchmarks*.json file."
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to a collected benchmarks JSON (array of rows).",
    )
    parser.add_argument(
        "--out",
        default=Path("visualizer/out"),
        type=Path,
        help="Output directory for generated PNGs (default: visualizer/out).",
    )
    parser.add_argument(
        "--targets",
        default=None,
        help="Optional comma-separated list of targets to plot (e.g. keccak,sha256).",
    )
    parser.add_argument(
        "--log-y",
        action="store_true",
        help="Use log scale on the Y axis (non-positive values are skipped).",
    )

    args = parser.parse_args(list(argv) if argv is not None else None)

    targets: Optional[List[str]] = None
    if args.targets:
        targets = [t.strip() for t in str(args.targets).split(",") if t.strip()]

    rows = _load_rows(args.input)
    rows = _filter_rows(rows, targets)

    if not rows:
        raise SystemExit("No rows to plot (check --targets and input file).")

    _ensure_out_dir(args.out)

    input_stem = args.input.stem
    title_prefix = input_stem

    rows_by_target: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in rows:
        target = str(r.get("target", ""))
        if not target:
            continue
        rows_by_target[target].append(r)

    for target, target_rows in sorted(rows_by_target.items(), key=lambda kv: kv[0]):
        input_sizes = _sorted_unique(
            int(r.get("input_size"))
            for r in target_rows
            if isinstance(r.get("input_size"), int)
        )

        # Build per-metric, per-series value maps.
        # series_to_values[series_label][input_size] = converted_value
        for metric in METRICS:
            series_to_values: Dict[str, Dict[int, float]] = defaultdict(dict)
            for r in target_rows:
                if not isinstance(r.get("input_size"), int):
                    continue
                if metric.key not in r:
                    continue
                raw_val = r.get(metric.key)
                if not isinstance(raw_val, int):
                    continue

                series = _series_label(r)
                input_size = int(r["input_size"])
                series_to_values[series][input_size] = metric.convert(raw_val)

            # Skip completely empty metrics.
            if not any(series_to_values.values()):
                continue

            out_name = f"{input_stem}_{target}_{metric.key}.png"
            out_path = args.out / out_name

            _plot_metric(
                target=target,
                metric=metric,
                input_sizes=input_sizes,
                series_to_values=series_to_values,
                out_path=out_path,
                title_prefix=title_prefix,
                log_y=bool(args.log_y),
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
