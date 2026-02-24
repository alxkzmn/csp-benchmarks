#!/usr/bin/env python3

import argparse
import json
import math
import os
import re
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
    axis_unit: str
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
        axis_unit="seconds",
        convert=_ns_to_s,
    ),
    MetricSpec(
        key="verify_duration",
        title="Verification time",
        axis_unit="seconds",
        convert=_ns_to_s,
    ),
    MetricSpec(
        key="peak_memory",
        title="Peak memory",
        axis_unit="MB",
        convert=_bytes_to_mib,
    ),
    MetricSpec(
        key="proof_size",
        title="Proof size",
        axis_unit="kB",
        convert=_bytes_to_kib,
    ),
    MetricSpec(
        key="preprocessing_size",
        title="Preprocessing size",
        axis_unit="kB",
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

    units = ("B", "kB", "MB", "GB", "TB")
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
    if axis_unit == "kB":
        value_bytes = value_in_axis_units * 1024.0
    elif axis_unit == "MB":
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
                lambda y, _pos, unit=metric.axis_unit: _format_binary_tick(
                    float(y), unit
                )
            )
        )

    # Avoid clutter from minor ticks/labels.
    ax.yaxis.set_minor_locator(mticker.NullLocator())
    ax.yaxis.set_minor_formatter(mticker.NullFormatter())


def _series_label(row: Dict[str, Any], include_run_label: bool = False) -> str:
    name = str(row.get("name", "")).strip()
    feat = row.get("feat")
    feat_str = str(feat).strip() if feat is not None else ""
    if not feat_str:
        label = name
    else:
        label = f"{name} ({feat_str})"

    if include_run_label:
        run_label = str(row.get("__run_label", "")).strip()
        if run_label:
            return f"{label} ({run_label})"
    return label


def _clean_optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


def _normalize_feat(row: Dict[str, Any]) -> Optional[str]:
    feat = _clean_optional_str(row.get("feat"))
    if feat:
        row["feat"] = feat
    return feat


def _derive_name_and_feat_from_system(
    system_id: Optional[str], feat: Optional[str]
) -> Tuple[Optional[str], Optional[str]]:
    if not system_id:
        return None, feat

    if feat and system_id.endswith(f"_{feat}"):
        name = system_id[: -(len(feat) + 1)]
        if name:
            return name, feat

    # Fallback for schema variants where feat is omitted but system ids
    # are encoded as "<name>_<feature>".
    if "_" in system_id:
        name, inferred_feat = system_id.split("_", 1)
        if name:
            return name, (feat or inferred_feat)

    return system_id, feat


def _load_rows(path: Path) -> List[Dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise SystemExit(f"Input file not found: {path}") from e
    except json.JSONDecodeError as e:
        raise SystemExit(f"Invalid JSON in {path}: {e}") from e

    # Legacy schema: list[benchmark_row]
    if isinstance(raw, list):
        rows: List[Dict[str, Any]] = []
        for idx, item in enumerate(raw):
            if not isinstance(item, dict):
                raise SystemExit(
                    f"Expected array of objects in {path}; entry {idx} is {type(item).__name__}"
                )
            row = dict(item)
            _normalize_feat(row)
            rows.append(row)
        return rows

    # New schema: {metadata, systems, measurements}
    if isinstance(raw, dict):
        measurements_raw = raw.get("measurements")
        if not isinstance(measurements_raw, list):
            raise SystemExit(
                f"Expected 'measurements' array in {path}; got {type(measurements_raw).__name__}"
            )

        systems_raw = raw.get("systems", {})
        if not isinstance(systems_raw, dict):
            raise SystemExit(
                f"Expected 'systems' object in {path}; got {type(systems_raw).__name__}"
            )

        systems: Dict[str, Dict[str, Any]] = {}
        for system_key, meta in systems_raw.items():
            if not isinstance(meta, dict):
                raise SystemExit(
                    f"Expected systems['{system_key}'] to be an object in {path}; got {type(meta).__name__}"
                )
            systems[str(system_key)] = meta

        rows: List[Dict[str, Any]] = []
        for idx, measurement in enumerate(measurements_raw):
            if not isinstance(measurement, dict):
                raise SystemExit(
                    f"Expected measurements array of objects in {path}; entry {idx} is {type(measurement).__name__}"
                )

            system_id = _clean_optional_str(measurement.get("system"))
            row: Dict[str, Any] = {}
            if system_id and system_id in systems:
                row.update(systems[system_id])
            row.update(measurement)

            feat = _normalize_feat(row)
            name = _clean_optional_str(row.get("name"))

            if not name:
                derived_name, derived_feat = _derive_name_and_feat_from_system(
                    system_id, feat
                )
                if derived_name:
                    row["name"] = derived_name
                if derived_feat:
                    row["feat"] = derived_feat

            if not _clean_optional_str(row.get("name")) and system_id:
                row["name"] = system_id

            rows.append(row)

        return rows

    raise SystemExit(
        f"Unsupported JSON shape in {path}; expected a row array or an object with 'measurements'."
    )


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


def _filter_systems(
    rows: List[Dict[str, Any]], systems: Optional[Sequence[str]]
) -> List[Dict[str, Any]]:
    if not systems:
        return rows
    allowed = {s.strip() for s in systems if s.strip()}
    if not allowed:
        return rows

    filtered: List[Dict[str, Any]] = []
    for row in rows:
        name = str(row.get("name", "")).strip()
        series = _series_label(row, include_run_label=False)
        if name in allowed or series in allowed:
            filtered.append(row)
    return filtered


def _filter_features(
    rows: List[Dict[str, Any]], features: Optional[Sequence[str]]
) -> List[Dict[str, Any]]:
    if not features:
        return rows
    allowed = {f.strip() for f in features if f.strip()}
    if not allowed:
        return rows

    filtered: List[Dict[str, Any]] = []
    for row in rows:
        feat = row.get("feat")
        feat_str = str(feat).strip() if feat is not None else ""
        if feat_str in allowed:
            filtered.append(row)
    return filtered


def _plot_metric(
    *,
    target: str,
    metric: MetricSpec,
    input_sizes: Sequence[int],
    series_to_values: Dict[str, Dict[int, float]],
    out_path: Path,
    title_prefix: str,
    log_y: bool,
    legend_outside: bool = False,
) -> None:
    fig, ax = plt.subplots(figsize=(11, 6))

    plotted_values: List[float] = []
    plotted_xs_set: set[int] = set()

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
            plotted_xs_set.add(input_size)

        if not xs:
            continue

        ax.plot(xs, ys, marker="o", linewidth=2, markersize=4, label=series)

    ax.set_title(f"{title_prefix} — {target} — {metric.title}")
    if title_prefix:
        ax.set_title(f"{title_prefix} — {target} — {metric.title}")
    else:
        ax.set_title(f"{target} — {metric.title}")
    ax.set_xlabel("Input Size, Bytes")
    if plotted_xs_set:
        xticks = sorted(plotted_xs_set)
        ax.set_xticks(xticks)
        ax.set_xticklabels([str(x) for x in xticks])

    # No Y-axis label: units are embedded in tick labels.
    ax.set_ylabel("")
    if log_y:
        if plotted_values:
            _configure_log_y_axis(ax, metric, min(plotted_values), max(plotted_values))
    ax.grid(True, which="major", linestyle="-", linewidth=0.5, alpha=0.5)

    # Only show legend if there is something to show.
    handles, labels = ax.get_legend_handles_labels()
    if labels:
        if legend_outside:
            ax.legend(
                loc="upper left",
                bbox_to_anchor=(1.02, 1.0),
                borderaxespad=0.0,
                frameon=False,
            )
            fig.tight_layout(rect=(0, 0, 0.78, 1))
        else:
            ax.legend(loc="best", frameon=False)
            fig.tight_layout()
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
        help="Path to a collected benchmarks JSON (legacy row-array or new {systems,measurements} object).",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        type=Path,
        help="Optional second collected benchmarks JSON to overlay for comparison.",
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
        "--systems",
        default=None,
        help="Optional comma-separated list of proving systems to include (matches 'name' or 'name (feat)').",
    )
    parser.add_argument(
        "--features",
        default=None,
        help="Optional comma-separated list of feature values to include (matches JSON 'feat').",
    )
    parser.add_argument(
        "--input-label",
        default=None,
        help="Legend label for --input (default: input file stem).",
    )
    parser.add_argument(
        "--baseline-label",
        default=None,
        help="Legend label for --baseline (default: baseline file stem).",
    )
    parser.add_argument(
        "--log-y",
        action="store_true",
        help="Use log scale on the Y axis (non-positive values are skipped).",
    )
    parser.add_argument(
        "--include-input-name",
        action="store_true",
        help="Include the input JSON filename (stem) in the plot title.",
    )

    parser.add_argument(
        "--legend-outside",
        action="store_true",
        help="Place the legend outside the plot area (may squash axes if labels are long).",
    )

    args = parser.parse_args(list(argv) if argv is not None else None)

    targets: Optional[List[str]] = None
    if args.targets:
        targets = [t.strip() for t in str(args.targets).split(",") if t.strip()]

    systems: Optional[List[str]] = None
    if args.systems:
        systems = [s.strip() for s in str(args.systems).split(",") if s.strip()]

    features: Optional[List[str]] = None
    if args.features:
        features = [f.strip() for f in str(args.features).split(",") if f.strip()]

    def _default_run_label(path: Path) -> str:
        label = path.stem
        if label.startswith("collected_benchmarks_"):
            label = label[len("collected_benchmarks_") :]

        # Shorten long commit hashes in labels for readability.
        label = re.sub(r"([0-9a-f]{8})[0-9a-f]{8,}", r"\1", label)
        return label

    dataset_specs: List[Tuple[Path, str]] = []
    input_label = (
        str(args.input_label).strip()
        if args.input_label
        else _default_run_label(args.input)
    )
    dataset_specs.append((args.input, input_label))
    if args.baseline is not None:
        baseline_label = (
            str(args.baseline_label).strip()
            if args.baseline_label
            else _default_run_label(args.baseline)
        )
        dataset_specs.append((args.baseline, baseline_label))

    rows: List[Dict[str, Any]] = []
    for input_path, run_label in dataset_specs:
        loaded = _load_rows(input_path)
        for row in loaded:
            enriched = dict(row)
            enriched["__run_label"] = run_label
            rows.append(enriched)

    rows = _filter_rows(rows, targets)
    rows = _filter_systems(rows, systems)
    rows = _filter_features(rows, features)

    if not rows:
        raise SystemExit(
            "No rows to plot (check --targets/--systems/--features and input files)."
        )

    _ensure_out_dir(args.out)

    input_stem = args.input.stem
    if bool(args.include_input_name):
        if args.baseline is None:
            title_prefix = input_stem
        else:
            title_prefix = f"{args.input.stem} vs {args.baseline.stem}"
    else:
        title_prefix = ""

    rows_by_target: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in rows:
        target = str(r.get("target", ""))
        if not target:
            continue
        rows_by_target[target].append(r)

    for target, target_rows in sorted(rows_by_target.items(), key=lambda kv: kv[0]):
        include_run_label = len(dataset_specs) > 1
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

                series = _series_label(r, include_run_label=include_run_label)
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
                legend_outside=bool(args.legend_outside),
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
