```bash
# Activate the project virtualenv before running any visualizer commands
source .venv/bin/activate

# Basic usage (single file)
cd results/visualizer
python3 plot_benchmarks.py --input ../collected_benchmarks_<revision>.json --out out

# Basic usage with the new schema ({metadata, systems, measurements})
python3 plot_benchmarks.py --input ../multiproof.json --out out

# Overlay two runs for comparison (old vs new)
python3 plot_benchmarks.py \
	--input ../collected_benchmarks_univariate_skip.json \
	--baseline ../collected_benchmarks_whir_7b96d3938c0c725e636aea00356395b1ef5c42ef.json \
	--out out

# Filter by proving system (e.g., only whirlaway)
python3 plot_benchmarks.py \
	--input ../collected_benchmarks_univariate_skip.json \
	--systems whirlaway \
	--out out

# Overlay two runs and filter by system, with log-y axis
python3 plot_benchmarks.py \
	--input ../collected_benchmarks_univariate_skip.json \
	--baseline ../collected_benchmarks_whir_7b96d3938c0c725e636aea00356395b1ef5c42ef.json \
	--systems whirlaway \
	--out out \
	--log-y

# Overlay two runs and filter by system + feature (JSON field: feat)
python3 plot_benchmarks.py \
	--input ../collected_benchmarks_univariate_skip.json \
	--baseline ../collected_benchmarks_whir_7b96d3938c0c725e636aea00356395b1ef5c42ef.json \
	--systems whirlaway \
	--features quintic_128 \
	--out out \
	--log-y

# Exclude a feature globally (e.g., drop quintic_100 from all systems)
python3 plot_benchmarks.py \
	--input ../multiproof.json \
	--exclude-features quintic_100 \
	--out out

# Exclude multiple features at once
python3 plot_benchmarks.py \
	--input ../multiproof.json \
	--exclude-features quintic_100,binomial4_100 \
	--exclude-features binomial8_128 \
	--out out

# Place legend outside the plot area (may squash axes if labels are long)
python3 plot_benchmarks.py \
	--input ../collected_benchmarks_univariate_skip.json \
	--baseline ../collected_benchmarks_whir_7b96d3938c0c725e636aea00356395b1ef5c42ef.json \
	--systems whirlaway \
	--out out \
	--log-y \
	--legend-outside
```

# How to obtain the latest best charts:

```
python3 plot_benchmarks.py --input ../multiproof.json --log-y --exclude-features quintic_100,binomial8_128
```
