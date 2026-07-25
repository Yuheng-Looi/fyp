import argparse
import os
import sys

# Add backend and frontend paths to sys.path
_benchmark_dir = os.path.dirname(os.path.abspath(__file__))
_backend_dir = os.path.dirname(_benchmark_dir)
_frontend_dir = os.path.join(os.path.dirname(_backend_dir), 'frontend')

if _benchmark_dir not in sys.path:
	sys.path.insert(0, _benchmark_dir)
if _backend_dir not in sys.path:
	sys.path.insert(0, _backend_dir)
if _frontend_dir not in sys.path:
	sys.path.insert(0, _frontend_dir)

from core.experiment_runner import ExperimentRunner


def _resolve_path(*parts):
	return os.path.join(os.path.dirname(__file__), *parts)


def main():
	parser = argparse.ArgumentParser(description="Run deterministic benchmark timeline")
	parser.add_argument(
		"--config",
		default=_resolve_path("config", "experiment.yaml"),
		help="Path to experiment.yaml",
	)
	parser.add_argument(
		"--scenario",
		default=_resolve_path("config", "scenarios", "ddos_internal_db.yaml"),
		help="Path to scenario YAML",
	)
	parser.add_argument(
		"--controller",
		default=[_resolve_path("controllers", "base_controller.py")],
		nargs="+",
		help="Path to Ryu controller file(s)",
	)
	parser.add_argument(
		"--topology",
		default="small",
		choices=["small", "large", "both"],
		help="Topology module name under benchmark/topology",
	)
	parser.add_argument("--nobase", action="store_true", help="Do not run simple_switch_13 as comparison baseline")
	parser.add_argument("--real-time", action="store_true", help="Run in real time")
	parser.add_argument("--dry-run", action="store_true", help="Run simulated timeline")

	args = parser.parse_args()

	real_time = None
	if args.real_time and args.dry_run:
		raise SystemExit("Choose either --real-time or --dry-run, not both")
	if args.real_time:
		real_time = True
	if args.dry_run:
		real_time = False

	controller_paths_raw = args.controller
	controller_paths = []
	for p in controller_paths_raw:
		if os.path.isabs(p):
			controller_paths.append(p)
		elif os.path.isfile(p):
			controller_paths.append(os.path.abspath(p))
		else:
			controller_paths.append(_resolve_path("controllers", p))
	controller_names = [os.path.splitext(os.path.basename(p))[0] for p in controller_paths]

	if args.topology == "both":
		small_scores_list = []
		large_scores_list = []
		ac_scores_list = []
		final_scores_list = []

		for p in controller_paths:
			controller_name = os.path.splitext(os.path.basename(p))[0]
			# Run small
			print(f"\n[orchestrator] Running SMALL network topology with controller {controller_name}...")
			runner_small = ExperimentRunner(
				args.config,
				args.scenario,
				controller_path=p,
				topology_name="small",
				real_time=real_time,
			)
			scores_small = runner_small.run()
			small_scores_list.append(scores_small)

			# Run large
			print(f"\n[orchestrator] Running LARGE network topology with controller {controller_name}...")
			runner_large = ExperimentRunner(
				args.config,
				args.scenario,
				controller_path=p,
				topology_name="large",
				real_time=real_time,
			)
			scores_large = runner_large.run()
			large_scores_list.append(scores_large)

			# Calculate cross-scale adaptiveness Layer B
			nrs_small = scores_small.get("NRS", 0.0)
			nrs_large = scores_large.get("NRS", 0.0)

			stability = max(0.0, 1.0 - (abs(nrs_small - nrs_large) / max(nrs_small, nrs_large, 0.01)))
			ac = nrs_large * stability
			final_score = (0.70 * nrs_large) + (0.30 * ac)

			ac_scores_list.append(ac)
			final_scores_list.append(final_score)

		print()
		print_results_table("SMALL NETWORK RESULTS", controller_names, small_scores_list, "NRS (Small)")
		print_results_table("LARGE NETWORK RESULTS", controller_names, large_scores_list, "NRS (Large)")
		print_scorecard_table(controller_names, ac_scores_list, final_scores_list)
	else:
		scores_list = []
		for p in controller_paths:
			controller_name = os.path.splitext(os.path.basename(p))[0]
			print(f"\n[orchestrator] Running {args.topology.upper()} network topology with controller {controller_name}...")
			runner = ExperimentRunner(
				args.config,
				args.scenario,
				controller_path=p,
				topology_name=args.topology,
				real_time=real_time,
			)
			scores = runner.run()
			scores_list.append(scores)
		
		print()
		title = f"{args.topology.upper()} NETWORK RESULTS"
		nrs_label = f"NRS ({args.topology.capitalize()})"
		print_results_table(title, controller_names, scores_list, nrs_label)

		# Save latest_benchmark.json for benchmark_runner
		import json
		from datetime import datetime
		results_dict = {}
		for p, sc in zip(controller_paths, scores_list):
			c_name = os.path.splitext(os.path.basename(p))[0]
			results_dict[c_name] = {args.topology: sc}

		out_data = {
			"metadata": {
				"timestamp": datetime.now().isoformat(),
				"topologies_tested": [args.topology],
			},
			"results": results_dict,
		}

		results_dir = _resolve_path("results")
		os.makedirs(results_dir, exist_ok=True)
		latest_json_path = os.path.join(results_dir, "latest_benchmark.json")
		with open(latest_json_path, "w") as f:
			json.dump(out_data, f, indent=2)
		print(f"[eval] Scorecard generated successfully. Detailed results saved to {latest_json_path}")


def print_results_table(title, controller_names, list_of_scores, nrs_label):
	header = f"{'Metric':<20}"
	for name in controller_names:
		header += f" | {name:<17}"
	print("=" * len(header))
	print(title)
	print("=" * len(header))
	print(header)
	print("-" * len(header))
	
	metrics = [
		("Service Continuity", "SCS"),
		("QoS Preservation", "QPS"),
		("User Impact", "UIS"),
		("Recovery Score", "RES"),
	]
	for label, key in metrics:
		row = f"{label:<20}"
		for scores in list_of_scores:
			val = scores.get(key, 0.0)
			row += f" | {val:<17.2f}"
		print(row)
		
	print("-" * len(header))
	row = f"{nrs_label:<20}"
	for scores in list_of_scores:
		val = scores.get("NRS", 0.0)
		row += f" | {val:<17.2f}"
	print(row)
	print()


def print_scorecard_table(controller_names, adaptiveness_scores, overall_scores):
	header = f"{'Metric':<20}"
	for name in controller_names:
		header += f" | {name:<17}"
	print("=" * len(header))
	print("FINAL SDN CONTROLLER BENCHMARK SCORECARD")
	print("=" * len(header))
	print(header)
	print("-" * len(header))
	
	row_ac = f"{'Adaptiveness Score':<20}"
	for ac in adaptiveness_scores:
		row_ac += f" | {ac:<17.2f}"
	print(row_ac)
	
	print("-" * len(header))
	
	row_final = f"{'OVERALL FINAL SCORE':<20}"
	for fs in overall_scores:
		row_final += f" | {fs:<17.2f}"
	print(row_final)
	print("=" * len(header))


if __name__ == "__main__":
	main()
