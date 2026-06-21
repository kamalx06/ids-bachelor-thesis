import csv
import argparse
from pathlib import Path

parser = argparse.ArgumentParser(description="Merge all CSV files in a directory.")
parser.add_argument(
    "input_folder",
    nargs="?",
    default="ai/MachineLearningCVE",
    help="Folder containing CSV files (default: ai/MachineLearningCVE)"
)

args = parser.parse_args()
input_dir = Path(args.input_folder)

if not input_dir.exists() or not input_dir.is_dir():
    raise FileNotFoundError(f"Input directory does not exist: {input_dir}")

output_dir = Path("ai/data")
output_dir.mkdir(parents=True, exist_ok=True)
output_file = output_dir / "cic_ids.csv"

csv_files = sorted(input_dir.glob("*.csv"))

print(f"Found {len(csv_files)} CSV files in '{input_dir}'.")

with open(output_file, "w", newline="", encoding="utf-8") as outfile:
    writer = csv.writer(outfile)

    for i, csv_file in enumerate(csv_files):
        print(f"Processing: {csv_file.name}")
        with open(csv_file, "r", newline="", encoding="utf-8") as infile:
            reader = csv.reader(infile)
            if i == 0:
                writer.writerows(reader)
            else:
                next(reader, None)
                writer.writerows(reader)

print(f"\nMerged file saved as: {output_file}")