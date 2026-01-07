from __future__ import annotations

import argparse
from typing import Sequence

from .run import run_etl


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse nginx/api/ufw logs and write normalized output."
    )
    parser.add_argument("--nginx", help="Path to nginx combined access log")
    parser.add_argument("--api", help="Path to API application log")
    parser.add_argument("--ufw", help="Path to UFW firewall log")
    parser.add_argument("--out", required=True, help="Output file path (.parquet or .csv)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    result = run_etl(
        nginx_path=args.nginx,
        api_path=args.api,
        ufw_path=args.ufw,
        out_path=args.out,
    )

    total_rows = result["total_rows"]
    output_path = result["output_path"]
    print("=== ETL Summary ===")
    for summary in result["summaries"]:
        print(
            f"{summary.file}: total={summary.total} ok={summary.ok} failed={summary.failed}"
        )
    print(f"total output rows: {total_rows}")
    print(f"output written to: {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

