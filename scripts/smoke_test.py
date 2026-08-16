from __future__ import annotations

import argparse

import httpx


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    with httpx.Client(base_url=args.base_url, timeout=10) as client:
        health = client.get("/health")
        health.raise_for_status()
        print("Health:", health.json())
        print("Interactive documentation:", f"{args.base_url}/docs")


if __name__ == "__main__":
    main()
