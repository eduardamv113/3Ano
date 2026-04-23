from __future__ import annotations

import argparse
import sys
from pathlib import Path


def parse_tree(tokens: list[str], index: int = 0) -> tuple[int, int]:
    """Recursive descent parser for:
    Tree -> INT Tree Tree | x

    Returns a tuple (depth, next_index).
    """
    if index >= len(tokens):
        raise ValueError("Unexpected end of input while parsing Tree")

    token = tokens[index]
    if token == "x":
        return 0, index + 1

    try:
        int(token)
    except ValueError as exc:
        raise ValueError(f"Invalid token '{token}' at position {index}") from exc

    left_depth, next_index = parse_tree(tokens, index + 1)
    right_depth, next_index = parse_tree(tokens, next_index)
    return 1 + max(left_depth, right_depth), next_index


def max_tree_depth_from_text(text: str) -> int:
    tokens = text.split()
    if not tokens:
        raise ValueError("Input is empty")

    # Large trees can exceed Python's default recursion limit.
    sys.setrecursionlimit(max(10000, len(tokens) + 10))

    depth, next_index = parse_tree(tokens, 0)
    if next_index != len(tokens):
        raise ValueError(
            f"Extra tokens after valid tree: stopped at {next_index} of {len(tokens)}"
        )
    return depth


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compute maximum depth of a binary tree encoded by grammar: Tree -> INT Tree Tree | x"
    )
    parser.add_argument(
        "input_file",
        type=Path,
        help="Path to file containing the serialized tree",
    )
    args = parser.parse_args()

    text = args.input_file.read_text(encoding="utf-8")
    depth = max_tree_depth_from_text(text)
    print(depth)


if __name__ == "__main__":
    main()
