#!/usr/bin/env bash
if ! [[ -d $1 ]]; then
    echo "Please specify a seeds directory"
fi

SEEDS_DIR="$1"

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

repro() {
    echo "Seed: $1"
    expected_diff="$SEEDS_DIR/$1/diff.txt"
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    RESET='\033[0m'
    echo -e "Expected diff:${RED}"
    cat "$expected_diff"
    echo -e "${RESET}"
    echo -e "Actual diff:${GREEN}"
    "$SCRIPT_DIR"/../sem.py --repro $1 --debug -O03 -o "$SEEDS_DIR-repro" 2>/dev/null
    echo -e "${RESET}\n==========\n"
}

for seed_dir in "$SEEDS_DIR"/*/; do
    seed=$(basename "$seed_dir")
    repro $seed
done