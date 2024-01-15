#!/usr/bin/env bash

if [[ $1 = "-h" ]]; then
    echo "Usage: FN_INFO=<FN_INFO> $0 <SEED> <OUTPUT>"
    exit 1
fi
# Argument parsing
SEED=$1
NUMERIC_RE='^[0-9]+$'
if ! [[ $SEED =~ $NUMERIC_RE ]]; then
    echo "Please specify a valid program seed"
fi
OUTPUT=$2
if [[ -z $OUTPUT ]]; then
    echo "Please specify a valid output directory"
fi
if [[ -z $FN_INFO ]]; then
    echo "Please specify chosen function information in \$FN_INFO"
fi

# Prepare temp dir for sem.py output
TEMP=$(mktemp -d -p /dev/shm)
cleanup() {
    rm -rf "$TEMP"
}
trap cleanup EXIT

# Goal: Find exact iteration where differences were introduced (assuming `-p mutate-csmith`)
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
MAX_ITERS=100
DIFF_CODE=11

for iter in $(seq 1 $MAX_ITERS); do
    echo ">>>===== Iteration $iter =====<<<"
    NUM_MUTATE=$iter "$SCRIPT_DIR"/../sem.py -q --debug -p mutate-csmith --repro $SEED --keep-data -O03 -o "$TEMP"
    err=$?
    if [[ $err = $DIFF_CODE ]]; then
        if ! [[ -d $OUTPUT ]]; then
            mkdir -p $OUTPUT
        fi
        echo "Difference found at iteration $iter"

        # If difference found, save code before and after mutation
        if [[ -d $TEMP/before ]]; then
            rm -rf "$OUTPUT/before"
            cp -r "$TEMP/before" "$OUTPUT"
        fi
        rm -rf "$OUTPUT/after"
        cp -r "$TEMP/$SEED" "$OUTPUT/after"
        exit
    elif [[ $err != 0 ]]; then
        echo "Error occurred"
        exit 1
    else
        # Save current as "before"
        rm -rf "$TEMP/before"
        mv "$TEMP/$SEED" "$TEMP/before"
    fi
done