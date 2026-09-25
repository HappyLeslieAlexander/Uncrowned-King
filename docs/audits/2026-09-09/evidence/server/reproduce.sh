#!/bin/sh
set -eu
EVIDENCE_DIR=$(cd "$(dirname "$0")" && pwd)
SOURCE=${1:?Usage: reproduce.sh /absolute/path/to/project}
REVIEW=$(mktemp -d /tmp/uk-server-review.XXXXXX)
cp "$SOURCE/Cargo.toml" "$SOURCE/Cargo.lock" "$REVIEW/"
cp -R "$SOURCE/crates" "$SOURCE/examples" "$REVIEW/"
cp -R "$SOURCE/.cargo" "$REVIEW/"
cd "$REVIEW"
patch -p1 < "$EVIDENCE_DIR/server-review-tests.patch"
cargo test --manifest-path "$REVIEW/Cargo.toml" --target-dir "$SOURCE/target" --locked -p uk-server --lib review_ -- --nocapture
