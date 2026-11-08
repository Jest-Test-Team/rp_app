#!/usr/bin/env bash
# Release preflight: decide in seconds whether this run publishes, and refuse a
# publish that would fail (or ship the wrong thing) minutes later.
#
# The workflow gathers the facts; this script only decides, so it can be tested.
# Facts (environment):
#   EVENT            push | workflow_dispatch | pull_request
#   PUBLISH_INPUT    true | false   (workflow_dispatch input)
#   TAG_INPUT        tag typed into the manual run (may be empty)
#   REF_NAME         github.ref_name (the tag on a tag push)
#   SHA              commit this run builds
#   TAG_SHA          commit the tag points at ("" if the tag does not exist)
#   RELEASE_EXISTS   true | false   (a GitHub Release with this tag exists)
#   CARGO_VERSION    workspace version from Cargo.toml (e.g. 0.2.0)
#   HAS_SIGNING_KEY  true | false   (MINISIGN_SECRET_KEY is set)
#
# Prints `publish=…`, `tag=…`, `mode=…` for $GITHUB_OUTPUT; exit 1 with every
# problem listed (as ::error:: annotations) when a publish must not happen.
set -euo pipefail

event=${EVENT:?} publish_input=${PUBLISH_INPUT:-false} tag_input=${TAG_INPUT:-}
ref_name=${REF_NAME:-} sha=${SHA:?} tag_sha=${TAG_SHA:-} release_exists=${RELEASE_EXISTS:-false}
cargo_version=${CARGO_VERSION:?} has_key=${HAS_SIGNING_KEY:-false}

semver='^v[0-9]+\.[0-9]+\.[0-9]+$'
errors=()
err() { errors+=("$1"); }

publish=false
case $event in
  push) publish=true; tag=$ref_name ;;
  workflow_dispatch) [[ $publish_input == true ]] && publish=true; tag=$tag_input ;;
  *) tag="" ;;
esac
tag=${tag// /}

if [[ $publish == true ]]; then
  expected="v$cargo_version"
  if [[ -z $tag ]]; then
    err "publish=true needs a tag. The workspace version is $cargo_version, so the tag would be $expected."
  elif ! [[ $tag =~ $semver ]]; then
    err "tag '$tag' is not of the form vX.Y.Z (e.g. $expected)."
  else
    [[ $tag == "$expected" ]] ||
      err "tag $tag does not match the workspace version $cargo_version (Cargo.toml). Release $expected, or bump the version first."
    if [[ -z $tag_sha ]]; then
      err "tag $tag does not exist. Create it on the commit to release, then push it (a tag push publishes by itself): git tag -a $tag -m $tag ${sha:0:7} && git push origin $tag"
    elif [[ $tag_sha != "$sha" ]]; then
      err "tag $tag points at ${tag_sha:0:7}, but this run builds ${sha:0:7}. Run the workflow from the tag (Run workflow › Use workflow from › Tags › $tag), or push the tag."
    fi
    [[ $release_exists != true ]] ||
      err "a GitHub Release $tag already exists. Bump the version (Cargo.toml + pubspec.yaml) and tag that."
  fi
  [[ $has_key == true ]] ||
    err "MINISIGN_SECRET_KEY is not set: devices refuse unsigned updates, so the release would be refused at the end."
fi

if ((${#errors[@]})); then
  for e in "${errors[@]}"; do echo "::error title=release preflight::$e" >&2; done
  echo "release preflight: ${#errors[@]} problem(s); nothing was built or published." >&2
  exit 1
fi

if [[ $publish != true && -n $tag && ! $tag =~ $semver ]]; then
  echo "::warning title=release preflight::ignoring tag '$tag' (not vX.Y.Z) for this dry run" >&2
  tag=""
fi

echo "publish=$publish"
echo "tag=$tag"
echo "mode=$([[ $publish == true ]] && echo "publish $tag" || echo "dry run")"
