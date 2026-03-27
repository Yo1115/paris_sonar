#!/usr/bin/env python3
import json
import sys


def main() -> int:
    if len(sys.argv) != 5:
        print(
            "Usage: inject-sbom-metadata.py <input_file> <repo_name> <branch> <commit_sha>",
            file=sys.stderr,
        )
        return 1

    input_file = sys.argv[1]
    repo_name = sys.argv[2]
    branch = sys.argv[3]
    commit_sha = sys.argv[4]
    short_sha = commit_sha[:7]

    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    metadata = data.setdefault("metadata", {})

    properties = metadata.get("properties")
    if not isinstance(properties, list):
        properties = []
        metadata["properties"] = properties

    properties.append({"name": "taitra:repo", "value": repo_name})
    properties.append({"name": "taitra:branch", "value": branch})
    properties.append({"name": "taitra:commit", "value": short_sha})

    component = metadata.get("component")
    if not isinstance(component, dict):
        component = {}
        metadata["component"] = component

    component_name = component.get("name", "")
    if not isinstance(component_name, str) or component_name.strip() in {"", "."}:
        component["name"] = repo_name

    with open(input_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(
        f"Injected SBOM metadata: repo={repo_name}, branch={branch}, commit={short_sha}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
