"""Decorator-based tool protection."""

from agentwall import Shield

shield = Shield()


@shield.protect(tool="shell")
def run_shell(command: str) -> str:
    return f"executed: {command}"


@shield.protect(tool="read_file")
def read_file(path: str) -> str:
    return f"contents of {path}"


if __name__ == "__main__":
    print(run_shell("npm test"))

    try:
        print(run_shell("rm -rf ./"))
    except PermissionError as exc:
        print(f"blocked: {exc}")

    try:
        print(read_file("~/.ssh/id_rsa"))
    except PermissionError as exc:
        print(f"blocked: {exc}")
