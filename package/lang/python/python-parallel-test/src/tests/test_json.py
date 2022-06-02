# Copyright 2019-2021 RnD Center "ELVEES", JSC

import json
import logging
import pathlib
import subprocess

example = json.dumps([{"cmd": "sleep", "param": {"1": "11"}} for _ in range(10)])


def run_parallel_test(args: str, pipe: bool = False) -> str:
    if pipe:
        command = f"echo '{args}' | parallel-test"
    else:
        command = f"parallel-test '{args}'"
    logging.info(f"Testing command: {command}")
    return subprocess.run(
        command,
        shell=True,
        stderr=subprocess.STDOUT,
        stdout=subprocess.PIPE,
    ).stdout.decode("utf-8")


def assert_example(result: str) -> None:
    # Check if there're 10 passed tests and 1 whole passed parallel test
    assert result.count("TEST PASSED") == 10 + 1


def test_file_input(tmp_path: pathlib.Path) -> None:
    filename = tmp_path / ".json"
    with open(filename, "w") as file_:
        file_.write(example)

    assert_example(run_parallel_test(str(filename)))


def test_str_input() -> None:
    assert_example(run_parallel_test(example))


def test_pipe_input() -> None:
    assert_example(run_parallel_test(example, pipe=True))


def test_empty_input() -> None:
    assert "FileNotFoundError" and "json.decoder.JSONDecodeError" in run_parallel_test("")
