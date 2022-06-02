#!/usr/bin/env python3
# Copyright 2020-2021 RnD Center "ELVEES", JSC

import argparse
import json
import sys

from parallel_test import CmdThreadDispatcher


def main():
    parser = argparse.ArgumentParser(
        add_help=True,
        description="Test thread dispatcher.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
example usage:
  parallel-test job.json
  echo job.json | parallel-test
  cat job.json | parallel-test
  parallel-test "$(cat job.json)"
        """,
    )

    parser.add_argument(
        "json",
        nargs="?",
        help="JSON string or file name with threads configuration. With no value provided, "
        "or when it is -, read JSON string or file name from standard input.",
    )
    parser.add_argument(
        "-T",
        "--full-time",
        type=int,
        default=10,
        help="Full test duration in seconds",
    )
    parser.add_argument(
        "-t",
        "--test-time",
        type=int,
        default=1,
        help="Test duration in seconds",
    )
    parser.add_argument(
        "-p",
        "--print-time",
        type=int,
        default=1,
        help="Status print time in seconds. Must be a least 10 times less than full time.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose flag",
    )
    parser.add_argument(
        "-j",
        "--json-desc",
        action="store_true",
        help="Print JSON test description and exit",
    )
    parser.add_argument(
        "--suppress-progress",
        dest="show_progress",
        action="store_false",
        help="Suppress spinner output",
    )
    parser.set_defaults(show_progress=True)

    args = parser.parse_args()

    output = None if args.verbose else open("/dev/null", "w")

    if not sys.stdin.isatty() and (args.json == "-" or args.json is None):
        json_ = sys.stdin.read()
    else:
        json_ = args.json
    try:
        tests_info = json.loads(json_)
    except ValueError:
        with open(args.json) as file_:
            tests_info = json.load(file_)

    # filter command arguments for testing duration
    tests_desc = []
    for t in tests_info:
        test = {}
        test["cmd"] = t["cmd"]
        test_times = [int(dur) for dur in t["param"]]
        nearest_duration = str(min(test_times, key=lambda x: abs(x - args.test_time)))
        test["param"] = t["param"][nearest_duration]
        tests_desc.append(test)

    if args.json_desc:
        print(json.dumps(tests_desc, indent=4))
        sys.exit()

    # getting commands and launching parameters for stress testing
    cmds = []
    pars = []
    for test in tests_desc:
        cmds.append(test["cmd"])
        pars.append(test["param"])

    disp = CmdThreadDispatcher(
        args.print_time, args.full_time, cmds, pars, output, args.show_progress
    )
    sys.exit(disp.run())


if __name__ == "__main__":
    main()
