# Copyright 2020 RnD Center "ELVEES", JSC

from setuptools import find_packages, setup

setup(
    name="parallel-test",
    version="1.0",
    description="Tools for running multiple tests in parallel",
    python_requires=">=3.6,<4.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "parallel-test = parallel_test.parallel_test:main",
        ]
    },
)
