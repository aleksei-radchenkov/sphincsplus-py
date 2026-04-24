import pytest

def pytest_addoption(parser):
    parser.addoption(
        "--run-comparisons",
        action="store_true",
        default=False,
        help="Benchmark the implementation compared to other cryptographic schemes",
    )

def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-comparisons"):
        return

    skip = pytest.mark.skip(reason="Needs the --run-comparisons option to run")

    for item in items:
        if "comparison" in item.keywords:
            item.add_marker(skip)