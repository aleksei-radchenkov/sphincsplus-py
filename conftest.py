import pytest


@pytest.fixture()
def benchmark():
    class _Benchmark:
        def pedantic(
            self,
            func,
            args=(),
            kwargs=None,
            rounds=1,
            iterations=1,
            warmup_rounds=0,
        ):
            if kwargs is None:
                kwargs = {}

            for _ in range(warmup_rounds):
                for _ in range(iterations):
                    func(*args, **kwargs)

            for _ in range(rounds):
                for _ in range(iterations):
                    func(*args, **kwargs)

    return _Benchmark()
