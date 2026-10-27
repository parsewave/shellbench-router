import asyncio
import inspect


def pytest_pyfunc_call(pyfuncitem):
    # Run `async def` tests without requiring pytest-asyncio.
    if inspect.iscoroutinefunction(pyfuncitem.obj):
        args = {n: pyfuncitem.funcargs[n] for n in pyfuncitem._fixtureinfo.argnames}
        asyncio.run(pyfuncitem.obj(**args))
        return True
    return None
