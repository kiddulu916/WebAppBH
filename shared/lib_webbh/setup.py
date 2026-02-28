from setuptools import setup, find_packages

setup(
    name="lib_webbh",
    version="0.1.0",
    packages=["lib_webbh"],
    package_dir={"lib_webbh": "."},
    install_requires=[
        "sqlalchemy[asyncio]>=2.0",
        "asyncpg>=0.29",
        "redis[hiredis]>=5.0",
        "pydantic>=2.0",
        "netaddr>=0.10",
        "tldextract>=5.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0",
            "pytest-asyncio>=0.23",
            "aiosqlite>=0.20",
        ],
    },
)
