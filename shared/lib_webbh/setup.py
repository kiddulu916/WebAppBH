from setuptools import setup, find_packages

setup(
    name="lib_webbh",
    version="0.1.0",
    packages=["lib_webbh", "lib_webbh.prompts", "lib_webbh.platform_api"],
    package_dir={"lib_webbh": ".", "lib_webbh.prompts": "prompts", "lib_webbh.platform_api": "platform_api"},
    package_data={"lib_webbh": ["py.typed"]},
    install_requires=[
        "sqlalchemy[asyncio]>=2.0",
        "asyncpg>=0.29",
        "redis[hiredis]>=5.0",
        "pydantic>=2.0",
        "netaddr>=0.10",
        "tldextract>=5.0",
        "croniter>=1.3",
        "httpx>=0.27",
        "alembic>=1.13",
        "prometheus-client>=0.20",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0",
            "pytest-asyncio>=0.23",
            "aiosqlite>=0.20",
        ],
    },
)
