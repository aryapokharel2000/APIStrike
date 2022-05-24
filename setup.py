from setuptools import setup, find_packages

setup(
    name="apistrike",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "apistrike=apistrike.cli:main",
        ],
    },
    python_requires=">=3.10",
)
