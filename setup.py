"""Setup configuration for the hp-bios-downloader-editor package."""

from setuptools import setup, find_packages
from pathlib import Path

long_description = Path("README.md").read_text(encoding="utf-8")

setup(
    name="hp-bios-tool",
    version="1.0.0",
    author="NightmareDesigns",
    description="HP BIOS Downloader, Editor, and Secret-Menu Unlocker",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/NightmareDesigns/hp-bios-downloader-editor",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "hp-bios=hp_bios_tool.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: System :: Hardware",
        "Topic :: Utilities",
        "Environment :: Console",
    ],
    keywords="hp bios firmware uefi editor downloader secret menu unlock",
)
