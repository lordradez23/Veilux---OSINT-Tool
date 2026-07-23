from setuptools import setup, find_packages

setup(
    name="veilux-ng",
    version="2.0.0",
    author="Lordradeez.exe",
    description="Next Generation Nigerian OSINT Framework — NDPA 2023 Compliant",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "requests>=2.31.0",
        "phonenumbers>=8.13.0",
        "python-whois>=0.9.4",
        "dnspython>=2.6.0",
        "Pillow>=10.3.0",
        "python-dotenv>=1.0.0",
        "colorama>=0.4.6",
    ],
    extras_require={
        "dev": [
            "pytest>=8.2.0",
            "pytest-mock>=3.14.0",
        ]
    },
)
