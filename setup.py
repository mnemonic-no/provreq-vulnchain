"""Setup script for the python-act library module"""

from os import path

from setuptools import setup

# read the contents of your README file
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, "README.md"), "rb") as f:
    long_description = f.read().decode("utf-8")

setup(
    name="provreq-vulnchain",
    version="0.1.0",
    author="mnemonic AS",
    zip_safe=True,
    author_email="opensource@mnemonic.no",
    description="Provreq vulnerability chainer config generator",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    keywords="provreq,vulnchain,vulnerability,aep,attack,mnemonic",
    entry_points={
        "console_scripts": [
            "provreq-build-cve-agent-promises = provreq.vulnchain.build_agent_promises:main",
        ]
    },
    # Include ini-file(s) from act/workers/etc
    include_package_date=True,
    package_data={"": ["data/*.json"]},
    packages=[
        "provreq.vulnchain",
    ],
    # https://packaging.python.org/guides/packaging-namespace-packages/#pkgutil-style-namespace-packages
    # __init__.py under all packages under in the act namespace must contain exactly string:
    # __path__ = __import__('pkgutil').extend_path(__path__, __name__)
    namespace_packages=["provreq"],
    url="https://github.com/mnemonic-no/provreq-vulnchain",
    install_requires=["caep"],
    python_requires=">=3.6, <4",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Utilities",
        "License :: OSI Approved :: ISC License (ISCL)",
    ],
)
