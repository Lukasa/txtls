#!/usr/bin/env python
from setuptools import setup, find_packages

long_description = (
    open("README.rst").read() + '\n\n' + open("HISTORY.rst").read()
)
short_description = (
    "A library that allows the use of arbitrary TLS implementations with "
    "Twisted via PEP 543"
)


setup(
    name="txtls",
    version="0.0.1",
    description=short_description,
    long_description=long_description,
    url="https://github.com/Lukasa/txtls",
    license="MIT",

    author="Cory Benfield",
    author_email="cory@lukasa.co.uk",

    install_requires=[
        "twisted>=16.5",
    ],

    packages=find_packages('src'),
    package_dir={'': 'src'},
    zip_safe=False,

    classifiers=[
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
    ]
)
