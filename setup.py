#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import ast
from setuptools import setup, find_packages

with open('README.md') as readme_file:
    readme = readme_file.read()


_version_re = re.compile(r'__version__\s+=\s+(.*)')


with open('pastebot/__init__.py', 'rb') as f:
    version = str(ast.literal_eval(_version_re.search(
        f.read().decode('utf-8')).group(1)))


requirements = [
    "click==6.7",
    "requests==2.18.4",
    "raven==6.1.0",
    "yara-python==3.6.3"
]

setup(
    name='pastebot',
    version=version,
    description="pastebot",
    long_description=readme,
    author="fate0",
    author_email='fate0@fatezero.org',
    url='https://github.com/fate0/pastebot',
    packages=find_packages(),
    package_dir={},
    entry_points={
        'console_scripts': [
            'pastebot=pastebot.cli:main'
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    license="BSD license",
    zip_safe=False,
    keywords='pastebot',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Browsers'
    ],
)
