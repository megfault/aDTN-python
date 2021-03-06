#!/usr/bin/env python3

"""
setup.py file for aDTN-python
"""

from setuptools import setup, find_packages

setup(name='pyadtn',
      version='0.1.0',
      author="Ana Barroso",
      author_email="meg@megfau.lt",
      description="""Anonymous delay tolerant networking library""",
      url="https://github.com/megfault/aDTN-python",
      license="AGPL3",
      packages=find_packages(exclude=['tests', 't', 'doc']),
      classifiers=[
          'Programming Language :: Python :: 3',
          'License :: OSI Approved :: GNU Affero General Public License v3',
      ],
      dependency_links=[
          "git+https://github.com/synnefy/scapy.git@master#egg=scapy-python3"
      ],
      install_requires=[
          "scapy-python3",
          "pynacl",
          "tinydb",
          "pyric"
      ]
      )
