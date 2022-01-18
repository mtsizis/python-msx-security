#
# Copyright (c) 2021 Cisco Systems, Inc and its affiliates
# All rights reserved
#
import os.path
from setuptools import setup, find_packages


setup(
    name='msxsecurity',
    version='0.1.0',
    author="Cisco MSX",
    description="A package to exchange an MSX access token for an MSX security context, to support implementation of RBAC and tenancy in RESTful APIs.",
    include_package_data=True,
    package_dir={"": "src"},
    packages=find_packages(),
    python_requires=">=3.0",
    install_requires=[
        "urllib3==1.26.5",
        "cachetools==4.2.2",
        "requests==2.25.1"
    ],
)
