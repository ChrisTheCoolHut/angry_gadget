#!/usr/bin/env python

from setuptools import setup

setup(name='angry_gadget',
      version='1.0',
      description='Finds the libc one_gadget',
      author='Christopher Roberts',
      author_email='roberts.michael.christopher@gmail.com',
      url='https://github.com/ChrisTheCoolHut/angry_gadget',
      scripts=['angry_gadget.py'],
      include_package_data=True,
      install_requires=[
          "angr",
          "termcolor",
          "tqdm",
          ],
     )
