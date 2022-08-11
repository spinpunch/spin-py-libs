import io
import os

from setuptools import find_packages, setup

__version__ = "0.5.6"

def read_from(file):
    reply = []
    with io.open(os.path.join(here, file), encoding='utf8') as f:
        for line in f:
            line = line.strip()
            if not line:
                break
            if line[:2] == '-r':
                reply += read_from(line.split(' ')[1])
                continue
            if line[0] != '#' or line[:2] != '//':
                reply.append(line)
    return reply

here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, 'README.md'), encoding='utf8') as f:
    README = f.read()

setup(
    name="spinlibs",
    version=__version__,
    packages=find_packages(),
    description='SpinPunch Python utility libraries',
    long_description=README,
    classifiers=[
        "Topic :: Internet :: WWW/HTTP",
        "Programming Language :: Python :: Implementation :: PyPy",
        'Programming Language :: Python',
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
    ],
    keywords='push webpush publication',
    author="Battlehouse Inc.",
    author_email="support@battlehouse.com",
    url='https://github.com/spinpunch/spin-py-libs',
    license="MIT",
    include_package_data=True,
    zip_safe=False,
    install_requires=read_from('requirements.txt'),
    # tests_require=read_from('test-requirements.txt'),
    entry_points="""
    [console_scripts]
    """,
)
