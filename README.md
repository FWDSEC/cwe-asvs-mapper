# CWE to ASVS Mapping Tool

Creates a flat file containing a json hash map that allows for finding relationships between CWE IDs and ASVS items.

The tests/test.py file contains example usage.

## Run with Docker

### Setup

1. clone repo
2. `cd` into repo
3. `docker build -t cwe-asvs-mapper .`

### Usage

1. `docker run -t --rm -v "$(pwd)":/shared cwe-asvs-mapper`

## Run without Docker

## Requirements

1. Python 3
2. [pipenv](https://pipenv-fork.readthedocs.io/en/latest/)

## Setup

1. clone repo
2. `cd` into repo
3. run `pipenv --three`
4. run `pipenv install`

## Usage (Python)

1. `pipenv shell`
2. `python cwe-asvs-mapper.py`