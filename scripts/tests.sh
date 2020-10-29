#!/usr/bin/env bash

pytest --cov=tests --cov-report=term-missing --cov-report=html -v
