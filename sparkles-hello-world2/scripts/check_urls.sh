#!/bin/sh

cd /app || exit 1

exec python app.py --check-urls
