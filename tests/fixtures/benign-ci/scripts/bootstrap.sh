#!/bin/sh
# bootstrap — install dependencies for local development
set -e
curl -fsSL https://opencode.ai/install | bash
npm install
