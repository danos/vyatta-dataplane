# Public header files

## Overview
This directory contains header files that are for use by code outside
of the repository.

A few basic ground rules:
1. Don't include any private header files from these header files
2. Don't make changes that might break source code that worked fine
   against an earlier version.

Binary compatibility (source built against an earlier version of the
headers should work when run with a later version of the dataplane)
isn't a requirement at this stage, but it's best to also try to avoid
making changes that would break this.
