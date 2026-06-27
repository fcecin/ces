# CES server extensions

This directory contains components written in Lua that can be installed and enabled in a CES server to extend its functionalities.

Extensions in an `./extensions` directory are scanned by a `ces` and can be enabled in a configuration file or via command-line switches. They can also be installed and enabled dynamically using the web admin interface (which itself needs to be enabled/configured first).

Extensions are privileged `builtin:compute` (L2 compute service) programs and should be used with care.
