"""CLI entrypoint for ewscan.experiments."""

import sys
from ewscan.experiments.runner import main

if __name__ == "__main__":
    sys.exit(main())
