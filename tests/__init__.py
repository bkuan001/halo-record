"""Test suite for halo-record.

Puts ``src/`` on ``sys.path`` so the suite runs against the working tree with no
install step (``python -m unittest discover -s tests`` just works), matching the
package's zero-dependency, stdlib-only stance.
"""

import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
