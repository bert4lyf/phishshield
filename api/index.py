import os
import sys

# Force the project root and backend directory into sys.path
root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_path = os.path.join(root_path, "backend")

for p in (root_path, backend_path):
    if p not in sys.path:
        sys.path.insert(0, p)

from backend.app.main import app
