import sys
import os

# Garante que o Python encontre o smart_report.py na mesma pasta
sys.path.insert(0, os.path.dirname(__file__))

from smart_report import app as application
