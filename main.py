import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from agent import run

if __name__ == "__main__":
    asyncio.run(run())
