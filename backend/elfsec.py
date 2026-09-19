"""ElfSec tek-dosya exe giriş noktası (PyInstaller bunu paketler)."""
from app.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
