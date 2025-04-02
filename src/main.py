#!/usr/bin/env python3
"""
Cursor Pro Keep Alive - Main Entry Point
This script serves as the main entry point for the Cursor Pro Keep Alive application.
"""

import os
import sys
from utils.logger import logging
from core.cursor_pro_keep_alive import main as cursor_keep_alive_main
from ui.logo import print_logo

# Add the parent directory to the path to import the local packages
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

# Handle frozen environment (PyInstaller)
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    bundle_dir = sys._MEIPASS # type: ignore
    
    if bundle_dir not in sys.path:
        sys.path.append(bundle_dir)
    # Add the src directory in the bundle
    src_dir = os.path.join(bundle_dir, 'src')
    if os.path.exists(src_dir) and src_dir not in sys.path:
        sys.path.append(src_dir)

def main():
    """Main entry point for the application."""
    print_logo()
    logging.info("Starting Cursor Pro Keep Alive application...")
    try:
        cursor_keep_alive_main()
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
        return 1
    return 0

if __name__ == "__main__":
    main()