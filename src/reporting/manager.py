import json
import csv
import logging
from typing import List, Dict, Any
from .db import ScanResult

logger = logging.getLogger(__name__)

class ReportManager:
    """Handles exporting scan results to different formats."""
    
    @staticmethod
    def to_json(results: List[Dict[str, Any]], output_path: str):
        """Exports results to a JSON file."""
        try:
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=4)
            logger.info(f"Report exported to JSON: {output_path}")
        except Exception as e:
            logger.error(f"Failed to export JSON: {e}")

    @staticmethod
    def to_csv(results: List[Dict[str, Any]], output_path: str):
        """Exports results to a CSV file."""
        if not results:
            return
        
        try:
            keys = results[0].keys()
            with open(output_path, 'w', newline='') as f:
                dict_writer = csv.DictWriter(f, fieldnames=keys)
                dict_writer.writeheader()
                dict_writer.writerows(results)
            logger.info(f"Report exported to CSV: {output_path}")
        except Exception as e:
            logger.error(f"Failed to export CSV: {e}")

    @staticmethod
    def to_text_summary(results: List[Dict[str, Any]], output_path: str):
        """Exports a human-readable summary to a text file."""
        try:
            with open(output_path, 'w') as f:
                f.write("SMBSeeker Scan Report Summary\n")
                f.write("=" * 30 + "\n\n")
                
                for r in results:
                    f.write(f"Target: {r.get('target')}\n")
                    f.write(f"File: {r.get('file_path')}/{r.get('file_name')}\n")
                    f.write(f"Findings: {len(r.get('findings', []))}\n")
                    for finding in r.get('findings', []):
                        f.write(f"  - [{finding['type']}] {finding['match']}\n")
                    f.write("-" * 20 + "\n")
            logger.info(f"Report summary exported to Text: {output_path}")
        except Exception as e:
            logger.error(f"Failed to export Text summary: {e}")
