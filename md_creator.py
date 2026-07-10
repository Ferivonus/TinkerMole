import json
from pathlib import Path
from datetime import datetime
from typing import Optional


class MarkdownReportGenerator:
    def __init__(self, report_directory: Path, application_name: str, framework_detected: str,
                 json_report_path: Optional[Path]):
        self.report_directory = report_directory
        self.application_name = application_name
        self.framework_detected = framework_detected
        self.json_report_path = json_report_path
        self.md_file_path = self.report_directory / f"{self.application_name}_Analysis_Report.md"

        # Mapping rule prefixes to professional parent categories (No emojis)
        self.category_mapping = {
            "Cloud": "Cloud Services and Analytics",
            "AI": "AI and ML Providers",
            "Payment": "Payment and FinTech Systems",
            "Database": "Databases and BaaS",
            "Comm": "Communications and Social",
            "DevOps": "DevOps and CI/CD Tools",
            "Auth": "Security and Authentication",
            "Crypto": "Cryptography Keys",
            "Generic": "Generic Secrets and Passwords",
            "Network": "Network Routing and DeepLinks",
            "Business": "Business Logic",
            "Hardcoded": "Hardcoded Vulnerabilities"
        }

    def _determine_language(self) -> str:
        """Determines the primary programming language based on the detected framework."""
        if not self.framework_detected:
            return "Java / Kotlin (Native Android)"

        framework_lower = self.framework_detected.lower()
        if "flutter" in framework_lower:
            return "Dart"
        elif "react" in framework_lower or "cordova" in framework_lower or "ionic" in framework_lower:
            return "JavaScript / TypeScript"
        return "Unknown"

    def _extract_company_name(self) -> str:
        """Attempts to extract the developer or company name from the application package name."""
        parts = self.application_name.split('.')
        if len(parts) >= 3 and parts[0] in ['com', 'org', 'net']:
            return parts[1].capitalize()
        return "Unknown (Check Package Name)"

    def _sanitize_markdown(self, text: str) -> str:
        """Removes characters that can break Markdown table formatting."""
        if not text:
            return "Unknown"
        # Convert to string, remove newlines, carriage returns, and escape pipe characters
        return str(text).replace('\n', ' ').replace('\r', '').replace('|', '&#124;')

    def generate_report(self) -> Path:
        """Generates the Markdown report and returns the path to the saved file."""
        language = self._determine_language()
        company_name = self._extract_company_name()
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        scan_results = {}
        total_issues = 0

        # Load the JSON Master Report if it exists
        if self.json_report_path and self.json_report_path.exists():
            try:
                with open(self.json_report_path, 'r', encoding='utf-8') as f:
                    scan_results = json.load(f)
                total_issues = sum(len(items) for items in scan_results.values())
            except Exception:
                pass

        # Group results by parent category
        grouped_results = {}
        for raw_category, items in scan_results.items():
            if not items:
                continue

            prefix = raw_category.split('_')[0] if '_' in raw_category else "Other"
            parent_category_name = self.category_mapping.get(prefix, "Miscellaneous Findings")

            if parent_category_name not in grouped_results:
                grouped_results[parent_category_name] = []

            grouped_results[parent_category_name].append({
                "sub_category": raw_category,
                "findings": items
            })

        # --- BUILD MARKDOWN CONTENT ---
        md_content = f"# Security and Architecture Report: {self.application_name}\n\n"
        md_content += "---\n\n"

        # Section 1: Application Overview
        md_content += "## Application Overview\n\n"
        md_content += "| Attribute | Details |\n"
        md_content += "| :--- | :--- |\n"
        md_content += f"| **Target Name** | `{self.application_name}` |\n"
        md_content += f"| **Developer / Company** | `{company_name}` |\n"
        md_content += f"| **UI Framework** | `{self.framework_detected or 'Native Android'}` |\n"
        md_content += f"| **Primary Language** | `{language}` |\n"
        md_content += f"| **Scan Date** | `{current_date}` |\n\n"
        md_content += "---\n\n"

        # Section 2: Scan Summary & Table of Contents
        md_content += "## Scan Summary\n\n"
        if total_issues == 0:
            md_content += "**Status:** CLEAN - No sensitive data, tokens, or secrets were detected based on the current ruleset.\n\n"
        else:
            md_content += f"**Status:** ACTION REQUIRED - Found **{total_issues}** potential vulnerabilities/secrets.\n\n"

            # Generate Table of Contents
            md_content += "### Table of Contents\n"
            for parent_cat in grouped_results.keys():
                # Create a markdown anchor link (lowercase, spaces to dashes, remove special chars)
                anchor = parent_cat.lower().replace(' ', '-').replace('&', '').replace(',', '')
                # Clean up multiple dashes that might result from replacing spaces around ampersands
                while '--' in anchor:
                    anchor = anchor.replace('--', '-')
                md_content += f"- [{parent_cat}](#{anchor})\n"
            md_content += "\n---\n\n"

        # Section 3: Detailed Grouped Findings
        if total_issues > 0:
            md_content += "## Detailed Findings\n\n"

            for parent_cat, sub_categories in grouped_results.items():
                md_content += f"### {parent_cat}\n\n"

                for sub_cat_data in sub_categories:
                    rule_name = sub_cat_data["sub_category"]
                    items = sub_cat_data["findings"]

                    md_content += f"#### Rule: `{rule_name}` ({len(items)} items)\n\n"
                    md_content += "| # | Found Value / Secret | File Location |\n"
                    md_content += "| :---: | :--- | :--- |\n"

                    for index, item in enumerate(items, start=1):
                        val = self._sanitize_markdown(item.get('found_value'))
                        loc = self._sanitize_markdown(item.get('file_location'))

                        md_content += f"| {index} | `{val}` | `{loc}` |\n"

                    md_content += "\n<br>\n\n"

        # Save to file
        with open(self.md_file_path, "w", encoding="utf-8") as md_file:
            md_file.write(md_content)

        return self.md_file_path