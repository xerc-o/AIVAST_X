from typing import Dict, List
from .base import BaseAnalyzer
from .structured_parser import extract_structured_data
import json

class NiktoAnalyzer(BaseAnalyzer):
    tool_name = "nikto"

    def build_prompt(self, data: dict) -> str:
        execution = data.get("execution", {})
        stdout = execution.get("stdout", "")
        stderr = execution.get("stderr", "")
        
        # Coba extract structured data
        structured = extract_structured_data("nikto", stdout, stderr)
        
        # Jika berhasil parse, gunakan structured data
        if structured.get("parsed"):
            structured_summary = f"""
Parsed Nikto Data:
- Target: {structured.get('target', {}).get('targetip', 'N/A')}
- Items found: {len(structured.get('items', []))}
- Statistics: {json.dumps(structured.get('statistics', {}), indent=2)}

Vulnerabilities/Issues:
{json.dumps(structured.get('items', []), indent=2)}
"""
            nikto_data = structured_summary
        else:
            nikto_data = f"Stdout: {stdout}\n\nStderr: {stderr}"

        return f"""
You are a web security analyst. Your goal is to analyze the Nikto scan results and provide a clear, concise, and actionable security report.

Return ONLY valid JSON.
DO NOT include explanations outside the JSON.
DO NOT use markdown formatting (e.g., ```json).

JSON schema:
{{
  "risk": "info|low|medium|high|critical",
  "summary": "A comprehensive summary of the key findings, potential vulnerabilities, and the overall security posture based on the Nikto output. This summary should clearly state the most important security implications.",
  "findings": [
    {{
      "id": "string (Nikto ID)",
      "description": "string (Description of vulnerability)",
      "uri": "string (Affected URI)",
      "severity": "low|medium|high|critical",
      "recommendation": "string (Specific recommendation to fix)"
    }}
  ],
  "recommendations": [
    "string (general high-level recommendations, e.g., 'Ensure all web server headers are properly configured', 'Regularly patch web applications')",
    "string"
  ]
}}

Nikto output:
{nikto_data}

Based on the Nikto output provided, generate the JSON response. Pay close attention to common web server misconfigurations, missing security headers, known vulnerabilities, and potential information leaks. If specific CVEs or detailed recommendations are not immediately apparent from the Nikto output alone, provide general security best practices relevant to the identified issues.
"""