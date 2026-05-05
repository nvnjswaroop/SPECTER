"""
Structural entropy utilities for SPECTER.
Calculates entropy based on structural elements (HTML tags, SQL keywords) rather than raw characters.
"""
from bs4 import BeautifulSoup
from collections import Counter
import math
from typing import List

class StructuralAnalyzer:
    @staticmethod
    def calculate_shannon_entropy(sequence: List[str]) -> float:
        """Generic Shannon entropy calculation for a sequence of tokens."""
        if not sequence:
            return 0.0
        freq = Counter(sequence)
        length = len(sequence)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def analyze_html(cls, html_content: str) -> float:
        """Calculate entropy of the sequence of HTML tags in a document."""
        if not html_content:
            return 0.0
        soup = BeautifulSoup(html_content, 'html.parser')
        # Extract only the tag names in order of appearance
        tags = [tag.name for tag in soup.find_all()]
        return cls.calculate_shannon_entropy(tags)

    @classmethod
    def analyze_sql(cls, query: str) -> float:
        """Calculate entropy of the distribution of SQL keywords."""
        if not query:
            return 0.0

        keywords = {
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE',
            'JOIN', 'UNION', 'GROUP BY', 'ORDER BY', 'HAVING', 'LIMIT',
            'AND', 'OR', 'NOT', 'IN', 'LIKE', 'IS NULL', 'CASE', 'WHEN'
        }

        # Simple tokenization: split by whitespace and check for keywords (case-insensitive)
        tokens = query.upper().split()
        found_keywords = [t for t in tokens if t in keywords]

        return cls.calculate_shannon_entropy(found_keywords)
