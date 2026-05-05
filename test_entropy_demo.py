#!/usr/bin/env python3
"""
Demo script to showcase Shannon entropy enhancement
"""

import sys
import os
sys.path.append('.')

# Import the entropy functions
from core.entropy import shannon_entropy, relative_entropy, calculate_distribution, kl_divergence
from core.structural_entropy import StructuralAnalyzer

def demo_entropy_features():
    """Demo the Shannon entropy enhancement features"""

    # Test strings for entropy comparison
    test_string1 = "This is a normal string with low entropy"
    test_string2 = "X5Fg!@#KLMN&*()_+"  # High entropy string

    print("=== Shannon Entropy Enhancement Demo ===")
    print(f"String 1: '{test_string1}'")
    print(f"  Shannon entropy: {shannon_entropy(test_string1):.4f}")
    print(f"  Character distribution: {calculate_distribution(test_string1)}")

    print(f"String 2: '{test_string2}'")
    print(f"  Shannon entropy: {shannon_entropy(test_string2):.4f}")
    print(f"  Character distribution: {calculate_distribution(test_string2)}")

    # Calculate relative entropy between the two strings
    rel_entropy = relative_entropy(test_string1, test_string2)
    print(f"Relative entropy between strings: {rel_entropy:.4f}")

    # Test structural entropy
    html_content = "<html><head><title>Test</title></head><body><p>Hello <b>World</b></p></body></html>"
    sql_query = "SELECT * FROM users WHERE id = 1"

    print(f"HTML structural entropy: {StructuralAnalyzer.analyze_html(html_content):.4f}")
    print(f"SQL structural entropy: {StructuralAnalyzer.analyze_sql(sql_query):.4f}")

if __name__ == "__main__":
    demo_entropy_features()