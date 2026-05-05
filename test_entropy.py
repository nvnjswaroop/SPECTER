#!/usr/bin/env python3
"""
Test script to verify Shannon entropy enhancement implementation
"""

import sys
import os
sys.path.append('.')

from core.entropy import shannon_entropy, relative_entropy, calculate_distribution, kl_divergence
from core.structural_entropy import StructuralAnalyzer

def test_entropy_functions():
    """Test the entropy functions to ensure they work correctly"""

    # Test basic shannon entropy
    test_string = "Hello, World!"
    entropy = shannon_entropy(test_string)
    print(f"Shannon entropy of '{test_string}': {entropy}")

    # Test calculate_distribution
    dist = calculate_distribution(test_string)
    print(f"Character distribution: {dist}")

    # Test KL divergence
    dist_a = {'a': 0.5, 'b': 0.3, 'c': 0.2}
    dist_b = {'a': 0.5, 'b': 0.4, 'd': 0.1}
    kl_div = kl_divergence(dist_a, dist_b)
    print(f"KL divergence: {kl_div}")

    # Test relative entropy
    rel_entropy = relative_entropy("test1", "test2")
    print(f"Relative entropy: {rel_entropy}")

    # Test structural entropy
    html_content = "<html><head><title>Test</title></head><body><p>Hello <b>World</b></p></body></html>"
    struct_entropy = StructuralAnalyzer.analyze_html(html_content)
    print(f"Structural entropy of HTML: {struct_entropy}")

    # Test structural analysis of SQL
    sql_query = "SELECT * FROM users WHERE id = 1"
    sql_entropy = StructuralAnalyzer.analyze_sql(sql_query)
    print(f"SQL structural entropy: {sql_entropy}")

if __name__ == "__main__":
    test_entropy_functions()