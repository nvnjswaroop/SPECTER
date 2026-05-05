"""
Entropy utilities for SPECTER.
Provides a Shannon entropy calculation and helper to compute average/max entropy of a list of payload strings.
"""
import math
from collections import Counter
from typing import List, Tuple


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string.
    Returns entropy in bits per character.
    """
    if not s:
        return 0.0
    # Count character frequencies
    freq = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def calculate_distribution(s: str) -> dict:
    """Calculate the probability distribution of characters in a string."""
    if not s:
        return {}
    freq = Counter(s)
    length = len(s)
    return {char: count / length for char, count in freq.items()}


def kl_divergence(p: dict, q: dict) -> float:
    """
    Calculate Kullback-Leibler Divergence between two distributions.
    Uses Laplace smoothing to avoid division by zero or log(0).
    """
    # Combine all keys from both distributions for the union
    all_chars = set(p.keys()).union(set(q.keys()))
    epsilon = 1e-10  # Smoothing factor
    divergence = 0.0

    for char in all_chars:
        # Use Laplace smoothing: (count + epsilon) / (total + epsilon * vocabulary_size)
        # Simplified here as p.get(char, epsilon) for the relative frequency
        p_val = p.get(char, epsilon)
        q_val = q.get(char, epsilon)
        divergence += p_val * math.log2(p_val / q_val)

    return divergence


def relative_entropy(text_a: str, text_b: str) -> float:
    """High-level wrapper to calculate KL divergence between two strings."""
    dist_a = calculate_distribution(text_a)
    dist_b = calculate_distribution(text_b)
    return kl_divergence(dist_a, dist_b)


def entropy_score(payloads: List[str]) -> Tuple[float, float]:
    """Return (average_entropy, max_entropy) for a list of payload strings.
    Useful for assessing overall payload quality.
    """
    if not payloads:
        return 0.0, 0.0
    entropies = [shannon_entropy(p) for p in payloads]
    avg = sum(entropies) / len(entropies)
    mx = max(entropies)
    return avg, mx
