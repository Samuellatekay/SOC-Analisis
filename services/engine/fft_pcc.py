"""
Fast Fourier Transform - Pearson Correlation Coefficient (FFT-PCC) Periodic Noise Detector.
Directly implements Equations (4), (5), (6) and Algorithm 1 from Guo et al. (2026).
"""

from typing import List, Tuple
import numpy as np

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))

from packages.contracts.models import FFTAnalysisResult, PCCAnalysisResult


class FFTPCCDetector:
    def __init__(
        self,
        peak_dominance_threshold: float = 3.0,
        pcc_threshold: float = 0.85,
        min_period_hours: float = 2.0,
        max_period_hours: float = 72.0,
        eps: float = 1e-6,
    ):
        self.peak_dominance_threshold = peak_dominance_threshold  # rho_g >= 3.0
        self.pcc_threshold = pcc_threshold  # r_g > 0.85
        self.min_period_hours = min_period_hours
        self.max_period_hours = max_period_hours
        self.eps = eps

    def analyze_fft(self, hourly_series: List[float]) -> FFTAnalysisResult:
        """
        Calculates FFT spectrum, checks peak dominance criterion (rho_g >= 3.0),
        and verifies if candidate period is within 2 to 72 hours.
        """
        N = len(hourly_series)
        if N < 8:
            return FFTAnalysisResult(
                dominant_peak_ratio=0.0,
                candidate_period_hours=0.0,
                is_periodic_candidate=False,
                details=f"Insufficient time-series length ({N} hours). Need at least 8 hours.",
            )

        signal = np.array(hourly_series, dtype=float)
        
        # Check if signal is entirely zero or flat
        if np.all(signal == signal[0]):
            return FFTAnalysisResult(
                dominant_peak_ratio=0.0,
                candidate_period_hours=0.0,
                is_periodic_candidate=False,
                details="Flat signal; no harmonic periodicity.",
            )

        # Eq (4): X_g(k) = F{x_g(h)}
        fft_values = np.fft.rfft(signal)
        amplitudes = np.abs(fft_values)

        # Remove zero-frequency (DC) component
        amplitudes[0] = 0.0

        if len(amplitudes) <= 1:
            return FFTAnalysisResult(
                dominant_peak_ratio=0.0,
                candidate_period_hours=0.0,
                is_periodic_candidate=False,
                details="No non-zero frequency bins available.",
            )

        k_star = int(np.argmax(amplitudes))
        max_amplitude = amplitudes[k_star]

        # Calculate mean non-dominant spectral amplitude
        non_dominant = np.delete(amplitudes, [0, k_star])
        mean_non_dominant = float(np.mean(non_dominant)) if len(non_dominant) > 0 else 0.0

        # Eq (5): rho_g = |X_g(k*)| / (X_bar_g + eps)
        rho_g = float(max_amplitude / (mean_non_dominant + self.eps))

        # Eq: p_g = round(N / k*)
        candidate_period = float(round(N / k_star)) if k_star > 0 else 0.0

        # Operational range: 2 to 72 hours
        in_range = self.min_period_hours <= candidate_period <= self.max_period_hours
        is_periodic = (rho_g >= self.peak_dominance_threshold) and in_range

        return FFTAnalysisResult(
            dominant_peak_ratio=round(rho_g, 4),
            candidate_period_hours=candidate_period,
            is_periodic_candidate=is_periodic,
            details=(
                f"Peak dominance ratio={rho_g:.2f} (threshold >={self.peak_dominance_threshold}), "
                f"Candidate period={candidate_period}h (range [{self.min_period_hours}, {self.max_period_hours}]h)."
            ),
        )

    def analyze_pcc(self, hourly_series: List[float], candidate_period_hours: float) -> PCCAnalysisResult:
        """
        Implements Equation (6):
        r_g = 2 / (M * (M - 1)) * sum_{u < v} rho_uv
        Segments the time series by candidate period p_g and calculates average pairwise Pearson correlation.
        """
        p = int(round(candidate_period_hours))
        N = len(hourly_series)

        if p <= 0 or N < 2 * p:
            return PCCAnalysisResult(
                mean_pairwise_correlation=0.0,
                is_stable_periodic=False,
                details=f"Cannot segment: series length {N} < 2 * period {p}.",
            )

        M = N // p
        if M < 2:
            return PCCAnalysisResult(
                mean_pairwise_correlation=0.0,
                is_stable_periodic=False,
                details=f"Not enough segments: M={M} < 2.",
            )

        segments = []
        for i in range(M):
            seg = np.array(hourly_series[i * p : (i + 1) * p], dtype=float)
            segments.append(seg)

        # Pairwise correlations
        correlations = []
        for u in range(M):
            for v in range(u + 1, M):
                seg_u = segments[u]
                seg_v = segments[v]
                std_u = np.std(seg_u)
                std_v = np.std(seg_v)

                if std_u < self.eps or std_v < self.eps:
                    # Identical or near-flat signals
                    if np.allclose(seg_u, seg_v, atol=1e-3):
                        correlations.append(1.0)
                    else:
                        correlations.append(0.0)
                else:
                    r = np.corrcoef(seg_u, seg_v)[0, 1]
                    if np.isnan(r):
                        r = 0.0
                    correlations.append(float(r))

        if not correlations:
            return PCCAnalysisResult(
                mean_pairwise_correlation=0.0,
                is_stable_periodic=False,
                details="No valid subsequence pairs to compare.",
            )

        r_g = float(np.mean(correlations))
        is_stable = r_g > self.pcc_threshold

        return PCCAnalysisResult(
            mean_pairwise_correlation=round(r_g, 4),
            is_stable_periodic=is_stable,
            details=f"Mean pairwise Pearson r_g={r_g:.3f} across {M} cycles (threshold > {self.pcc_threshold}).",
        )
