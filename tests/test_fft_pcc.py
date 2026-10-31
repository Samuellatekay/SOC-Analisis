"""
Unit tests for FFT-PCC Periodic Noise Reduction.
Tests Equations (4), (5), (6) and Algorithm 1 from Guo et al. (2026).
"""

import unittest
import numpy as np

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from services.engine.fft_pcc import FFTPCCDetector


class TestFFTPCC(unittest.TestCase):
    def test_fft_periodic_signal(self):
        """Test clean 24-hour periodic sine wave."""
        detector = FFTPCCDetector()
        hours = 72
        period = 24.0
        
        # Generate 72-hour periodic signal with period 24h
        t = np.arange(hours)
        # 3 full cycles
        series = 50.0 + 30.0 * np.sin(2 * np.pi * t / period)
        series = series.tolist()

        fft_res = detector.analyze_fft(series)
        self.assertTrue(fft_res.is_periodic_candidate)
        self.assertGreaterEqual(fft_res.dominant_peak_ratio, 3.0)
        self.assertLessEqual(abs(fft_res.candidate_period_hours - 24.0), 1.0)

        # Test PCC on the periodic series
        pcc_res = detector.analyze_pcc(series, fft_res.candidate_period_hours)
        self.assertTrue(pcc_res.is_stable_periodic)
        self.assertGreater(pcc_res.mean_pairwise_correlation, 0.85)

    def test_fft_aperiodic_noise(self):
        """Test random aperiodic noisy signal."""
        detector = FFTPCCDetector()
        np.random.seed(42)
        series = np.random.uniform(5.0, 95.0, 72).tolist()

        fft_res = detector.analyze_fft(series)
        # Random white noise should have low peak dominance ratio
        self.assertLess(fft_res.dominant_peak_ratio, 3.0)
        self.assertFalse(fft_res.is_periodic_candidate)

    def test_insufficient_length(self):
        """Test short time series."""
        detector = FFTPCCDetector()
        short_series = [10.0, 12.0, 11.0]
        fft_res = detector.analyze_fft(short_series)
        self.assertFalse(fft_res.is_periodic_candidate)


if __name__ == "__main__":
    unittest.main()
