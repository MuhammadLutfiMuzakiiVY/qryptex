use std::time::Instant;

/// Statistical timing leak detection report (Welch's t-test / dudect methodology)
#[derive(Debug, Clone)]
pub struct TimingAuditReport {
    pub num_samples: usize,
    pub t_statistic: f64,
    pub max_t_statistic: f64,
    pub is_leak_detected: bool,
}

/// Compute Welch's t-statistic between two measurement distributions
pub fn welch_t_test(group_a: &[f64], group_b: &[f64]) -> f64 {
    let n_a = group_a.len() as f64;
    let n_b = group_b.len() as f64;
    if n_a < 2.0 || n_b < 2.0 {
        return 0.0;
    }

    let mean_a = group_a.iter().sum::<f64>() / n_a;
    let mean_b = group_b.iter().sum::<f64>() / n_b;

    let var_a = group_a.iter().map(|x| (x - mean_a).powi(2)).sum::<f64>() / (n_a - 1.0);
    let var_b = group_b.iter().map(|x| (x - mean_b).powi(2)).sum::<f64>() / (n_b - 1.0);

    let denom = (var_a / n_a + var_b / n_b).sqrt();
    if denom == 0.0 {
        0.0
    } else {
        (mean_a - mean_b) / denom
    }
}

/// Run timing audit on two closures (e.g. valid ciphertext vs invalid ciphertext)
pub fn run_timing_audit<F1, F2>(mut func_a: F1, mut func_b: F2, iterations: usize) -> TimingAuditReport
where
    F1: FnMut(),
    F2: FnMut(),
{
    let mut times_a = Vec::with_capacity(iterations);
    let mut times_b = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start_a = Instant::now();
        func_a();
        times_a.push(start_a.elapsed().as_nanos() as f64);

        let start_b = Instant::now();
        func_b();
        times_b.push(start_b.elapsed().as_nanos() as f64);
    }

    let t_stat = welch_t_test(&times_a, &times_b);
    let abs_t = t_stat.abs();

    // In standard dudect methodology, |t| > 4.5 indicates a timing leak with high statistical confidence
    let is_leak_detected = abs_t > 4.5;

    TimingAuditReport {
        num_samples: iterations,
        t_statistic: t_stat,
        max_t_statistic: abs_t,
        is_leak_detected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_audit_mock() {
        let report = run_timing_audit(|| {
            let mut x = 0;
            for i in 0..100 { x += i; }
            std::hint::black_box(x);
        }, || {
            let mut y = 0;
            for j in 0..100 { y += j; }
            std::hint::black_box(y);
        }, 500);

        // Identical operations should not trigger timing leak threshold
        assert!(!report.is_leak_detected);
    }
}
