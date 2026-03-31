pub mod sloth;
pub mod hash_pow;
pub mod gpu;

use pyo3::prelude::*;

#[pyfunction]
fn solve_sloth(challenge: &[u8]) -> PyResult<Vec<u8>> {
    sloth::solver::solve_bytes(challenge)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
}

#[pyfunction]
#[pyo3(signature = (prefix, algorithm, bits, position, charset, threads=None))]
fn hash_bruteforce(
    py: Python<'_>,
    prefix: &[u8],
    algorithm: &str,
    bits: u32,
    position: &str,
    charset: &str,
    threads: Option<u32>,
) -> PyResult<Vec<u8>> {
    let algo = hash_pow::parse_algo(algorithm)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
    let pos = hash_pow::parse_position(position)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
    let cs = hash_pow::parse_charset(charset)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;

    let result = py.detach(|| {
        // Try GPU first (no-op when `cuda` feature is not enabled)
        #[cfg(feature = "cuda")]
        {
            let algo_str = algorithm;
            let pos_str  = position;
            if let Some(r) = gpu::bruteforce(prefix, algo_str, bits, pos_str, &cs) {
                return Some(r);
            }
        }
        hash_pow::bruteforce(prefix, algo, bits, pos, &cs, threads)
    });
    result.ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("no solution found"))
}

/// Returns "cuda", "cpu", or "unavailable" depending on what's compiled in and initialised.
#[pyfunction]
fn backend_info() -> &'static str {
    #[cfg(feature = "cuda")]
    {
        // Trigger lazy init and report result
        if gpu::bruteforce(b"probe", "sha256", 0, "leading", b"a").is_some() {
            return "cuda";
        }
        return "cuda-init-failed";
    }
    #[cfg(not(feature = "cuda"))]
    "cpu"
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "pow_solver")?;
    m.add_function(wrap_pyfunction!(solve_sloth, &m)?)?;
    m.add_function(wrap_pyfunction!(hash_bruteforce, &m)?)?;
    m.add_function(wrap_pyfunction!(backend_info, &m)?)?;
    parent.add_submodule(&m)?;
    Ok(())
}
