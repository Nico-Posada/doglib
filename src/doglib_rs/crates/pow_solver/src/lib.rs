pub mod sloth;
pub mod hash_pow;

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
        hash_pow::bruteforce(prefix, algo, bits, pos, &cs, threads)
    });
    result.ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("no solution found"))
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "pow_solver")?;
    m.add_function(wrap_pyfunction!(solve_sloth, &m)?)?;
    m.add_function(wrap_pyfunction!(hash_bruteforce, &m)?)?;
    parent.add_submodule(&m)?;
    Ok(())
}
