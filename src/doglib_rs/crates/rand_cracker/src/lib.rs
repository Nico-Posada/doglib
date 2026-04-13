use pyo3::prelude::*;

mod glibc;

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "rand_cracker")?;
    glibc::register(&m)?;
    parent.add_submodule(&m)?;
    Ok(())
}
