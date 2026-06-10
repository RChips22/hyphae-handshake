use rand_core::{CryptoRng, Error, OsRng, RngCore};
use std::sync::Arc;

/// Marker trait for secure random number generators.
///
/// Blanket-implemented for every type that implements `RngCore + CryptoRng + Send`.
pub trait SecureRng: RngCore + CryptoRng + Send {}

impl<T: RngCore + CryptoRng + Send> SecureRng for T {}

/// Concrete wrapper that delegates `RngCore` to a boxed `dyn SecureRng`.
///
/// `HandshakeInfo::initialize` takes `impl RngCore + CryptoRng` (Sized),
/// but `RngFactory` returns trait objects. This wrapper bridges the gap.
pub(crate) struct DynRng(Box<dyn SecureRng>);

impl DynRng {
    pub(crate) fn new(rng: Box<dyn SecureRng>) -> Self {
        Self(rng)
    }
}

impl RngCore for DynRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for DynRng {}

/// Factory that creates new secure random number generator instances.
///
/// Each call to the factory produces a fresh, independent RNG.
/// The default uses `OsRng`.
pub type RngFactory = Arc<dyn Fn() -> Box<dyn SecureRng> + Send + Sync>;

/// Returns the default RNG factory backed by `OsRng`.
pub fn default_rng_factory() -> RngFactory {
    Arc::new(|| Box::new(OsRng))
}
