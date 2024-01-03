use digest::{Digest, DynDigest, Output};
use goblin::pe::PE;

pub trait Authenticode {
    fn authenticode_digest<D: Digest>(&self) -> Output<D>;
    fn authenticode_dyndigest(&self, hasher: Box<dyn DynDigest>) -> Box<[u8]>;
}

impl<'a> Authenticode for PE<'a> {
    fn authenticode_digest<D: Digest>(&self) -> Output<D> {
        let mut digest = D::new();

        for chunk in self.authenticode_ranges() {
            digest.update(chunk);
        }

        digest.finalize()
    }

    fn authenticode_dyndigest(&self, mut hasher: Box<dyn DynDigest>) -> Box<[u8]> {
        for chunk in self.authenticode_ranges() {
            hasher.update(chunk);
        }

        hasher.finalize()
    }
}
