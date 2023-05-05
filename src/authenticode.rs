use digest::{Digest, Output};
use goblin::pe::PE;

pub trait Authenticode {
    fn authenticode_digest<D: Digest>(&self) -> Output<D>;
}

impl<'a> Authenticode for PE<'a> {
    fn authenticode_digest<D: Digest>(&self) -> Output<D> {
        let mut digest = D::new();

        for chunk in self.authenticode_ranges() {
            digest.update(chunk);
        }

        digest.finalize()
    }
}
