use x509_cert::Certificate;
use goblin::pe::PE;

pub fn sign(pe: PE, _certificate: Certificate) -> PE {
    pe
}
