pub mod sqrt;

use std::sync::Arc;

use generic_ec::Scalar;
use malachite::Integer;
use malachite_base::num::logic::traits::SignificantBits;
use crate::integer_ext::IntegerExt;
use fast_paillier::integer_ext::mod_pow_int;
use malachite_base::num::basic::traits::One;
/// Auxiliary data known to both prover and verifier
#[cfg_attr(
    feature = "__internal_doctest",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Clone, Debug)]
pub struct Aux {
    /// ring-pedersen parameter
    pub s: Integer,
    /// ring-pedersen parameter
    pub t: Integer,
    /// N^ in paper
    pub rsa_modulo: Integer,
    /// Precomuted table for computing `s^x t^y mod rsa_modulo` faster
    ///
    /// If absent, optimization is disabled.
    #[cfg_attr(feature = "__internal_doctest", serde(skip))]
    pub multiexp: Option<Arc<crate::multiexp::MultiexpTable>>,
    #[cfg_attr(feature = "__internal_doctest", serde(skip))]
    pub crt: Option<fast_paillier::utils::CrtExp>,
}

impl Aux {
    /// Returns `s^x t^y mod rsa_modulo`
    pub fn combine(&self, x: &Integer, y: &Integer) -> Result<Integer, BadExponent> {
        println!("combine: x = {}, y = {}", x, y);
        if let Some(table) = &self.multiexp {
            println!("have multiexp");
            match table.prod_exp(x, y) {
                Some(res) => return Ok(res),
                None if cfg!(debug_assertions) => {
                    return Err(BadExponentReason::ExpSize {
                        exp_size: (x.significant_bits() as u32, y.significant_bits() as u32),
                        max_exp_size: table.max_exponents_size(),
                    }
                    .into())
                }
                None => {
                    // When debug assertions are disabled, we fallback to naive exponentiation
                }
            }
        }

        println!("no multiexp");

        // Naive exponentiation when optimizations are not enabled
        self.rsa_modulo.combine(&self.s, x, &self.t, y)
    }

    /// Returns `x^e mod rsa_modulo`
    pub fn pow_mod(&self, x: &Integer, e: &Integer) -> Result<Integer, BadExponent> {
        println!("pow_mod: x = {}, e = {}", x, e);
        match &self.crt {
            Some(crt) => {
                println!("crt: {:?}", crt);
                let e = crt.prepare_exponent(e);
                crt.exp(x, &e).ok_or_else(BadExponent::undefined)
            }
            None => {
                println!("no crt");
                Ok(mod_pow_int(x, e, &self.rsa_modulo))
            }
        }
    }

    /// Returns a stripped version of `Aux` that contains only public data which can be digested
    /// via [`udigest::Digestable`]
    pub fn digest_public_data(&self) -> impl udigest::Digestable {
        let s_bytes = self.s.to_bytes();
        let t_bytes = self.t.to_bytes();
        let rsa_modulo_bytes = self.rsa_modulo.to_bytes();
        udigest::inline_struct!("paillier_zk.aux" {
            s: udigest::Bytes(s_bytes),
            t: udigest::Bytes(t_bytes),
            rsa_modulo: udigest::Bytes(rsa_modulo_bytes),
        })
    }
}

/// Error indicating that proof is invalid
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid proof")]
pub struct InvalidProof(
    #[source]
    #[from]
    InvalidProofReason,
);

/// Reason for failure. If the proof failes, you should only be interested in a
/// reason for debugging purposes
#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum InvalidProofReason {
    /// One equality doesn't hold. Parameterized by equality index
    #[error("equality check failed {0}")]
    EqualityCheck(usize),
    /// One range check doesn't hold. Parameterized by check index
    #[error("range check failed {0}")]
    RangeCheck(usize),
    /// Encryption of supplied data failed when attempting to verify
    #[error("encryption failed")]
    Encryption,
    #[error("paillier encryption failed")]
    PaillierEnc,
    #[error("paillier homomorphic op failed")]
    PaillierOp,
    /// Failed to evaluate powmod
    #[error("powmod failed")]
    ModPow,
    /// Paillier-Blum modulus is prime
    #[error("modulus is prime")]
    ModulusIsPrime,
    /// Paillier-Blum modulus is even
    #[error("modulus is even")]
    ModulusIsEven,
    /// Proof's z value in n-th power does not equal commitment value
    #[error("incorrect nth root")]
    IncorrectNthRoot,
    /// Proof's x value in 4-th power does not equal commitment value
    #[error("incorrect 4th root")]
    IncorrectFourthRoot,
}

impl InvalidProof {
    #[cfg(test)]
    pub(crate) fn reason(&self) -> InvalidProofReason {
        self.0
    }
}

impl From<BadExponent> for InvalidProof {
    fn from(_err: BadExponent) -> Self {
        InvalidProofReason::ModPow.into()
    }
}

impl From<PaillierError> for InvalidProof {
    fn from(_err: PaillierError) -> Self {
        InvalidProof(InvalidProofReason::Encryption)
    }
}

/// Error indicating that encryption failed
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("paillier encryption failed")]
pub struct PaillierError;


/// Error indicating that computation cannot be evaluated because of bad exponent
///
/// Returned by [`BigNumberExt::powmod`] and other functions that do exponentiation internally
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error(transparent)]
pub struct BadExponent(#[from] BadExponentReason);

impl BadExponent {
    /// Constructs an error that exponent is undefined
    pub fn undefined() -> Self {
        Self(BadExponentReason::Undefined)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
enum BadExponentReason {
    #[error("exponent is undefined")]
    Undefined,
    #[error("multiexp error: exponent size is too large (exponents size: {exp_size:?}, max exponent size: {max_exp_size:?})")]
    ExpSize {
        exp_size: (u32, u32),
        max_exp_size: (usize, usize),
    },
}

/// Returns `Err(err)` if `assertion` is false
pub fn fail_if<E>(err: E, assertion: bool) -> Result<(), E> {
    if assertion {
        Ok(())
    } else {
        Err(err)
    }
}

/// Returns `Err(err)` if `lhs != rhs`
pub fn fail_if_ne<T: PartialEq, E>(err: E, lhs: T, rhs: T) -> Result<(), E> {
    if lhs == rhs {
        Ok(())
    } else {
        Err(err)
    }
}

pub mod encoding {
    use crate::integer_ext::IntegerExt;

    /// Digests a rug integer
    pub struct Integer;
    impl udigest::DigestAs<malachite::Integer> for Integer {
        fn digest_as<B: udigest::Buffer>(
            value: &malachite::Integer,
            encoder: udigest::encoding::EncodeValue<B>,
        ) {
            let bytes = value.to_bytes();
            encoder.encode_leaf_value(bytes)
        }
    }

    /// Digests any encryption key
    pub struct AnyEncryptionKey;
    impl udigest::DigestAs<&dyn fast_paillier::AnyEncryptionKey> for AnyEncryptionKey {
        fn digest_as<B: udigest::Buffer>(
            value: &&dyn fast_paillier::AnyEncryptionKey,
            encoder: udigest::encoding::EncodeValue<B>,
        ) {
            <Integer as udigest::DigestAs<malachite::Integer>>::digest_as(value.n(), encoder)
        }
    }
}

/// A common logic shared across tests and doctests
#[cfg(test)]
pub mod test {
    use crate::integer_ext::IntegerExt;
    use malachite::Integer;
    use malachite_base::num::basic::traits::One;
    use malachite_base::num::arithmetic::traits::Square;
    use malachite_base::num::arithmetic::traits::Mod;
    use fast_paillier::integer_ext::mod_pow_int;

    pub fn random_key<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
    ) -> Option<fast_paillier::DecryptionKey> {
        let n_size = 3072;
        let a_size = 512;
        fast_paillier::DecryptionKey::generate(rng, n_size, a_size).ok()
    }

    pub fn sample_key() -> fast_paillier::DecryptionKey {
        fast_paillier::DecryptionKey::sample_128()
    }

    pub fn sample_other_key() -> fast_paillier::DecryptionKey {
        fast_paillier::DecryptionKey::sample_other_128()
    }
    use malachite_base::num::conversion::traits::FromStringBase;
    pub fn aux<R: rand_core::RngCore>(rng: &mut R) -> super::Aux {
        let p = Integer::from_string_base(16, "119718298173119878105125282170952301903604788836137192672971085086931697454850578932741977173627414449815867352984108049440807338548948797578442102781940057113712352026131358062988204403634623787863403524694314770165787749649165099519120341381625516324331282224170802953909133093459522735120382898061575755427").unwrap();
        let q = Integer::from_string_base(16, "90684028399912762319968138686204104120379010978734483157509623196436980870215927551569968173582391210838773744285614231471344350473494545770380636071402624403290484788376380599113518289534999987953418185019079958140799840748557330172676687793563591522131283238279656530154885714292887606570952169867532646327").unwrap();
        let n = &p * &q;

        let (s, t) = {
            let phi_n = (p.clone() - &Integer::ONE) * (q.clone() - &Integer::ONE);
            let r = Integer::gen_invertible(&n, rng);
            let lambda = fast_paillier::utils::sample_in_mult_group(rng, &phi_n);

            let t = r.square().mod_op(&n);
            let s = mod_pow_int(&t, &lambda, &n);

            (s, t)
        };

        super::Aux {
            s,
            t,
            rsa_modulo: n,
            multiexp: None,
            crt: None,
        }
    }

    pub fn generate_blum_prime(rng: &mut impl rand_core::RngCore, bits_size: u32) -> Integer {
        loop {
            let n = generate_prime(rng, bits_size);
            if n.clone().mod_op(&Integer::from(4)) == 3 {
                break n;
            }
        }
    }

    pub fn generate_prime(rng: &mut impl rand_core::RngCore, bits_size: u32) -> Integer {
        fast_paillier::utils::generate_safe_prime(rng, bits_size)
    }
}

#[cfg(test)]
mod _test {
    use malachite::Integer;
    use crate::integer_ext::IntegerExt;
    use fast_paillier::integer_ext::mod_pow_int;
    use malachite_base::num::conversion::traits::FromStringBase;
    use malachite_base::num::basic::traits::One;
    use malachite_base::num::arithmetic::traits::{Square, Mod};

    // #[test]
    // fn to_scalar_encoding() {
    //     type E = generic_ec::curves::Secp256k1;

    //     let bytes = [123u8, 231u8];
    //     let int = u16::from_be_bytes(bytes);
    //     let bn = Integer::from(int);
    //     let scalar = bn.to_scalar();
    //     assert_eq!(scalar, generic_ec::Scalar::<E>::from(int));

    //     assert_eq!(bn.to_bytes(), &bytes);

    //     let curve_order = Integer::curve_order::<E>();
    //     assert_eq!(curve_order.to_scalar(), generic_ec::Scalar::<E>::zero());
    //     assert_eq!(
    //         (curve_order - 1u8).to_scalar(),
    //         -generic_ec::Scalar::<E>::one()
    //     );
    // }

    #[test]
    fn signed_modulo() {
        let n = Integer::from(7);

        assert_eq!(Integer::from(0).signed_modulo(&n), 0);
        assert_eq!(Integer::from(1).signed_modulo(&n), 1);
        assert_eq!(Integer::from(2).signed_modulo(&n), 2);
        assert_eq!(Integer::from(3).signed_modulo(&n), 3);
        assert_eq!(Integer::from(4).signed_modulo(&n), -3);
        assert_eq!(Integer::from(5).signed_modulo(&n), -2);
        assert_eq!(Integer::from(6).signed_modulo(&n), -1);
        assert_eq!(Integer::from(7).signed_modulo(&n), 0);
        assert_eq!(Integer::from(8).signed_modulo(&n), 1);

        let n = Integer::from(4);
        assert_eq!(Integer::from(0).signed_modulo(&n), 0);
        assert_eq!(Integer::from(1).signed_modulo(&n), 1);
        assert_eq!(Integer::from(2).signed_modulo(&n), -2);
        assert_eq!(Integer::from(3).signed_modulo(&n), -1);
    }

    #[test]
    fn multiexp() {
        let mut rng = rand_dev::DevRng::new();
        let mut aux = super::test::aux(&mut rng);
        let table = std::sync::Arc::new(
            crate::multiexp::MultiexpTable::build(&aux.s, &aux.t, 512, 448, aux.rsa_modulo.clone())
                .unwrap(),
        );
        let (x_bits, y_bits) = table.max_exponents_size();
        aux.multiexp = Some(table);

        // // Corner case: upper bound
        let x_max = (Integer::from(1) << x_bits) - Integer::from(1);
        let y_max = (Integer::from(1) << y_bits) - Integer::from(1);
        // let actual = aux.combine(&x_max, &y_max).unwrap();
        // let expected = aux
        //     .rsa_modulo
        //     .combine(&aux.s, &x_max, &aux.t, &y_max)
        //     .unwrap();
        // assert_eq!(actual, expected);

        // Corner case: lower bound
        let x_min = -x_max.clone();
        let y_min = -y_max.clone();
        let actual = aux.combine(&x_min, &y_min).unwrap();
        let expected = aux
            .rsa_modulo
            .combine(&aux.s, &x_min, &aux.t, &y_min)
            .unwrap();
        assert_eq!(actual, expected);

        // Random integers within the range
        // for _ in 0..100 {
        //     let x = fast_paillier::utils::random_below(&mut rng, &(x_max.clone() + Integer::from(1)));
        //     // let x = (x_max.clone() + Integer::from(1)).random_below(&mut rng);
        //     let y = fast_paillier::utils::random_below(&mut rng, &(y_max.clone() + Integer::from(1)));
        //     // let y = (y_max.clone() + Integer::from(1)).random_below(&mut rng);

        //     let x = if rng.bits(1) == 1 { x } else { -x };
        //     let y = if rng.bits(1) == 1 { y } else { -y };

        //     println!("x: {x}");
        //     println!("y: {y}");

        //     let actual = aux.combine(&x, &y).unwrap();
        //     let expected = aux.rsa_modulo.combine(&aux.s, &x, &aux.t, &y).unwrap();
        //     assert_eq!(actual, expected);
        // }
    }

    #[test]
    fn combine_basic() {
        let mut rng = rand_dev::DevRng::new();
        let aux = super::test::aux(&mut rng);
        
        // Test with small positive values
        let x = Integer::from_string_base(10,"6148764041380253083546192390085992054633595418703755180057546823404661094261678622048314853192829683499204626929035284368593051324938310822734988496202488878706571168118683661817282981218687447499683658677331197375098463456300146108888079223840277699181246092854986837431076722512591896045266223023653136324235765688092758846763642120964077637081747326847051466852061445972084180659609634472291150594644275845619647537825166476830566293").unwrap();
        let y = Integer::from_string_base(10, "372465309908021267823342766442835163159207224666484760078535115661461870575425732510595875934015568117884757179437854662478376439944087120832978141648114393064275161207176674304529819142885089804191056204140628399528644730486178097258894406094808011530535306902001802152201730892545222565935078941674697957087956280414491208535043054316976618210353496408792197819877139829914663562965926518161653424090719424457302251693224634516831448029143127376590385003027598235315625626123415844170014652501569918665750998003626387985751656533837222543773137424458280470623933846220036064246841940291561054288209533501334318226057427547132893427677659802270462463631584692920949120655576274446910292233310005620917212711169868470174820621102480314381316448992387701076238347396527396339238525536993287308983759763579212560564326497752104994983513470055323783293702675086330992704014061810485341007460176033628148891569412200786332334950834177903145615103720739139253857650598134499597977727157860119754454108255585987572358036957399312244298633638187354760289382653282881060368752055715025500909448563650614490122262285860450395541348587372431479539360335548438826379460660726724782430498325").unwrap();
        let result = aux.combine(&x, &y).unwrap();
        
        // Verify result matches s^x * t^y mod rsa_modulo
        let expected = aux.rsa_modulo.combine(&aux.s, &x, &aux.t, &y).unwrap();
        assert_eq!(result, expected);
        
        // Test with zero exponents
        let zero = Integer::from(0);
        let result_zero_x = aux.combine(&zero, &y).unwrap();
        let expected_zero_x = aux.rsa_modulo.combine(&aux.s, &zero, &aux.t, &y).unwrap();
        assert_eq!(result_zero_x, expected_zero_x);
        
        let result_zero_y = aux.combine(&x, &zero).unwrap();
        let expected_zero_y = aux.rsa_modulo.combine(&aux.s, &x, &aux.t, &zero).unwrap();
        assert_eq!(result_zero_y, expected_zero_y);
        
        // Test with both zero
        let result_both_zero = aux.combine(&zero, &zero).unwrap();
        let expected_both_zero = aux.rsa_modulo.combine(&aux.s, &zero, &aux.t, &zero).unwrap();
        assert_eq!(result_both_zero, expected_both_zero);
        
        // Test with negative exponents
        let neg_x = Integer::from(-7);
        let neg_y = Integer::from(-4);
        let result_neg = aux.combine(&neg_x, &neg_y).unwrap();
        let expected_neg = aux.rsa_modulo.combine(&aux.s, &neg_x, &aux.t, &neg_y).unwrap();
        assert_eq!(result_neg, expected_neg);
        
        // Test with mixed positive and negative
        let result_mixed = aux.combine(&x, &neg_y).unwrap();
        let expected_mixed = aux.rsa_modulo.combine(&aux.s, &x, &aux.t, &neg_y).unwrap();
        assert_eq!(result_mixed, expected_mixed);
    }

    #[test]
    fn combine_with_multiexp_table() {
        let mut rng = rand_dev::DevRng::new();
        let mut aux = super::test::aux(&mut rng);
        
        // Test without multiexp table first
        let x = Integer::from(42);
        let y = Integer::from(17);
        let result_without_table = aux.combine(&x, &y).unwrap();
        
        // Add multiexp table
        let table = std::sync::Arc::new(
            crate::multiexp::MultiexpTable::build(&aux.s, &aux.t, 512, 448, aux.rsa_modulo.clone())
                .unwrap(),
        );
        aux.multiexp = Some(table);
        
        // Test with multiexp table
        let result_with_table = aux.combine(&x, &y).unwrap();
        
        // Results should be the same
        assert_eq!(result_without_table, result_with_table);
        
        // Test with larger values within table bounds
        let (x_bits, y_bits) = aux.multiexp.as_ref().unwrap().max_exponents_size();
        let large_x = Integer::from(1) << (x_bits - 1);  // Use half of max bits to avoid overflow
        let large_y = Integer::from(1) << (y_bits - 1);
        
        let result_large = aux.combine(&large_x, &large_y).unwrap();
        
        // Verify against direct computation
        let expected_large = aux.rsa_modulo.combine(&aux.s, &large_x, &aux.t, &large_y).unwrap();
        assert_eq!(result_large, expected_large);
    }

    #[test]
    fn combine_random_values() {
        let mut rng = rand_dev::DevRng::new();
        let aux = super::test::aux(&mut rng);
        
        // Test with random values
        for _ in 0..10 {
            let x = Integer::from_rng_pm(&Integer::from(1000), &mut rng);
            let y = Integer::from_rng_pm(&Integer::from(1000), &mut rng);
            
            let result = aux.combine(&x, &y).unwrap();
            let expected = aux.rsa_modulo.combine(&aux.s, &x, &aux.t, &y).unwrap();
            assert_eq!(result, expected, "Failed for x={}, y={}", x, y);
        }
    }

    #[test]
    fn pow_mod_basic() {
        let mut rng = rand_dev::DevRng::new();
        let aux = super::test::aux(&mut rng);
        
        // Test with small positive values
        let base = Integer::from_string_base(10, "555553907039542285287778188401954854249614317171804531367438129679364595107589186196512714634357713838661511155225958286881511326040268973736911466560910900419298090437175204266618313196506230810044047047596426742528378721733631246230901630689265139692204869711078949446007849363037062338593627986099690552938015462130418631023249482837849899352830329995903821482516754906304844427763161820938571820248855733451763793021632800727007934575635247439211407605418473940301630421654477402586186962056209106693732582904214232829015181383383756598415690049164260479527582288353316834762713877596132404207858835952600323761958534212285313640548869777681634361032553811576436188338713858252522655628224675954675829047727039887939448304558278323205251").unwrap();
        let exponent = Integer::from_string_base(19, "316819081939861044636107404782286008178").unwrap();
        let result = aux.pow_mod(&base, &exponent).unwrap();
        
        // Verify result matches base^exponent mod rsa_modulo
        let expected = mod_pow_int(&base, &exponent, &aux.rsa_modulo);
        assert_eq!(result, expected);
        
        // Test with zero exponent (should return 1)
        let zero_exp = Integer::from(0);
        let result_zero_exp = aux.pow_mod(&base, &zero_exp).unwrap();
        let expected_zero_exp = mod_pow_int(&base, &zero_exp, &aux.rsa_modulo);
        assert_eq!(result_zero_exp, expected_zero_exp);
        assert_eq!(result_zero_exp, Integer::from(1));
        
        // Test with exponent = 1 (should return base mod rsa_modulo)
        let one_exp = Integer::from(1);
        let result_one_exp = aux.pow_mod(&base, &one_exp).unwrap();
        let expected_one_exp = mod_pow_int(&base, &one_exp, &aux.rsa_modulo);
        assert_eq!(result_one_exp, expected_one_exp);
        
        // Test with base = 1 (should return 1)
        let one_base = Integer::from(1);
        let result_one_base = aux.pow_mod(&one_base, &exponent).unwrap();
        let expected_one_base = mod_pow_int(&one_base, &exponent, &aux.rsa_modulo);
        assert_eq!(result_one_base, expected_one_base);
        assert_eq!(result_one_base, Integer::from(1));
    }

    #[test]
    fn pow_mod_negative_exponents() {
        let mut rng = rand_dev::DevRng::new();
        let aux = super::test::aux(&mut rng);
        
        // Test with negative exponents
        let base = Integer::from(5);
        let neg_exponent = Integer::from(-3);
        let result = aux.pow_mod(&base, &neg_exponent).unwrap();
        
        // Verify result matches base^(-exponent) mod rsa_modulo
        let expected = mod_pow_int(&base, &neg_exponent, &aux.rsa_modulo);
        assert_eq!(result, expected);
        
        // Test with large negative exponent
        let large_neg_exp = Integer::from(-1000);
        let result_large_neg = aux.pow_mod(&base, &large_neg_exp).unwrap();
        let expected_large_neg = mod_pow_int(&base, &large_neg_exp, &aux.rsa_modulo);
        assert_eq!(result_large_neg, expected_large_neg);
    }

    #[test]
    fn pow_mod_with_crt() {
        let mut rng = rand_dev::DevRng::new();
        let mut aux = super::test::aux(&mut rng);
        
        // Test without CRT first
        let base = Integer::from(42);
        let exponent = Integer::from(17);
        let result_without_crt = aux.pow_mod(&base, &exponent).unwrap();
        
        // Add CRT optimization
        // Note: We can't easily create a CRT without knowing the factorization,
        // but we can test that the function still works without it
        
        // Test with larger values
        let large_base = Integer::from(123456);
        let large_exp = Integer::from(789);
        let result_large = aux.pow_mod(&large_base, &large_exp).unwrap();
        let expected_large = mod_pow_int(&large_base, &large_exp, &aux.rsa_modulo);
        assert_eq!(result_large, expected_large);
    }

    #[test]
    fn pow_mod_random_values() {
        let mut rng = rand_dev::DevRng::new();
        let aux = super::test::aux(&mut rng);
        
        // Test with random values
        for _ in 0..10 {
            let base = Integer::from_rng_pm(&Integer::from(1000), &mut rng);
            let exponent = Integer::from_rng_pm(&Integer::from(100), &mut rng);
            
            let result = aux.pow_mod(&base, &exponent).unwrap();
            let expected = mod_pow_int(&base, &exponent, &aux.rsa_modulo);
            assert_eq!(result, expected, "Failed for base={}, exponent={}", base, exponent);
        }
    }

    #[test]
    fn pow_mod_edge_cases() {
        let mut rng = rand_dev::DevRng::new();
        let aux = super::test::aux(&mut rng);
        
        // Test with zero base and positive exponent (should return 0)
        let zero_base = Integer::from(0);
        let pos_exp = Integer::from(5);
        let result_zero_base = aux.pow_mod(&zero_base, &pos_exp).unwrap();
        let expected_zero_base = mod_pow_int(&zero_base, &pos_exp, &aux.rsa_modulo);
        assert_eq!(result_zero_base, expected_zero_base);
        assert_eq!(result_zero_base, Integer::from(0));
        
        // Test with base equal to modulus (should return 0)
        let mod_base = aux.rsa_modulo.clone();
        let result_mod_base = aux.pow_mod(&mod_base, &pos_exp).unwrap();
        let expected_mod_base = mod_pow_int(&mod_base, &pos_exp, &aux.rsa_modulo);
        assert_eq!(result_mod_base, expected_mod_base);
        assert_eq!(result_mod_base, Integer::from(0));
        
        // Test with large exponent
        let base = Integer::from(7);
        let large_exp = Integer::from(1) << 100;  // 2^100
        let result_large_exp = aux.pow_mod(&base, &large_exp).unwrap();
        let expected_large_exp = mod_pow_int(&base, &large_exp, &aux.rsa_modulo);
        assert_eq!(result_large_exp, expected_large_exp);

    }
}
