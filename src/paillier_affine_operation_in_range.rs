//! ZK-proof of paillier operation with group commitment in range. Called Пaff-g
//! or Raff-g in the CGGMP21 paper.
//!
//! ## Description
//!
//! A party P performs a paillier affine operation with C, Y, and X
//! obtaining `D = C*X + Y`. `X` and `Y` are encrypted values of `x` and `y`. P
//! then wants to prove that `y` and `x` are at most `L` and `L'` bits,
//! correspondingly, and P doesn't want to disclose none of the plaintexts
//!
//! Given:
//! - `key0`, `pkey0`, `key1`, `pkey1` - pairs of public and private keys in
//!   paillier cryptosystem
//! - `nonce_y`, `nonce` - nonces in paillier encryption
//! - `x`, `y` - some numbers
//! - `q`, `g` such that `<g> = Zq*` - prime order group
//! - `C` is some ciphertext encrypted by `key0`
//! - `Y = key1.encrypt(y, nonce_y)`
//! - `X = g * x`
//! - `D = oadd(enc(y, nonce), omul(x, C))` where `enc`, `oadd` and `omul` are
//!   paillier encryption, homomorphic addition and multiplication with `key0`
//!
//! Prove:
//! - `bitsize(abs(x)) <= l_x`
//! - `bitsize(abs(y)) <= l_y`
//!
//! Disclosing only: `key0`, `key1`, `C`, `D`, `Y`, `X`
//!
//! ## Example
//!
//! ```rust
//! use paillier_zk::{paillier_affine_operation_in_range as p, IntegerExt};
//! use rug::{Integer, Complete};
//! use generic_ec::{Point, curves::Secp256k1 as E};
//! # mod pregenerated {
//! #     use super::*;
//! #     paillier_zk::load_pregenerated_data!(
//! #         verifier_aux: p::Aux,
//! #         someone_encryption_key0: fast_paillier::EncryptionKey,
//! #         someone_encryption_key1: fast_paillier::EncryptionKey,
//! #     );
//! # }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Prover and verifier have a shared protocol state
//! let shared_state = "some shared state";
//!
//! let mut rng = rand_core::OsRng;
//! # let mut rng = rand_dev::DevRng::new();
//!
//! // 0. Setup: prover and verifier share common Ring-Pedersen parameters:
//!
//! let aux: p::Aux = pregenerated::verifier_aux();
//! let security = p::SecurityParams {
//!     l_x: 256,
//!     l_y: 848,
//!     epsilon: 230,
//!     q: (BigInt::from(1) << 128_u32),
//! };
//!
//! // 1. Setup: prover prepares the paillier keys
//!
//! // C and D are encrypted by this key
//! let key0: fast_paillier::EncryptionKey = pregenerated::someone_encryption_key0();
//! // Y is encrypted using this key
//! let key1: fast_paillier::EncryptionKey = pregenerated::someone_encryption_key1();
//!
//! // C is some number encrypted using key0. Neither of parties
//! // need to know the plaintext
//! let ciphertext_c = BigInt::gen_invertible(&key0.nn(), &mut rng);
//!
//! // 2. Setup: prover prepares all plaintexts
//!
//! // x in paper
//! let plaintext_x = BigInt::from_rng_pm(
//!     &(BigInt::from(1) << security.l_x),
//!     &mut rng,
//! );
//! // y in paper
//! let plaintext_y = BigInt::from_rng_pm(
//!     &(BigInt::from(1) << security.l_y),
//!     &mut rng,
//! );
//!
//! // 3. Setup: prover encrypts everything on correct keys and remembers some nonces
//!
//! // X in paper
//! let ciphertext_x = Point::<E>::generator() * plaintext_x.to_scalar();
//! // Y and ρ_y in paper
//! let (ciphertext_y, nonce_y) = key1.encrypt_with_random(
//!     &mut rng,
//!     &(plaintext_y.signed_modulo(key1.n())),
//! )?;
//! // nonce is ρ in paper
//! let (ciphertext_y_by_key1, nonce) = key0.encrypt_with_random(
//!     &mut rng,
//!     &(plaintext_y.signed_modulo(key0.n()))
//! )?;
//! // D in paper
//! let ciphertext_d = key0
//!     .oadd(
//!         &key0.omul(&plaintext_x, &ciphertext_c)?,
//!         &ciphertext_y_by_key1,
//!     )?;
//!
//! // 4. Prover computes a non-interactive proof that plaintext_x and
//! //    plaintext_y are at most `l_x` and `l_y` bits
//!
//! let data = p::Data {
//!     key0: &key0,
//!     key1: &key1,
//!     c: &ciphertext_c,
//!     d: &ciphertext_d,
//!     x: &ciphertext_x,
//!     y: &ciphertext_y,
//! };
//! let pdata = p::PrivateData {
//!     x: &plaintext_x,
//!     y: &plaintext_y,
//!     nonce: &nonce,
//!     nonce_y: &nonce_y,
//! };
//! let (commitment, proof) =
//!     p::non_interactive::prove::<E, sha2::Sha256>(
//!         &shared_state,
//!         &aux,
//!         data,
//!         pdata,
//!         &security,
//!         &mut rng,
//!     )?;
//!
//! // 5. Prover sends this data to verifier
//!
//! # use generic_ec::Curve;
//! # fn send<E: Curve>(_: &p::Data<E>, _: &p::Commitment<E>, _: &p::Proof) {  }
//! send(&data, &commitment, &proof);
//!
//! // 6. Verifier receives the data and the proof and verifies it
//!
//! # let recv = || (data, commitment, proof);
//! let (data, commitment, proof) = recv();
//! let r = p::non_interactive::verify::<E, sha2::Sha256>(
//!     &shared_state,
//!     &aux,
//!     data,
//!     &commitment,
//!     &security,
//!     &proof,
//! )?;
//! #
//! # Ok(()) }
//! ```
//!
//! If the verification succeeded, verifier can continue communication with prover

use fast_paillier::{AnyEncryptionKey, Ciphertext, Nonce};
use generic_ec::{Curve, Point};
use num_bigint::BigInt;

use fast_paillier::utils::serde_wrapper::serializable_bigint;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use crate::common::{Aux, InvalidProof};

/// Security parameters for proof. Choosing the values is a tradeoff between
/// speed and chance of rejecting a valid proof or accepting an invalid proof
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityParams {
    /// l in paper, bit size of +-x
    pub l_x: usize,
    /// l' in paper, bit size of +-y
    pub l_y: usize,
    /// Epsilon in paper, slackness parameter
    pub epsilon: usize,
    /// q in paper. Security parameter for challenge
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub q: BigInt,
}

/// Public data that both parties know
#[derive(Debug, Clone, Copy, udigest::Digestable)]
#[udigest(bound = "")]
pub struct Data<'a, C: Curve> {
    /// N0 in paper, public key that C was encrypted on
    #[udigest(as = crate::common::encoding::AnyEncryptionKey)]
    pub key0: &'a dyn AnyEncryptionKey,
    /// N1 in paper, public key that y -> Y was encrypted on
    #[udigest(as = crate::common::encoding::AnyEncryptionKey)]
    pub key1: &'a dyn AnyEncryptionKey,
    /// C or C0 in paper, some data encrypted on N0
    #[udigest(as = &crate::common::encoding::BigInt)]
    pub c: &'a Ciphertext,
    /// D or C in paper, result of affine transformation of C0 with x and y
    #[udigest(as = &crate::common::encoding::BigInt)]
    pub d: &'a BigInt,
    /// Y in paper, y encrypted on N1
    #[udigest(as = &crate::common::encoding::BigInt)]
    pub y: &'a Ciphertext,
    /// X in paper, obtained as g^x
    pub x: &'a Point<C>,
}

/// Private data of prover
#[derive(Clone, Copy)]
pub struct PrivateData<'a> {
    /// x or epsilon in paper, preimage of X
    pub x: &'a BigInt,
    /// y or delta in paper, preimage of Y
    pub y: &'a BigInt,
    /// rho in paper, nonce in encryption of y for additive action
    pub nonce: &'a Nonce,
    /// rho_y in paper, nonce in encryption of y to obtain Y
    pub nonce_y: &'a Nonce,
}

// As described in cggmp21 at page 35
/// Prover's first message, obtained by [`interactive::commit`]
#[derive(Debug, Clone, udigest::Digestable)]
#[udigest(bound = "")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct Commitment<C: Curve> {
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub a: BigInt,
    pub b_x: Point<C>,
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub b_y: BigInt,
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub e: BigInt,
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub s: BigInt,
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub f: BigInt,
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub t: BigInt,
}

/// Prover's data accompanying the commitment. Kept as state between rounds in
/// the interactive protocol.
#[derive(Clone)]
pub struct PrivateCommitment {
    pub alpha: BigInt,
    pub beta: BigInt,
    pub r: BigInt,
    pub r_y: BigInt,
    pub gamma: BigInt,
    pub m: BigInt,
    pub delta: BigInt,
    pub mu: BigInt,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
pub type Challenge = BigInt;

/// The ZK proof. Computed by [`interactive::prove`] or
/// [`non_interactive::prove`]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proof {
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub z1: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub z2: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub z3: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub z4: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub w: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub w_y: BigInt,
}

/// The interactive version of the ZK proof. Should be completed in 3 rounds:
/// prover commits to data, verifier responds with a random challenge, and
/// prover gives proof with commitment and challenge.
pub mod interactive {
    use crate::common::{fail_if, fail_if_ne, BigIntExt, InvalidProof, InvalidProofReason};
    use crate::Error;
    use generic_ec::{Curve, Point};
    use num_traits::Num;
    use rand_core::RngCore;

    use super::*;

    /// Create random commitment
    pub fn commit<C: Curve, R: RngCore>(
        aux: &Aux,
        data: Data<C>,
        pdata: PrivateData,
        security: &SecurityParams,
        mut rng: R,
    ) -> Result<(Commitment<C>, PrivateCommitment), Error> {
        let two_to_l = (BigInt::from(1) << security.l_x);
        let two_to_l_e = (BigInt::from(1) << (security.l_x + security.epsilon));
        let two_to_l_prime_e = (BigInt::from(1) << (security.l_y + security.epsilon));
        let hat_n_at_two_to_l_e = (&aux.rsa_modulo * &two_to_l_e);
        let hat_n_at_two_to_l = (&aux.rsa_modulo * &two_to_l);

        // let m = BigInt::from_rng_pm(&hat_n_at_two_to_l, &mut rng);
        // let mu = BigInt::from_rng_pm(&hat_n_at_two_to_l, &mut rng);
        // let alpha = BigInt::from_rng_pm(&two_to_l_e, &mut rng);
        // let gamma = BigInt::from_rng_pm(&hat_n_at_two_to_l_e, &mut rng);
        // let beta = BigInt::from_rng_pm(&two_to_l_prime_e, &mut rng);
        // let delta = BigInt::from_rng_pm(&hat_n_at_two_to_l_e, &mut rng);
        // let r = BigInt::from_rng_pm(&(BigInt::from(1) << data.key0.nounce_size()), &mut rng);
        // let r_y = fast_paillier::utils::sample_with_size(&mut rng, data.key1.nounce_size());

        let m = BigInt::from_str_radix("-791914950346972042860440813564182990077885093581320986985656255539821069094684363770653113959250650561336908115340337684936044945818135595782753748759575763005711220687207736529276518851798168859376168035430746228846382949438384084975631598350483695874603087844394058265204520472825604030291338892680769967564966035026375677740619646203992326209399375045047129868134700891896810305749866980606948412226792104884870505816436178605982765009095279940341126065232270601096827603597580652429062349960017878541454958187784381666985874890425992687699287015742820597163241519369480836010208273021788502466407891322057807350562835413601353977552586754523270819568118994784694891451481865324033362910704367221986084915468040325581407302092765787624439477373065314203218838609025625388474919630572196195781638774771088258786716927847215835950879083038983972946198194556132643889556837960566100823005771500566967464216110053226839900350", 10).unwrap();
        let mu = BigInt::from_str_radix("-352209065548236911109135558278833952030384688052583175958118581689378630564426712869475236609442363126892354676266840228397166559652099080850226091564267580909558730892296321585228642002976400893912241976279690064532173470168699849632022137194046449846291226139951255075195789504909511328538765831383313173656051112833698898070760292623851692882288143241579025120565282716981790530369223017601294997948150303836011880127953020321489236573155966632273610404296264433211807598184814441826242771203806429792345422707561638369894720984322398420221920618401053065905728428322081257568743300263639069496846873397026290718683201287733320093989573024235425718247204669768789818198123300440370482107708131319514475027851238130905768783873502317124477333693567628215679663129422084630534430469117843770936580214679677738998885723752904648681125329819880423762801774310377851185480479183149929237733363005816230621032230158244461145439", 10).unwrap();
        let alpha = BigInt::from_str_radix("335738627287958586544358898443576674120658114298663608041257190516921613810215033958382256848427945392406571640456202746296551406381367587532492799952129426831184857850027074390195137139544753801425424597722807648116371728685034668894344739048824046178422730318591547880493038540976349331028582124883385771471175673856794679168762966729257901434929337217971637296822753593716872871539524566948829009", 10).unwrap();
        let gamma = BigInt::from_str_radix("-389458885766656827413863329801594845639134468712751162788011666524793645507732896477578503067788455878179977255014624008753062403882322203153005007360529907842032528615830538636949745256079008637841286610305531282011807884176039126971850808139830398164245460909605285203909569173535138617061685361113991916692013003023164293598790615971661942134566494958167103602273719769324772872276644954195786534080550246709542518259864295949827769786049662599655557950403818455216026724485133824948235593798522604513374822066758807044744377231314622345892335848033553605241977109135499036999477075369380511865185936608917852815641805100102779532222991292073463710729831594380187757066819437071144133931348596528214020205934517304296419355602264747182651048752635496357086207026406857160169574698044798442803027875035683416821359782828303442132637060450736049970341180868820257742275699675810433632489002900235629368116135449974599813482934700043096102071772884977234908855578608558663467712440504680503627427234129093830976480", 10).unwrap();
        let beta = BigInt::from_str_radix("-95293863774677279668736363784000584895496304874535622586755292869888687072239865853336741345824098328788639977653135275018753243419292445960756482228510884830929068342875687018083198046385245984423400939171079261600853518956000681085430542948917420676754623488669448389958377086117482890202285779582993035221162503940204152639636303756203764136310200638631312977262124543794147890285275781650659468", 10).unwrap();
        let delta = BigInt::from_str_radix("-1732291109528210705280005846816715290537346167216064900666509191710366975190421547697128495751039373157089407702787581238325805400093943627972879432060983761292774455514715341499080382655334534672152481109929109363370487621959118034323767296534602690320338876623574227344029727041746007633519518783444124555346588518476434951900394839239032348363573219972529426539379334509095708323084483724665351378372803799696784686886595239192480124941599748930359510435763328937503440684292292041082846575295078830270732356243064835950309274182840721845944217039686839155221057031555539814749149182121963258489972437874113017409596245933918405978869794805475692710997498035079416311080384455036268120070825881381500227890582645428817619643446332132028348835833543885943307938867272730035208218677928185645100160595958263805680744485606571548404936465839930405266896399120507102226873808897696373582308543408597902315901374172639336618951111358176797597378929213481092479659722807993963197396542899123503271435398105922323145133", 10).unwrap();
        let r = BigInt::from_str_radix("384233225987753004445152514900665501347570310645909436073397372880943928230543500313126141803450971522640047667511327040766865700944113326510718768578141467503518103272760302527367288411905977972147450002051472936203756507553802062814136507613956991719801615327583857686625667538637219737238858906296441009825838045983516391360139756930034592768999424484787918374625317920177827127990841219620687361606808897490196317395218024807011002973537740618592334574431521466889122181893132248891861592825826768729448059129467507061772662719770375629772151292889680630677867213101508206747138366058966380213839956408869089139298724398429269432866682473864913709288601595333909341858151251110061049760952511439146507247147186657765110011640765554016865940047456233844825944576284479685856664938555250847348687647643458065268789864999480341461458664459295165561275359048261718201349135639541281109014113220831405355240106474776707850210", 10).unwrap();
        let r_y = BigInt::from_str_radix("3992009715669774221281204082708745832266888292319228296632111283840831507599898372932521162018127142194996506707723273799547255531461603328340907385436828936184226846535954456247250212969583972666680310907004354831484782175491199304720781762588386680969162177798436235264645067917482778239948469735344382254294862229022737192853274504719579704437695001228665993153571513706782322174832346764076011543491621851989463728301655216219682071605971423321479298674568213411393834311721894048731969854826392653160230655366124880989941239096724389498672006463737895713466872100515930952993239562367854891851971622178165839913905489307974823738460736409154897678850483103020204924327760932321551936739309205897436875499910006911460018041710925439863972490195840991114026486280046348697530243400295925364770687137902597602780119018111733568592453567551833622402800401567079947008671463884123499341512916271155328230635857368849944106", 10).unwrap();

        println!("let m = Integer::from_str_radix(\"{m}\", 10).wrap();");
        println!("let mu = Integer::from_str_radix(\"{mu}\", 10).wrap();");
        println!("let alpha = Integer::from_str_radix(\"{alpha}\", 10).wrap();");
        println!("let gamma = Integer::from_str_radix(\"{gamma}\", 10).wrap();");
        println!("let beta = Integer::from_str_radix(\"{beta}\", 10).wrap();");
        println!("let delta = Integer::from_str_radix(\"{delta}\", 10).wrap();");
        println!("let r = Integer::from_str_radix(\"{r}\", 10).wrap();");
        println!("let r_y = Integer::from_str_radix(\"{r_y}\", 10).wrap();");

        let beta_enc_key0 = data.key0.encrypt_with(&beta, &r)?;
        let alpha_at_c = data.key0.omul(&alpha, data.c)?;
        let a = data.key0.oadd(&alpha_at_c, &beta_enc_key0)?;

        println!("let a = Integer::from_str_radix(\"{a:?}\", 10).unwrap();");
        let commitment = Commitment {
            a,
            b_x: Point::<C>::generator() * alpha.to_scalar(),
            b_y: data.key1.encrypt_with(&beta, &r_y)?,
            e: aux.combine(&alpha, &gamma)?,
            s: aux.combine(pdata.x, &m)?,
            f: aux.combine(&beta, &delta)?,
            t: aux.combine(pdata.y, &mu)?,
        };
        let private_commitment = PrivateCommitment {
            alpha,
            beta,
            r,
            r_y,
            gamma,
            m,
            delta,
            mu,
        };

        println!("commitment: {commitment:?}");
        Ok((commitment, private_commitment))
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove<C: Curve>(
        data: Data<C>,
        pdata: PrivateData,
        pcomm: &PrivateCommitment,
        challenge: &Challenge,
    ) -> Result<Proof, Error> {
        println!(
            "let x = Integer::from_str_radix(\"{}\", 10).unwrap();",
            pdata.x
        );
        println!(
            "let y = Integer::from_str_radix(\"{}\", 10).unwrap();",
            pdata.y
        );

        Ok(Proof {
            z1: (&pcomm.alpha + challenge * pdata.x),
            z2: (&pcomm.beta + challenge * pdata.y),
            z3: (&pcomm.gamma + challenge * &pcomm.m),
            z4: (&pcomm.delta + challenge * &pcomm.mu),
            w: data
                .key0
                .n()
                .combine(&pcomm.r, &BigInt::from(1), pdata.nonce, challenge)?,
            w_y: data
                .key1
                .n()
                .combine(&pcomm.r_y, &BigInt::from(1), pdata.nonce_y, challenge)?,
        })
    }

    /// Verify the proof
    pub fn verify<C: Curve>(
        aux: &Aux,
        data: Data<C>,
        commitment: &Commitment<C>,
        security: &SecurityParams,
        challenge: &Challenge,
        proof: &Proof,
    ) -> Result<(), InvalidProof> {
        // Five equality checks and two range checks
        {
            let lhs = {
                let z1_at_c = data
                    .key0
                    .omul(&proof.z1, data.c)
                    .map_err(|_| InvalidProofReason::PaillierOp)?;
                let enc = data
                    .key0
                    .encrypt_with(&proof.z2, &proof.w)
                    .map_err(|_| InvalidProofReason::PaillierEnc)?;
                data.key0
                    .oadd(&z1_at_c, &enc)
                    .map_err(|_| InvalidProofReason::PaillierOp)?
            };
            let rhs = {
                let e_at_d = data
                    .key0
                    .omul(challenge, data.d)
                    .map_err(|_| InvalidProofReason::PaillierOp)?;
                data.key0
                    .oadd(&commitment.a, &e_at_d)
                    .map_err(|_| InvalidProofReason::PaillierOp)?
            };
            // enc(p(e.x + alpha) + (beta + e.y), random)
            // let x = BigInt::from_str_radix("59535676186585379588401092542491407004097977185999343756652982412279347293214773037924289251570517523601226793228566844680303120528722403452483471679446058561011645755012529819482257885450232096240838951286622406240990988324666332788611585185991541102377014800082151193794943460840807169197386757915165698634", 10).unwrap();
            // let y = BigInt::from_str_radix("-167802937019754854351703778953379421731500393606797659141399329594497736972325345805409133269489785568717291051469479346764434058042567514096747328714756448262035825933177378699465366273982565149178348477888857728066624340450365566361133116642630519735346985292800179094383312495078276107469776199773120880770", 10).unwrap();
            // let temp = data.key0.encrypt_with(&((proof.z1 * data.x + proof.z2) + (x * y)), &proof.w)?;

            let c = BigInt::from_str_radix("325030951749138314430042814775677846607643648377715355359107596574024160548959971140014043451304693467721874284969443406333283122744582996773529069353864768987016929330600267205251699106170498903505128902376522251887107182274386058992052919185155952159161437796317078833919653559580479012658329890357090249175074017292360758294536532021618825906934664171414996145446549432499393306103041729115932726657473719569641919089508012704710771355067562125217232414271030024830665748198526397086531311803489943053299815561240876483024019322044036179928928369107423900849869927536078850705081272927662786741280515344028667072932569626168720490867921663296799201039996638899405160696515787866820016416181334320110350972701082870265042608992857775582133309262101800318162011715605719228558828935091978211819910093967813184244904594049520535447598478002738480840200104195299039855154368400014426125077841159533841870949192758394343269168808374197177337280666202351900927541028891627257996314575573388568141929139918381933182786184405397037137294587223065544015800218459272604797021350453677895028628488956568019383075731341339724388950173130135146339107844961875166105740624469353117676294727665360490019232598069535020861134329506127149790424344543181306083598298948977164777339367778701993531430140971548307952184536646861877724887269227459842864966899357134555521180347760288031044393221099549752288352888827835243708044811809777161552166461008312576840211582833963122385988586468195774200481447447460794750257894448262302027756399334420704840022285701393056127214295502245799874069468608644219578111161947113902897719687296274943967385932615674681463215771185171765940649891508253748768663150474409255271659215697806179955614787991917185991743819949385889859097901111041595101062652789132893861269563554548787678268515620353393804720904969414388597995538100", 10).unwrap();
            let random = BigInt::from_str_radix("12943213477814789852306309294621210830839451409597804669488230270536513154834405888743719926064492785347035501587338796994658362988467365568395295826282992", 10).unwrap();
            let plaintext = BigInt::from_str_radix("162557612053670265087934689879141179163340864248177275807135580999524376221763651229662639138106503444809248578229385107143085673848833966760505727738512662003561097835391303422275784244578100313338394547712403416381880643476040617122189169200556951484246672698071321338804010606452881475901647858136424310045806121477363754235234857450203448053851195554337065138801452394781129777557014746050283374982269718347607408791717962705372194224543548728100562922997439474489890276361071398389072800766236236853897017782083182278839188335570821083512436539229076001033065216891677680654391268765989559935060017508571251106682163923250262175044379988495701834650437139829251628589730925379838396828363249936226763532582895689772415903673838823368989333668451386433382364776581054753257303204567412772534281820773926338431781154806341185591567418602134933315577196315408260797945582946273120973597264106526928402243739380614926148155", 10).unwrap();
            let x = BigInt::from_str_radix("-167205781950661801111199959153523769024267643253147222386164677930780674293055169645321209870120592276545008507799178165405475373993003578153132444255642327066654065795796612069908710307399205742569182204000537530909364260765857853939270243888012435851098612285577421613561983137408843761193843860503225550477", 10).unwrap();
            let y = BigInt::from_str_radix("100347181391403367566459747773499463981336902684693295794365685299726323140306252556193891636450457195598336384869012684766841314968105347640137179962849808684563031874929194607728329619578147475950342207301929265092660934982812323694942514266171138670165867336334718472147697536698287748874286400931000496009", 10).unwrap();
            let alpha = BigInt::from_str_radix("335738627287958586544358898443576674120658114298663608041257190516921613810215033958382256848427945392406571640456202746296551406381367587532492799952129426831184857850027074390195137139544753801425424597722807648116371728685034668894344739048824046178422730318591547880493038540976349331028582124883385771471175673856794679168762966729257901434929337217971637296822753593716872871539524566948829009", 10).unwrap();
            let beta = BigInt::from_str_radix("-95293863774677279668736363784000584895496304874535622586755292869888687072239865853336741345824098328788639977653135275018753243419292445960756482228510884830929068342875687018083198046385245984423400939171079261600853518956000681085430542948917420676754623488669448389958377086117482890202285779582993035221162503940204152639636303756203764136310200638631312977262124543794147890285275781650659468", 10).unwrap();
            let rho = BigInt::from_str_radix("-1995485722598803056418243298519919091967440382317675622871441397762683706605906658850324294115297881230651089273775", 10).unwrap();
            let r = BigInt::from_str_radix("384233225987753004445152514900665501347570310645909436073397372880943928230543500313126141803450971522640047667511327040766865700944113326510718768578141467503518103272760302527367288411905977972147450002051472936203756507553802062814136507613956991719801615327583857686625667538637219737238858906296441009825838045983516391360139756930034592768999424484787918374625317920177827127990841219620687361606808897490196317395218024807011002973537740618592334574431521466889122181893132248891861592825826768729448059129467507061772662719770375629772151292889680630677867213101508206747138366058966380213839956408869089139298724398429269432866682473864913709288601595333909341858151251110061049760952511439146507247147186657765110011640765554016865940047456233844825944576284479685856664938555250847348687647643458065268789864999480341461458664459295165561275359048261718201349135639541281109014113220831405355240106474776707850210", 10).unwrap();
            let r_y = BigInt::from_str_radix("3992009715669774221281204082708745832266888292319228296632111283840831507599898372932521162018127142194996506707723273799547255531461603328340907385436828936184226846535954456247250212969583972666680310907004354831484782175491199304720781762588386680969162177798436235264645067917482778239948469735344382254294862229022737192853274504719579704437695001228665993153571513706782322174832346764076011543491621851989463728301655216219682071605971423321479298674568213411393834311721894048731969854826392653160230655366124880989941239096724389498672006463737895713466872100515930952993239562367854891851971622178165839913905489307974823738460736409154897678850483103020204924327760932321551936739309205897436875499910006911460018041710925439863972490195840991114026486280046348697530243400295925364770687137902597602780119018111733568592453567551833622402800401567079947008671463884123499341512916271155328230635857368849944106", 10).unwrap();
            let text = plaintext * (challenge * x.clone() + alpha.clone()) + (beta + challenge * y);
            let nounce = random * (alpha.clone() + challenge * x.clone()) + (r + challenge * rho);

            let temp = data.key0.encrypt_with(&text, &nounce);
            // text = plaintext(e.x + alpha) + (beta + e.y)
            // nounce = random.(alpha + e.x) + (r + e.rho)

            println!("lhs: {:?}", lhs);
            println!("rhs: {:?}", rhs);
            println!("temp: {:?}", temp);
            fail_if_ne(InvalidProofReason::EqualityCheck(1), lhs, rhs)?;
        }
        {
            let lhs = Point::<C>::generator() * proof.z1.to_scalar();
            let rhs = commitment.b_x + data.x * challenge.to_scalar();
            fail_if_ne(InvalidProofReason::EqualityCheck(2), lhs, rhs)?;
        }
        // {
        //     let lhs = data
        //         .key1
        //         .encrypt_with(&proof.z2, &proof.w_y)
        //         .map_err(|_| InvalidProofReason::PaillierEnc)?;
        //     let rhs = {
        //         let e_at_y = data
        //             .key1
        //             .omul(challenge, data.y)
        //             .map_err(|_| InvalidProofReason::PaillierOp)?;
        //         data.key1
        //             .oadd(&commitment.b_y, &e_at_y)
        //             .map_err(|_| InvalidProofReason::PaillierOp)?
        //     };
        //     fail_if_ne(InvalidProofReason::EqualityCheck(3), lhs, rhs)?;
        // }
        {
            let lhs = aux.combine(&proof.z1, &proof.z3)?;
            let s_to_e = aux.pow_mod(&commitment.s, challenge)?;
            let rhs = (&commitment.e * s_to_e) % (&aux.rsa_modulo);
            fail_if_ne(InvalidProofReason::EqualityCheck(4), lhs, rhs)?;
        }
        {
            let lhs = aux.combine(&proof.z2, &proof.z4)?;
            let t_to_e = aux.pow_mod(&commitment.t, challenge)?;
            let rhs = (&commitment.f * t_to_e) % (&aux.rsa_modulo);
            fail_if_ne(InvalidProofReason::EqualityCheck(5), lhs, rhs)?;
        }
        fail_if(
            InvalidProofReason::RangeCheck(6),
            proof
                .z1
                .is_in_pm(&(BigInt::from(1) << (security.l_x + security.epsilon))),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(7),
            proof
                .z2
                .is_in_pm(&(BigInt::from(1) << (security.l_y + security.epsilon))),
        )?;
        Ok(())
    }

    /// Generate random challenge
    pub fn challenge<R>(security: &SecurityParams, rng: &mut R) -> BigInt
    where
        R: RngCore,
    {
        BigInt::from_rng_pm(&security.q, rng)
    }
}

/// The non-interactive version of proof. Completed in one round, for example
/// see the documentation of parent module.
pub mod non_interactive {
    use digest::Digest;
    use generic_ec::Curve;

    use crate::{Error, InvalidProof};

    use super::{Aux, Challenge, Commitment, Data, PrivateData, Proof, SecurityParams};

    /// Compute proof for the given data, producing random commitment and
    /// deriving determenistic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<C: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data<C>,
        pdata: PrivateData,
        security: &SecurityParams,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<(Commitment<C>, Proof), Error> {
        let (comm, pcomm) = super::interactive::commit(aux, data, pdata, security, rng)?;
        let challenge = challenge::<C, D>(shared_state, aux, data, &comm, security);
        let proof = super::interactive::prove(data, pdata, &pcomm, &challenge)?;
        Ok((comm, proof))
    }

    /// Verify the proof, deriving challenge independently from same data
    pub fn verify<C: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data<C>,
        commitment: &Commitment<C>,
        security: &SecurityParams,
        proof: &Proof,
    ) -> Result<(), InvalidProof> {
        let challenge = challenge::<C, D>(shared_state, aux, data, commitment, security);
        super::interactive::verify(aux, data, commitment, security, &challenge, proof)
    }

    /// Deterministically compute challenge based on prior known values in protocol
    pub fn challenge<C: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data<C>,
        commitment: &Commitment<C>,
        security: &SecurityParams,
    ) -> Challenge {
        let tag = "paillier_zk.paillier_affine_operation_in_range.ni_challenge";
        let aux = aux.digest_public_data();
        let seed = udigest::inline_struct!(tag {
            shared_state,
            aux,
            security,
            data,
            commitment,
        });
        let mut rng = rand_hash::HashRng::<D, _>::from_seed(seed);
        super::interactive::challenge(security, &mut rng)
    }
}

#[cfg(test)]
mod test {
    use generic_ec::{Curve, Point};
    use sha2::Digest;

    use crate::common::test::{sample_key, sample_other_key};
    use crate::common::{BigIntExt, InvalidProofReason};
    use fast_paillier::AnyEncryptionKey;
    use num_bigint::BigInt;
    use num_traits::Num;
    fn run<R: rand_core::RngCore + rand_core::CryptoRng, C: Curve, D: Digest>(
        rng: &mut R,
        security: super::SecurityParams,
        x: BigInt,
        y: BigInt,
    ) -> Result<(), crate::common::InvalidProof> {
        let x = BigInt::from_str_radix("-167205781950661801111199959153523769024267643253147222386164677930780674293055169645321209870120592276545008507799178165405475373993003578153132444255642327066654065795796612069908710307399205742569182204000537530909364260765857853939270243888012435851098612285577421613561983137408843761193843860503225550477", 10).unwrap();
        let y = BigInt::from_str_radix("100347181391403367566459747773499463981336902684693295794365685299726323140306252556193891636450457195598336384869012684766841314968105347640137179962849808684563031874929194607728329619578147475950342207301929265092660934982812323694942514266171138670165867336334718472147697536698287748874286400931000496009", 10).unwrap();
        let dk0 = sample_key();
        let dk1 = sample_other_key();
        let ek0 = dk0.encryption_key().clone();
        let ek1 = dk1.encryption_key().clone();

        // let ((c, random), plaintext) = {
        //     let plaintext = BigInt::from_rng_pm(ek0.half_n(), rng);
        //     (ek0.encrypt_with_random(rng, &plaintext).unwrap(), plaintext)
        // };

        let c = BigInt::from_str_radix("325030951749138314430042814775677846607643648377715355359107596574024160548959971140014043451304693467721874284969443406333283122744582996773529069353864768987016929330600267205251699106170498903505128902376522251887107182274386058992052919185155952159161437796317078833919653559580479012658329890357090249175074017292360758294536532021618825906934664171414996145446549432499393306103041729115932726657473719569641919089508012704710771355067562125217232414271030024830665748198526397086531311803489943053299815561240876483024019322044036179928928369107423900849869927536078850705081272927662786741280515344028667072932569626168720490867921663296799201039996638899405160696515787866820016416181334320110350972701082870265042608992857775582133309262101800318162011715605719228558828935091978211819910093967813184244904594049520535447598478002738480840200104195299039855154368400014426125077841159533841870949192758394343269168808374197177337280666202351900927541028891627257996314575573388568141929139918381933182786184405397037137294587223065544015800218459272604797021350453677895028628488956568019383075731341339724388950173130135146339107844961875166105740624469353117676294727665360490019232598069535020861134329506127149790424344543181306083598298948977164777339367778701993531430140971548307952184536646861877724887269227459842864966899357134555521180347760288031044393221099549752288352888827835243708044811809777161552166461008312576840211582833963122385988586468195774200481447447460794750257894448262302027756399334420704840022285701393056127214295502245799874069468608644219578111161947113902897719687296274943967385932615674681463215771185171765940649891508253748768663150474409255271659215697806179955614787991917185991743819949385889859097901111041595101062652789132893861269563554548787678268515620353393804720904969414388597995538100", 10).unwrap();
        let random = BigInt::from_str_radix("12943213477814789852306309294621210830839451409597804669488230270536513154834405888743719926064492785347035501587338796994658362988467365568395295826282992", 10).unwrap();
        let plaintext = BigInt::from_str_radix("162557612053670265087934689879141179163340864248177275807135580999524376221763651229662639138106503444809248578229385107143085673848833966760505727738512662003561097835391303422275784244578100313338394547712403416381880643476040617122189169200556951484246672698071321338804010606452881475901647858136424310045806121477363754235234857450203448053851195554337065138801452394781129777557014746050283374982269718347607408791717962705372194224543548728100562922997439474489890276361071398389072800766236236853897017782083182278839188335570821083512436539229076001033065216891677680654391268765989559935060017508571251106682163923250262175044379988495701834650437139829251628589730925379838396828363249936226763532582895689772415903673838823368989333668451386433382364776581054753257303204567412772534281820773926338431781154806341185591567418602134933315577196315408260797945582946273120973597264106526928402243739380614926148155", 10).unwrap();

        println!("let c = Integer::from_str_radix(\"{c:?}\", 10).unwrap();");
        println!("let random = Integer::from_str_radix(\"{random:?}\", 10).unwrap();");
        println!("let plaintext = Integer::from_str_radix(\"{plaintext:?}\", 10).unwrap();");

        let rho_y = BigInt::from_rng_pm(&(BigInt::from(1) << (ek1.nounce_size() - 129)), rng);
        let y_enc_ek1 = ek1.encrypt_with(&y, &rho_y).unwrap();

        let rho = BigInt::from_rng_pm(&(BigInt::from(1) << (dk0.nounce_size() - 129)), rng);
        let rho = BigInt::from_str_radix("-1995485722598803056418243298519919091967440382317675622871441397762683706605906658850324294115297881230651089273775", 10).unwrap();
        println!("let rho = Integer::from_str_radix(\"{rho:?}\", 10).unwrap();");

        let d = {
            let x_at_c = dk0.omul(&x, &c).unwrap();
            let y_enc_ek0 = dk0.encrypt_with(&y, &rho).unwrap();
            dk0.oadd(&x_at_c, &y_enc_ek0).unwrap()
        };

        let data = super::Data {
            key0: &ek0,
            key1: &ek1,
            c: &c,
            d: &d,
            y: &y_enc_ek1,
            x: &(x.to_scalar::<C>() * Point::generator()),
        };

        
        let pdata = super::PrivateData {
            x: &x,
            y: &y,
            nonce: &rho,
            nonce_y: &rho_y,
        };

        let aux = crate::common::test::aux(rng);

        let shared_state = "shared state";

        let (commitment, proof) =
            super::non_interactive::prove::<C, D>(&shared_state, &aux, data, pdata, &security, rng)
                .unwrap();
        super::non_interactive::verify::<C, D>(
            &shared_state,
            &aux,
            data,
            &commitment,
            &security,
            &proof,
        )
    }

    fn passing_test<C: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l_x: 1024,
            l_y: 1024,
            epsilon: 300,
            q: (BigInt::from(1) << 128_u32).into(),
        };
        let x = BigInt::from_rng_pm(&(BigInt::from(1) << security.l_x), &mut rng);
        let y = BigInt::from_rng_pm(&(BigInt::from(1) << security.l_y), &mut rng);
        run::<_, C, D>(&mut rng, security, x, y).expect("proof failed");
    }

    fn failing_on_additive<C: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l_x: 1024,
            l_y: 1024,
            epsilon: 300,
            q: (BigInt::from(1) << 128_u32),
        };
        let x = BigInt::from_rng_pm(&(BigInt::from(1) << security.l_x), &mut rng);
        let y = (BigInt::from(1) << (security.l_y + security.epsilon)) + 1;
        let r = run::<_, C, D>(&mut rng, security, x, y).expect_err("proof should not pass");
        match r.reason() {
            InvalidProofReason::RangeCheck(7) => (),
            e => panic!("proof should not fail with: {e:?}"),
        }
    }

    fn failing_on_multiplicative<C: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l_x: 1024,
            l_y: 1024,
            epsilon: 300,
            q: (BigInt::from(1) << 128_u32),
        };
        let x = (BigInt::from(1) << (security.l_x + security.epsilon)) + 1;
        let y = BigInt::from_rng_pm(&(BigInt::from(1) << security.l_y), &mut rng);
        let r = run::<_, C, D>(&mut rng, security, x, y).expect_err("proof should not pass");
        match r.reason() {
            InvalidProofReason::RangeCheck(6) => (),
            e => panic!("proof should not fail with: {e:?}"),
        }
    }

    #[test]
    fn passing_p256() {
        passing_test::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }
    #[test]
    fn failing_p256_add() {
        failing_on_additive::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }
    #[test]
    fn failing_p256_mul() {
        failing_on_multiplicative::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }

    #[test]
    fn passing_million() {
        passing_test::<crate::curve::C, sha2::Sha256>()
    }
    #[test]
    fn failing_million_add() {
        failing_on_additive::<crate::curve::C, sha2::Sha256>()
    }
    #[test]
    fn failing_million_mul() {
        failing_on_multiplicative::<crate::curve::C, sha2::Sha256>()
    }
}
