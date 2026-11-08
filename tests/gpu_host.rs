use brut_wallet::gpu::{decode_hits, validate_batch_size};

#[test]
fn batch_limits_are_checked_without_opencl() {
    assert!(validate_batch_size(0).is_err());
    assert!(validate_batch_size(127).is_err());
    assert!(validate_batch_size(129).is_err());
    assert!(validate_batch_size(128).is_ok());
    assert!(validate_batch_size(65536).is_ok());
    assert!(validate_batch_size(usize::MAX).is_err());
}

#[test]
fn hits_are_candidate_indices_and_never_silently_truncated() {
    assert_eq!(decode_hits(3, &[3, 11, 7], 3).unwrap(), vec![0, 1, 2]);
    assert!(decode_hits(17, &[3; 16], 128).is_err());
    assert!(decode_hits(u32::MAX, &[3; 16], 128).is_err());
    assert!(decode_hits(2, &[3], 128).is_err());
    assert!(decode_hits(1, &[0], 128).is_err());
    assert!(decode_hits(1, &[515], 128).is_err());
    assert!(decode_hits(2, &[3, 3], 128).is_err());
    assert_eq!(decode_hits(0, &[], 128).unwrap(), Vec::<usize>::new());
    let full: Vec<u32> = (0..16).rev().map(|index| index * 4 + 3).collect();
    assert_eq!(
        decode_hits(16, &full, 128).unwrap(),
        (0..16).collect::<Vec<_>>()
    );
}

#[test]
fn full_width_suffix_values_keep_the_upper_bits() {
    use brut_wallet::pattern::SuffixPattern;
    let pattern = SuffixPattern::new("__________").unwrap();
    assert_eq!(pattern.mask(), 0x0fff_ffff_ffff_ffffu64);
    assert_eq!(pattern.value(), 0x0fff_ffff_ffff_ffffu64);
    assert!(pattern.matches(&format!("UQA{}__________", "A".repeat(35))));
    assert!(!pattern.matches(&format!("UQA{}A_________", "A".repeat(35))));
}

#[test]
#[ignore = "Запускать только явно на целевом GPU; задайте BRUT_WALLET_GPU_DEVICE"]
fn explicit_gpu_differential_self_test() -> anyhow::Result<()> {
    let index: usize = std::env::var("BRUT_WALLET_GPU_DEVICE")?.parse()?;
    let mut engine = brut_wallet::gpu::GpuEngine::new(index, 128)?;
    engine.self_test()
}
