use siros_verifier_core::sdjwt::{StatusRef, X5cLeaf};
use siros_verifier_core::status_list::{index_parts, status_at, verify_token};
use siros_verifier_core::trust::TrustQuery;

const NOW: i64 = 1_793_656_800;
const TOKEN: &str = "eyJ4NWMiOlsiTUlJQnZqQ0NBV09nQXdJQkFnSVVmdzRpbjJ4YmJhTzRCUlZ6Q01KOWpjeCtNWVV3Q2dZSUtvWkl6ajBFQXdJd0lqRWdNQjRHQTFVRUF3d1hZMjl1Wm05eWJXRnVZMlV1WlhoaGJYQnNaUzVqYjIwd0hoY05Nall3TlRFMU1EYzFNelExV2hjTk1qY3dOVEUxTURjMU16UTFXakFpTVNBd0hnWURWUVFEREJkamIyNW1iM0p0WVc1alpTNWxlR0Z0Y0d4bExtTnZiVEJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCQno3UkdCQkVEUm5EaGhyVUY1NXZGVzI2OGxtRGhlM1paa3luQThDTVpPdEtudjAyOTY4WFNpRW1OU29HUGFIWDNMWGwrYm9RenRzSzBEQjQ2VmhFNitqZHpCMU1CMEdBMVVkRGdRV0JCUi96QTdoMytpa0tCb2EzanlNaVNYN3NGZGt5ekFmQmdOVkhTTUVHREFXZ0JSL3pBN2gzK2lrS0JvYTNqeU1pU1g3c0Zka3l6QVBCZ05WSFJNQkFmOEVCVEFEQVFIL01DSUdBMVVkRVFRYk1CbUNGMk52Ym1admNtMWhibU5sTG1WNFlXMXdiR1V1WTI5dE1Bb0dDQ3FHU000OUJBTUNBMGtBTUVZQ0lRQzRsaHh3aVF5MytHUHR6ZFFXOUlsRFNyUW9Fbm5jb202WXNLWjNpekh1SWdJaEFLWklqTllXVEcweElwRnJTNERWa3ZvMXFpVjlrTmYxUXZwOFN0T1c2cEVyIl0sInR5cCI6InN0YXR1c2xpc3Qrand0IiwiYWxnIjoiRVMyNTYiLCJqd2siOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NiIsImtpZCI6InZwLXZlcmlmaWVyLWtleS0xIiwieDVjIjpbIk1JSUJ2akNDQVdPZ0F3SUJBZ0lVZnc0aW4yeGJiYU80QlJWekNNSjlqY3grTVlVd0NnWUlLb1pJemowRUF3SXdJakVnTUI0R0ExVUVBd3dYWTI5dVptOXliV0Z1WTJVdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpZd05URTFNRGMxTXpRMVdoY05NamN3TlRFMU1EYzFNelExV2pBaU1TQXdIZ1lEVlFRRERCZGpiMjVtYjNKdFlXNWpaUzVsZUdGdGNHeGxMbU52YlRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQkJ6N1JHQkJFRFJuRGhoclVGNTV2RlcyNjhsbURoZTNaWmt5bkE4Q01aT3RLbnYwMjk2OFhTaUVtTlNvR1BhSFgzTFhsK2JvUXp0c0swREI0NlZoRTYramR6QjFNQjBHQTFVZERnUVdCQlIvekE3aDMraWtLQm9hM2p5TWlTWDdzRmRreXpBZkJnTlZIU01FR0RBV2dCUi96QTdoMytpa0tCb2EzanlNaVNYN3NGZGt5ekFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQ0lHQTFVZEVRUWJNQm1DRjJOdmJtWnZjbTFoYm1ObExtVjRZVzF3YkdVdVkyOXRNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUUM0bGh4d2lReTMrR1B0emRRVzlJbERTclFvRW5uY29tNllzS1ozaXpIdUlnSWhBS1pJak5ZV1RHMHhJcEZyUzREVmt2bzFxaVY5a05mMVF2cDhTdE9XNnBFciJdLCJ4IjoiSFB0RVlFRVFOR2NPR0d0UVhubThWYmJyeVdZT0Y3ZGxtVEtjRHdJeGs2MCIsInkiOiJLbnYwMjk2OFhTaUVtTlNvR1BhSFgzTFhsLWJvUXp0c0swREI0NlZoRTY4IiwiYWxnIjoiRVMyNTYifX0.eyJzdWIiOiJodHRwczovL2xvY2FsaG9zdC5lbW9iaXguY28udWs6ODQ0My90ZXN0L2Evc2lyb3MtdmVyaWZpZXItdnAtdGVzdC9zdGF0dXNsaXN0cy9FY1VJdjlyaGtpaWJBcWduSmpKSyIsImV4cCI6MTc5Mzc0MzE5NiwiaWF0IjoxNzkzNjU2Nzk2LCJ0dGwiOjMwMCwic3RhdHVzX2xpc3QiOnsiYml0cyI6MSwibHN0IjoiZU5wYnRRb19BQUJlenhWQiJ9fQ.YbQ89wmpUFsZQXyK-dimVsrPmM6pC4yy6jiPV3idF-EnGzhuFinBV0GelpBMk2sww45vBk9ntApmFCCVSPI02A";

fn reference(idx: u64) -> StatusRef {
    StatusRef {
        idx,
        uri: "https://localhost.emobix.co.uk:8443/test/a/siros-verifier-vp-test/statuslists/EcUIv9rhkiibAqgnJjJK".into(),
    }
}

#[test]
fn genuine_suite_token_verifies_and_reads_revocation_bits() {
    let token = verify_token(TOKEN, &X5cLeaf, NOW).unwrap();
    assert_eq!(status_at(&token, &reference(5)).unwrap(), 1);
    assert_eq!(status_at(&token, &reference(4)).unwrap(), 0);
    let query = TrustQuery::for_issuer(&token.issuer, "status-list-signer", "status-list");
    assert_eq!(query.role, "status-list-signer");
    assert_eq!(query.subject_id, reference(0).uri);
}

#[test]
fn signature_time_subject_and_index_are_checked() {
    assert!(verify_token(TOKEN, &X5cLeaf, 1_793_743_196).is_err());
    let token = verify_token(TOKEN, &X5cLeaf, NOW).unwrap();
    assert!(status_at(&token, &reference(1000)).is_err());
    let mut wrong = reference(1);
    wrong.uri = "https://example.com/other".into();
    assert!(status_at(&token, &wrong).is_err());
    let mut tampered = TOKEN.to_owned();
    tampered.push('x');
    assert!(verify_token(&tampered, &X5cLeaf, NOW).is_err());
}

#[test]
fn an_index_beyond_the_native_usize_range_is_rejected_not_truncated() {
    let token = verify_token(TOKEN, &X5cLeaf, NOW).unwrap();
    // 2^32 truncates to zero on 32-bit targets. The production arithmetic must
    // retain the exact bit offset on every target, and status lookup must stay
    // out of range rather than selecting the first status entry.
    assert_eq!(index_parts(1_u64 << 32, 1).unwrap(), (1_u64 << 32, 0));
    let error = status_at(&token, &reference(1_u64 << 32)).unwrap_err();
    assert_eq!(error.code(), "policy");
    assert!(error.to_string().contains("status_list_index_out_of_range"));
}
