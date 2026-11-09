//! The inbound HTTP adapter: request translation (duplicate-preserving), the
//! payload bound that genuine Longfellow presentations fit inside, and the
//! health endpoint.

use actix_web::{test, web, App};
use siros_verifier_service::http::{build_request_data, health, MAX_HTTP_BODY_BYTES};

#[actix_web::test]
async fn health_returns_status_ok() {
    let app = test::init_service(App::new().route("/health", web::get().to(health))).await;
    let req = test::TestRequest::get().uri("/health").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body, serde_json::json!({ "status": "ok" }));
}

#[actix_web::test]
async fn genuine_longfellow_response_size_fits_the_http_body_limit() {
    let app = test::init_service(
        App::new()
            .app_data(web::PayloadConfig::new(MAX_HTTP_BODY_BYTES))
            .default_service(web::to(|_body: web::Bytes| async {
                actix_web::HttpResponse::Ok().finish()
            })),
    )
    .await;
    // Measured from a genuine Pixel Longfellow direct_post.jwt response.
    let req = test::TestRequest::post()
        .uri("/vp/response/id")
        .set_payload(vec![0u8; 1_102_937])
        .to_request();
    let response = test::call_service(&app, req).await;
    assert_eq!(response.status(), actix_web::http::StatusCode::OK);
}

#[actix_web::test]
async fn request_adapter_preserves_duplicate_protocol_parameters() {
    let request = test::TestRequest::post()
        .uri("/vp/response/id?resource=first&resource=second&state=one&state=two")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .to_http_request();
    let body = web::Bytes::from_static(b"response=first&response=second");
    let data = build_request_data(&request, &body);
    assert_eq!(data.query_pairs.len(), 4);
    assert_eq!(data.form_pairs.len(), 2);
    assert_eq!(data.query.get("state").map(String::as_str), Some("two"));
    assert_eq!(
        data.form.get("response").map(String::as_str),
        Some("second")
    );
}
