use warp::filters::cors::Builder;

/// Creates a CORS filter with allowed origins and methods.
pub fn cors_filter() -> Builder {
	// Enable CORS for all origins and common HTTP methods/headers
	warp::cors()
		.allow_credentials(true)
		.allow_headers(vec!["Content-Type", "Authorization"])
		.allow_methods(vec!["GET", "POST", "OPTIONS"])
		.allow_origin("http://localhost:3000")
		.allow_origin("http://localhost:3001")
		.allow_origin("http://127.0.0.1:3000")
		.allow_origin("http://127.0.0.1:3001")
		.allow_origin("https://dev-frontend.qubetics.work")
}
