// Tyk custom middleware: stamp a fresh validity window on the request the
// gateway forwards upstream.
//
// Why this is needed: Tyk's `global_headers` are static, but the JDLib gateway
// adapter refuses an assertion whose window is absent, stale, or wider than the
// configured skew (that refusal is the replay protection). A static window
// would therefore be correctly rejected, so the gateway has to compute one per
// request.
var stampWindow = new TykJS.TykMiddleware.NewMiddleware({});

stampWindow.NewProcessRequest(function (request, session, config) {
    var now = Math.floor(Date.now() / 1000);
    request.SetHeaders["x-tyk-jdlib-issued-at"] = String(now - 5);
    request.SetHeaders["x-tyk-jdlib-expires-at"] = String(now + 55);
    return stampWindow.ReturnData(request, session.meta_data);
});
