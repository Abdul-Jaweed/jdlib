// Tyk custom middleware: stamp a fresh validity window on the request the
// gateway forwards upstream.
//
// Why this is needed: Tyk's `global_headers` are static, but the JDLib gateway
// adapter refuses an assertion whose window is absent, stale, or wider than the
// configured skew (that refusal is the replay protection). A static window
// would therefore be correctly rejected, so the gateway has to compute one per
// request.
//
// The global below must be named exactly as the API definition's middleware entry
// (`stamp_window`): Tyk's JSVM looks the name up in this file and calls it, and an
// entry with no matching global fails every request with
// `ReferenceError: 'stamp_window' is not defined`.
var stamp_window = new TykJS.TykMiddleware.NewMiddleware({});

stamp_window.NewProcessRequest(function (request, session, config) {
    var now = Math.floor(Date.now() / 1000);
    request.SetHeaders["x-tyk-jdlib-issued-at"] = String(now - 5);
    request.SetHeaders["x-tyk-jdlib-expires-at"] = String(now + 55);
    // The middleware runs with `require_session: false`, so there may be no
    // session to carry through.
    var meta = (session && session.meta_data) || {};
    return stamp_window.ReturnData(request, meta);
});
