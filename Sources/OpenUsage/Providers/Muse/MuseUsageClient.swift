import Foundation

struct MuseUsageClient: Sendable {
    static let usageURL = URL(string: "https://dev.meta.ai/usage/")!

    var http: any HTTPClient

    init(http: any HTTPClient = URLSessionHTTPClient()) {
        self.http = http
    }

    /// Fetch the usage page. The single `llm_sess` cookie authenticates it; the server
    /// 302-redirects the bare `/usage/` URL to the team's `team_id`/`project_id` URL and
    /// embeds the full quota result (`subscription_quota_usage`) in the returned HTML, so no
    /// GraphQL call is needed. Bisected 2026-09-11: `Accept: text/html` is the only header
    /// the page needs beyond the cookie (User-Agent, Sec-CH-UA, Sec-Fetch-* all verified
    /// unnecessary) — a request without it gets an error page or a variant without quota data.
    func fetchUsagePage(sessionCookie: String) async throws -> HTTPResponse {
        try await http.send(HTTPRequest(
            method: "GET",
            url: Self.usageURL,
            headers: [
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Cookie": "\(MuseAuthStore.cookieName)=\(sessionCookie)"
            ],
            timeout: 30
        ))
    }
}
