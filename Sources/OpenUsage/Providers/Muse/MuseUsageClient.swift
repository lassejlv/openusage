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
    /// GraphQL call is needed. Full browser headers are required — a bare request gets an
    /// error page instead of the app.
    func fetchUsagePage(sessionCookie: String) async throws -> HTTPResponse {
        try await http.send(HTTPRequest(
            method: "GET",
            url: Self.usageURL,
            headers: [
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Sec-Ch-Ua": "\"Chromium\";v=\"152\", \"Not?A_Brand\";v=\"24\", \"Brave\";v=\"152\"",
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": "\"macOS\"",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-origin",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
                "Cookie": "\(MuseAuthStore.cookieName)=\(sessionCookie)"
            ],
            timeout: 30
        ))
    }
}
