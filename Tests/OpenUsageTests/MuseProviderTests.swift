import XCTest
@testable import OpenUsage

// MARK: - Fakes

/// SQLite fake answering per (path, SQL): browser-cookie tests must distinguish the cleartext,
/// encrypted-hex, and presence queries hitting the same database file.
private final class MuseFakeSQLite: SQLiteAccessing, @unchecked Sendable {
    var answer: (String, String) -> String?
    var throwPaths: Set<String>
    var lastPath: String?
    var lastSQL: String?

    init(answer: @escaping (String, String) -> String? = { _, _ in nil }, throwPaths: Set<String> = []) {
        self.answer = answer
        self.throwPaths = throwPaths
    }

    func queryValue(path: String, sql: String) throws -> String? {
        lastPath = path
        lastSQL = sql
        if throwPaths.contains(path) { throw SQLiteError.queryFailed("denied") }
        return answer(path, sql)
    }

    func execute(path: String, sql: String) throws {}
}

private final class MuseFakeProcess: ProcessRunning, @unchecked Sendable {
    var output: String

    init(output: String) {
        self.output = output
    }

    func run(executable: String, arguments: [String], environment: [String: String], timeout: TimeInterval) throws -> ProcessResult {
        ProcessResult(exitCode: 0, stdout: output, stderr: "")
    }
}

private final class MuseQueueHTTPClient: HTTPClient, @unchecked Sendable {
    var responses: [HTTPResponse]
    var requests: [HTTPRequest] = []

    init(responses: [HTTPResponse]) {
        self.responses = responses
    }

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        requests.append(request)
        guard !responses.isEmpty else { throw HTTPClientError.invalidResponse }
        return responses.removeFirst()
    }
}

/// Hermetic store: sqlite/keychain/files/env/process/binary-reads/profiles all faked, so no test
/// can see the machine's real browsers, keychain, or cookie stores.
private func museStore(
    files: TextFileAccessing = FakeFiles(),
    environment: EnvironmentReading = FakeEnvironment(),
    sqlite: SQLiteAccessing = MuseFakeSQLite(),
    keychain: KeychainAccessing = FakeKeychain(nil),
    process: ProcessRunning = MuseFakeProcess(output: ""),
    binary: @escaping @Sendable (String) throws -> Data? = { _ in nil },
    profiles: @escaping @Sendable (String) -> [String] = { _ in [] }
) -> MuseAuthStore {
    MuseAuthStore(
        files: files, environment: environment, sqlite: sqlite, keychain: keychain,
        process: process, binaryReader: binary, profileNames: profiles
    )
}

/// Builds a minimal but layout-faithful `Cookies.binarycookies` blob: `cook` magic, one page,
/// LE cookie records (size, unknown, flags, unknown, url/name/path/value offsets, end marker,
/// expiry/creation doubles, NUL-terminated strings). Mirrors the documented format, not just
/// what the parser happens to read.
private func binarycookiesBlob(_ cookies: [(url: String, name: String, value: String)]) -> Data {
    var records: [Data] = []
    for cookie in cookies {
        let url = Data(cookie.url.utf8) + Data([0])
        let name = Data(cookie.name.utf8) + Data([0])
        let path = Data("/".utf8) + Data([0])
        let value = Data(cookie.value.utf8) + Data([0])
        var header = Data(count: 56)
        func put(_ v: UInt32, at offset: Int) {
            header[offset] = UInt8(v & 0xFF)
            header[offset + 1] = UInt8((v >> 8) & 0xFF)
            header[offset + 2] = UInt8((v >> 16) & 0xFF)
            header[offset + 3] = UInt8((v >> 24) & 0xFF)
        }
        let urlOffset = 56
        let nameOffset = urlOffset + url.count
        let pathOffset = nameOffset + name.count
        let valueOffset = pathOffset + path.count
        put(UInt32(urlOffset), at: 16); put(UInt32(nameOffset), at: 20)
        put(UInt32(pathOffset), at: 24); put(UInt32(valueOffset), at: 28)
        var record = header + url + name + path + value
        let size = UInt32(record.count)
        record[0] = UInt8(size & 0xFF); record[1] = UInt8((size >> 8) & 0xFF)
        record[2] = UInt8((size >> 16) & 0xFF); record[3] = UInt8((size >> 24) & 0xFF)
        records.append(record)
    }
    var page = Data([0, 0, 1, 0, 0, 0, 0, 0])
    let count = UInt32(records.count)
    page += Data([UInt8(count & 0xFF), UInt8((count >> 8) & 0xFF), UInt8((count >> 16) & 0xFF), UInt8((count >> 24) & 0xFF)])
    var offset = 12 + 4 * records.count
    for record in records {
        let value = UInt32(offset)
        page += Data([UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF), UInt8((value >> 16) & 0xFF), UInt8((value >> 24) & 0xFF)])
        offset += record.count
    }
    for record in records { page += record }
    var blob = Data("cook".utf8)
    blob += Data([0, 0, 0, 1])
    let pageSize = UInt32(page.count)
    blob += Data([UInt8((pageSize >> 24) & 0xFF), UInt8((pageSize >> 16) & 0xFF), UInt8((pageSize >> 8) & 0xFF), UInt8(pageSize & 0xFF)])
    blob += page
    return blob
}

// MARK: - Auth store

final class MuseAuthStoreTests: XCTestCase {
    // AES-128-CBC (IV = 16 spaces) of "llm-sess-cookie-value-123" under the Chromium macOS
    // KDF: PBKDF2-HMAC-SHA1("test-safe-storage-password", salt "saltysalt", 1003 iters).
    static let cookiePassword = "test-safe-storage-password"
    static let cookiePlaintext = "llm-sess-cookie-value-123"
    static let cookieCipherHex = "763130cb8cff3761f0c463feff671e6cc04ea417262e35784cf2ed66520884f70cba92"

    /// Answers like a Chromium database holding one encrypted cookie: hex for the encrypted
    /// query, "1" for presence probes, nothing in cleartext.
    fileprivate static func encryptedDB(_ db: String, hex: String = cookieCipherHex) -> MuseFakeSQLite {
        MuseFakeSQLite(answer: { path, sql in
            guard path == db else { return nil }
            if sql.contains("hex(encrypted_value)") { return hex }
            if sql.hasPrefix("SELECT 1") { return "1" }
            return nil
        })
    }

    func testManualCookiePrefersConfigFileOverEnv() {
        let store = museStore(
            files: FakeFiles([MuseAuthStore.configPaths[0]: "cookie-from-file"]),
            environment: FakeEnvironment(["MUSE_LLM_SESS": "cookie-from-env"])
        )
        XCTAssertEqual(store.loadManualCookie()?.sessionCookie, "cookie-from-file")
        XCTAssertEqual(store.keyStatus(), .overrideActive)
    }

    func testManualCookieFallsBackToEnv() {
        let store = museStore(environment: FakeEnvironment(["MUSE_LLM_SESS": "cookie-from-env"]))
        XCTAssertEqual(store.loadManualCookie()?.sessionCookie, "cookie-from-env")
        XCTAssertEqual(store.keyStatus(), .fromEnvironment)
    }

    func testSaveAndDeleteRoundTrip() throws {
        let store = museStore()
        XCTAssertEqual(store.keyStatus(), .notSet)
        try store.saveAPIKey("saved-cookie")
        XCTAssertEqual(store.loadManualCookie()?.sessionCookie, "saved-cookie")
        XCTAssertEqual(store.keyStatus(), .saved)
        XCTAssertEqual(store.currentAPIKey(), "saved-cookie")
        try store.deleteAPIKey()
        XCTAssertNil(store.loadManualCookie())
        XCTAssertEqual(store.keyStatus(), .notSet)
    }

    func testParseDefaultBrowserPrefersHTTPS() {
        let output = """
            {
                LSHandlerRoleAll = "com.brave.browser";
                LSHandlerURLScheme = http;
            },
            {
                LSHandlerModificationDate = 808138075;
                LSHandlerPreferredVersions =         {
                    LSHandlerRoleAll = "-";
                };
                LSHandlerRoleAll = "company.thebrowser.browser";
                LSHandlerURLScheme = https;
            },
        """
        // The nested LSHandlerPreferredVersions braces must not break parsing, and https wins.
        XCTAssertEqual(MuseAuthStore.parseDefaultBrowser(output), .arc)
    }

    func testParseDefaultBrowserFallsBackToHTTP() {
        XCTAssertEqual(
            MuseAuthStore.parseDefaultBrowser("LSHandlerRoleAll = \"com.brave.browser\";\nLSHandlerURLScheme = http;"),
            .brave
        )
        XCTAssertNil(MuseAuthStore.parseDefaultBrowser("LSHandlerRoleAll = \"com.unknown.app\";\nLSHandlerURLScheme = https;"))
        XCTAssertNil(MuseAuthStore.parseDefaultBrowser("nothing here"))
    }

    func testOrderedBrowsersPutsDefaultFirst() {
        let store = museStore(process: MuseFakeProcess(output: """
            LSHandlerRoleAll = "org.mozilla.firefox";
            LSHandlerURLScheme = https;
            """))
        XCTAssertEqual(store.orderedBrowsers().first, .firefox)
        XCTAssertEqual(store.orderedBrowsers().count, MuseBrowser.allCases.count)
    }

    func testLoadsChromiumCookieDecryptingCiphertext() {
        let db = MuseAuthStore.chromiumCookiePaths(.brave)[0]
        let store = museStore(
            sqlite: Self.encryptedDB(db),
            keychain: FakeKeychain(Self.cookiePassword)
        )
        XCTAssertEqual(store.loadBrowserCookie(), .found(Self.cookiePlaintext))
        XCTAssertTrue(store.browserCookiePresent())
    }

    func testLoadsChromiumCleartextCookieWithoutKeychain() {
        let db = MuseAuthStore.chromiumCookiePaths(.chrome)[0]
        let store = museStore(
            sqlite: MuseFakeSQLite(answer: { path, sql in
                guard path == db, sql.contains("SELECT value") else { return nil }
                return "clear-cookie"
            }),
            keychain: FakeKeychain(nil) // cleartext must not need the keychain
        )
        XCTAssertEqual(store.loadBrowserCookie(), .found("clear-cookie"))
    }

    func testChromiumQueryTargetsCookieTableAndPrefersDevHost() {
        let sqlite = MuseFakeSQLite()
        let store = museStore(sqlite: sqlite, keychain: FakeKeychain("pw"))
        _ = store.loadBrowserCookie()
        let sql = sqlite.lastSQL ?? ""
        XCTAssertTrue(sql.contains("FROM cookies"))
        XCTAssertTrue(sql.contains("name = 'llm_sess'"))
        XCTAssertTrue(sql.contains("dev.meta.ai"))
    }

    func testDefaultBrowserWinsOverFallbackOrder() {
        let braveDB = MuseAuthStore.chromiumCookiePaths(.brave)[0]
        let chromeDB = MuseAuthStore.chromiumCookiePaths(.chrome)[0]
        let store = museStore(
            sqlite: MuseFakeSQLite(answer: { path, sql in
                guard sql.contains("hex(encrypted_value)") else { return nil }
                if path == braveDB { return Self.cookieCipherHex }
                if path == chromeDB { return Self.cookieCipherHex }
                return nil
            }),
            keychain: FakeKeychain(Self.cookiePassword),
            process: MuseFakeProcess(output: """
                LSHandlerRoleAll = "com.google.chrome";
                LSHandlerURLScheme = https;
                """)
        )
        // Both hold the cookie; Chrome is default so its database is read first. Either way the
        // value resolves — the ordering assertion below pins the probe order instead.
        XCTAssertEqual(store.loadBrowserCookie(), .found(Self.cookiePlaintext))
        XCTAssertEqual(store.orderedBrowsers().first, .chrome)
    }

    func testUnsupportedCookieVersionIsUnreadable() {
        let db = MuseAuthStore.chromiumCookiePaths(.brave)[0]
        let store = museStore(
            sqlite: Self.encryptedDB(db, hex: "763830" + String(repeating: "ab", count: 32)),
            keychain: FakeKeychain(Self.cookiePassword)
        )
        // v80: a real cookie the v10/v11 decryptor can't read — must not render as logged out.
        XCTAssertEqual(store.loadBrowserCookie(), .unreadable)
    }

    func testBrowserCookieAbsentWhenNothingStored() {
        let store = museStore()
        XCTAssertEqual(store.loadBrowserCookie(), .absent)
        XCTAssertFalse(store.browserCookiePresent())
    }

    func testDeniedDatabaseIsUnreadable() {
        let db = MuseAuthStore.chromiumCookiePaths(.brave)[0]
        let store = museStore(
            sqlite: MuseFakeSQLite(throwPaths: [db]),
            keychain: FakeKeychain(Self.cookiePassword)
        )
        XCTAssertEqual(store.loadBrowserCookie(), .unreadable)
    }

    func testLoadsFirefoxCookieInCleartext() {
        let db = "\(MuseAuthStore.firefoxProfilesDirectory)/abc.default/cookies.sqlite"
        let store = museStore(
            sqlite: MuseFakeSQLite(answer: { path, _ in path == db ? "firefox-cookie" : nil }),
            profiles: { _ in ["abc.default"] }
        )
        XCTAssertEqual(store.loadBrowserCookie(), .found("firefox-cookie"))
        XCTAssertTrue(store.browserCookiePresent())
    }

    func testLoadsSafariCookieFromBinaryStore() {
        let blob = binarycookiesBlob([
            (url: "example.com", name: "other", value: "nope"),
            (url: ".dev.meta.ai", name: "llm_sess", value: "safari-cookie")
        ])
        let store = museStore(binary: { _ in blob })
        XCTAssertEqual(store.loadBrowserCookie(), .found("safari-cookie"))
        XCTAssertTrue(store.browserCookiePresent())
    }

    func testSafariCorruptStoreIsUnreadable() {
        let store = museStore(binary: { _ in Data("not-cookies".utf8) })
        XCTAssertEqual(store.loadBrowserCookie(), .unreadable)
        XCTAssertFalse(store.browserCookiePresent())
    }

    func testSafariWellFormedStoreWithoutCookieIsAbsent() {
        let blob = binarycookiesBlob([(url: ".example.com", name: "other", value: "nope")])
        XCTAssertTrue(MuseBinaryCookies.isWellFormed(blob))
        let store = museStore(binary: { _ in blob })
        XCTAssertEqual(store.loadBrowserCookie(), .absent)
    }
}

// MARK: - Cookie decrypt + binarycookies

final class MuseCookieDecryptTests: XCTestCase {
    func testDecryptsV10Ciphertext() throws {
        let cookie = try MuseCookieDecrypt.decryptChromiumCookie(
            hex: MuseAuthStoreTests.cookieCipherHex,
            password: MuseAuthStoreTests.cookiePassword
        )
        XCTAssertEqual(cookie, MuseAuthStoreTests.cookiePlaintext)
    }

    func testDecryptsV11TagWithSameScheme() throws {
        // v11 shares the v10 scheme; only the version tag differs.
        let v11 = "763131" + MuseAuthStoreTests.cookieCipherHex.dropFirst(6)
        let cookie = try MuseCookieDecrypt.decryptChromiumCookie(hex: String(v11), password: MuseAuthStoreTests.cookiePassword)
        XCTAssertEqual(cookie, MuseAuthStoreTests.cookiePlaintext)
    }

    func testRejectsBadHexVersionAndPassword() {
        XCTAssertThrowsError(try MuseCookieDecrypt.decryptChromiumCookie(hex: "zz", password: "pw"))
        XCTAssertThrowsError(try MuseCookieDecrypt.decryptChromiumCookie(hex: "763830" + String(repeating: "ab", count: 32), password: "pw"))
        XCTAssertThrowsError(try MuseCookieDecrypt.decryptChromiumCookie(hex: MuseAuthStoreTests.cookieCipherHex, password: "wrong"))
    }
}

final class MuseBinaryCookiesTests: XCTestCase {
    func testFindsCookieByNameAndDomain() {
        let blob = binarycookiesBlob([
            (url: ".dev.meta.ai", name: "llm_sess", value: "wanted"),
            (url: ".dev.meta.ai", name: "other", value: "unwanted"),
            (url: ".example.com", name: "llm_sess", value: "wrong-domain")
        ])
        XCTAssertEqual(MuseBinaryCookies.cookie(named: "llm_sess", domainHint: "meta.ai", in: blob), "wanted")
        XCTAssertNil(MuseBinaryCookies.cookie(named: "missing", domainHint: "meta.ai", in: blob))
    }

    func testMalformedInputYieldsNothing() {
        XCTAssertNil(MuseBinaryCookies.cookie(named: "llm_sess", domainHint: "meta.ai", in: Data()))
        XCTAssertNil(MuseBinaryCookies.cookie(named: "llm_sess", domainHint: "meta.ai", in: Data("cook".utf8)))
        XCTAssertNil(MuseBinaryCookies.cookie(named: "llm_sess", domainHint: "meta.ai", in: Data(repeating: 0, count: 200)))
    }
}

// MARK: - Mapper

final class MuseUsageMapperTests: XCTestCase {
    static let quotaJSON = """
        {"tier":"Muse Code High Usage","as_of":1789148348,\
        "window_weighted_used":"1123886840","window_weighted_limit":"18000000000",\
        "window_resets_at":1789162970,"weekly_weighted_used":"12787866500",\
        "weekly_weighted_limit":"51000000000","weekly_resets_at":1789344000}
        """

    static func usagePage(quota: String = quotaJSON) -> String {
        // Surrounding junk exercises the scanner: braces in and out of strings, nested objects.
        """
        <!DOCTYPE html><html><head><script>var x = {"a": "brace { in string }"};</script></head>\
        <body>{"noise":[1,{"deep":{}}]},["adp_LLMDCUsageQueryRelayPreloader_abc",\
        {"__bbox":{"complete":true,"result":{"data":{"team":\
        {"id":"1","subscription_quota_usage":\(quota)}}}}}] trailing {"junk":true}</body></html>
        """
    }

    func testMapsQuotaLinesWithResets() throws {
        let mapped = try MuseUsageMapper.mapUsagePage(Self.usagePage())

        XCTAssertEqual(mapped.plan, "High Usage")
        XCTAssertEqual(mapped.lines.count, 2)
        let session = try XCTUnwrap(progress(mapped.lines, "Session quota"))
        XCTAssertEqual(session.used, 1123886840.0 / 18000000000.0 * 100, accuracy: 0.0001)
        XCTAssertEqual(session.limit, 100)
        XCTAssertEqual(session.resetsAt, Date(timeIntervalSince1970: 1789162970))
        XCTAssertEqual(session.periodDurationMs, MuseUsageMapper.sessionPeriodMs)
        let weekly = try XCTUnwrap(progress(mapped.lines, "Weekly quota"))
        XCTAssertEqual(weekly.used, 12787866500.0 / 51000000000.0 * 100, accuracy: 0.0001)
        XCTAssertEqual(weekly.resetsAt, Date(timeIntervalSince1970: 1789344000))
        XCTAssertEqual(weekly.periodDurationMs, MuseUsageMapper.weekPeriodMs)
    }

    func testCutsRedundantPrefixButKeepsUnknownTiers() throws {
        func plan(for tier: String) throws -> String? {
            try MuseUsageMapper.mapQuota([
                "tier": tier,
                "window_weighted_used": "1", "window_weighted_limit": "100", "window_resets_at": 1,
                "weekly_weighted_used": "1", "weekly_weighted_limit": "100", "weekly_resets_at": 1
            ]).plan
        }
        XCTAssertEqual(try plan(for: "Muse Code High Usage"), "High Usage")
        XCTAssertEqual(try plan(for: "muse code lower"), "lower")
        XCTAssertEqual(try plan(for: "Something Else"), "Something Else")
        XCTAssertNil(try plan(for: "Muse Code"))
        XCTAssertEqual(try plan(for: "Muse Coder Pro"), "Muse Coder Pro")
    }

    func testMissingBlobMeansSessionExpired() {
        XCTAssertThrowsError(try MuseUsageMapper.mapUsagePage("<html>logged out</html>")) { error in
            XCTAssertEqual(error as? MuseUsageError, .sessionExpired)
        }
    }

    func testIncompleteQuotaIsInvalidResponse() {
        XCTAssertThrowsError(try MuseUsageMapper.mapQuota([:])) { error in
            XCTAssertEqual(error as? MuseUsageError, .invalidResponse)
        }
        XCTAssertThrowsError(try MuseUsageMapper.mapQuota([
            "window_weighted_used": "1", "window_weighted_limit": "0", "window_resets_at": 1,
            "weekly_weighted_used": "1", "weekly_weighted_limit": "10", "weekly_resets_at": 1
        ])) { error in
            XCTAssertEqual(error as? MuseUsageError, .invalidResponse)
        }
    }

    private func progress(_ lines: [MetricLine], _ label: String) -> (used: Double, limit: Double, resetsAt: Date?, periodDurationMs: Int?)? {
        guard case .progress(_, let used, let limit, _, let resetsAt, let periodDurationMs, _) = lines.first(where: { $0.label == label }) else {
            return nil
        }
        return (used, limit, resetsAt, periodDurationMs)
    }
}

// MARK: - Provider

@MainActor
final class MuseProviderTests: XCTestCase {
    func testRefreshUsesManualCookieFirst() async {
        let http = MuseQueueHTTPClient(responses: [
            HTTPResponse(statusCode: 200, headers: [:], body: Data(MuseUsageMapperTests.usagePage().utf8))
        ])
        let provider = MuseProvider(
            authStore: museStore(files: FakeFiles([MuseAuthStore.configPaths[0]: "manual-cookie"])),
            usageClient: MuseUsageClient(http: http),
            now: { Date(timeIntervalSince1970: 1_800_000_000) }
        )

        let snapshot = await provider.refresh()

        XCTAssertEqual(snapshot.plan, "High Usage")
        XCTAssertEqual(snapshot.lines.count, 2)
        XCTAssertEqual(http.requests.count, 1)
        XCTAssertEqual(http.requests.first?.url.absoluteString, "https://dev.meta.ai/usage/")
        XCTAssertEqual(http.requests.first?.headers["Cookie"], "llm_sess=manual-cookie")
        // Bisected live: Accept: text/html is the only header the page needs beyond the
        // cookie — without it the server returns an error page or a quota-less variant.
        XCTAssertEqual(
            http.requests.first?.headers["Accept"],
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        )
    }

    func testRefreshFallsThroughToBrowserCookieAfterRejection() async {
        let http = MuseQueueHTTPClient(responses: [
            HTTPResponse(statusCode: 200, headers: [:], body: Data("<html>logged out</html>".utf8)),
            HTTPResponse(statusCode: 200, headers: [:], body: Data(MuseUsageMapperTests.usagePage().utf8))
        ])
        let db = MuseAuthStore.chromiumCookiePaths(.brave)[0]
        let provider = MuseProvider(
            authStore: museStore(
                files: FakeFiles([MuseAuthStore.configPaths[0]: "stale-cookie"]),
                sqlite: MuseAuthStoreTests.encryptedDB(db),
                keychain: FakeKeychain(MuseAuthStoreTests.cookiePassword)
            ),
            usageClient: MuseUsageClient(http: http)
        )

        let snapshot = await provider.refresh()

        XCTAssertEqual(snapshot.plan, "High Usage")
        XCTAssertEqual(http.requests.count, 2)
        XCTAssertEqual(http.requests.last?.headers["Cookie"], "llm_sess=\(MuseAuthStoreTests.cookiePlaintext)")
    }

    func testRefreshReportsSessionExpiredWhenAllCookiesRejected() async {
        let http = MuseQueueHTTPClient(responses: [
            HTTPResponse(statusCode: 200, headers: [:], body: Data("<html>logged out</html>".utf8))
        ])
        let provider = MuseProvider(
            authStore: museStore(files: FakeFiles([MuseAuthStore.configPaths[0]: "stale-cookie"])),
            usageClient: MuseUsageClient(http: http)
        )

        let snapshot = await provider.refresh()
        XCTAssertEqual(errorText(snapshot), MuseUsageError.sessionExpired.localizedDescription)
    }

    func testRefreshReportsBrowserBlockedWhenStoreUnreadable() async {
        let db = MuseAuthStore.chromiumCookiePaths(.brave)[0]
        let provider = MuseProvider(
            authStore: museStore(sqlite: MuseFakeSQLite(throwPaths: [db])),
            usageClient: MuseUsageClient(http: MuseQueueHTTPClient(responses: []))
        )

        let snapshot = await provider.refresh()
        XCTAssertEqual(errorText(snapshot), MuseAuthError.browserBlocked.localizedDescription)
    }

    func testRefreshReportsNotLoggedInWithoutCookies() async {
        let http = MuseQueueHTTPClient(responses: [])
        let provider = MuseProvider(
            authStore: museStore(),
            usageClient: MuseUsageClient(http: http)
        )

        let snapshot = await provider.refresh()

        XCTAssertEqual(errorText(snapshot), MuseAuthError.notLoggedIn.localizedDescription)
        XCTAssertEqual(http.requests.count, 0)
    }

    func testHasLocalCredentialsMirrorsRefreshSources() async {
        let empty = MuseProvider(authStore: museStore())
        let emptyHasCredentials = await empty.hasLocalCredentials()
        XCTAssertFalse(emptyHasCredentials)

        let manual = MuseProvider(authStore: museStore(files: FakeFiles([MuseAuthStore.configPaths[0]: "x"])))
        let manualHasCredentials = await manual.hasLocalCredentials()
        XCTAssertTrue(manualHasCredentials)

        let db = MuseAuthStore.chromiumCookiePaths(.brave)[0]
        let browser = MuseProvider(authStore: museStore(sqlite: MuseAuthStoreTests.encryptedDB(db)))
        let browserHasCredentials = await browser.hasLocalCredentials()
        XCTAssertTrue(browserHasCredentials)
    }

    func testWidgetDescriptors() {
        let provider = MuseProvider()
        XCTAssertEqual(provider.widgetDescriptors.map(\.id), ["muse.session", "muse.weekly"])
        XCTAssertEqual(provider.provider.links.map(\.label), ["Usage"])
    }

    func testAPIKeyManagementDelegatesToStore() throws {
        let provider = MuseProvider(authStore: museStore())
        XCTAssertEqual(provider.apiKeyStatus, .notSet)
        try provider.saveAPIKey("editor-cookie")
        XCTAssertEqual(provider.currentAPIKey(), "editor-cookie")
        try provider.deleteAPIKey()
        XCTAssertNil(provider.currentAPIKey())
    }

    private func errorText(_ snapshot: ProviderSnapshot) -> String? {
        guard case .badge(_, let text, _, _) = snapshot.lines.first else { return nil }
        return text
    }
}
