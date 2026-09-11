import Foundation

@MainActor
final class MuseProvider: ProviderRuntime {
    let provider = Provider(
        id: "muse",
        displayName: "Muse",
        icon: .providerMark("muse"),
        links: [
            .init(label: "Usage", url: "https://dev.meta.ai/usage/")
        ]
    )

    let authStore: MuseAuthStore
    let usageClient: MuseUsageClient
    let now: @Sendable () -> Date

    init(
        authStore: MuseAuthStore = MuseAuthStore(),
        usageClient: MuseUsageClient = MuseUsageClient(),
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.authStore = authStore
        self.usageClient = usageClient
        self.now = now
    }

    var widgetDescriptors: [WidgetDescriptor] {
        [
            .percent(id: "muse.session", provider: provider, title: "Session", metricLabel: "Session quota")
                .exportingLimit("session", unit: "percent"),
            .percent(id: "muse.weekly", provider: provider, title: "Weekly", metricLabel: "Weekly quota")
                .exportingLimit("weekly", unit: "percent")
        ]
    }

    func hasLocalCredentials() async -> Bool {
        // Same sources as `refresh()`: the saved cookie / env var, then any browser holding the
        // session cookie. All local-only; the browser check is a row-presence probe that never
        // reads the keychain, so it can't prompt. Blocking loads run off the main actor.
        if await loadOffMainActor({ [authStore] in authStore.loadManualCookie() }) != nil { return true }
        return await loadOffMainActor { [authStore] in authStore.browserCookiePresent() }
    }

    func refresh() async -> ProviderSnapshot {
        var sawCookie = false
        var sawAuthFailure = false
        var sawUnreadable = false

        // A manually saved cookie (or env var) wins; a rejected one falls through to the
        // browser so a stale saved value doesn't wedge refresh while the browser is signed in.
        if let manual = await loadOffMainActor({ [authStore] in authStore.loadManualCookie() }) {
            sawCookie = true
            switch await attempt(auth: manual) {
            case .success(let mapped):
                return snapshot(from: mapped)
            case .authFailure:
                sawAuthFailure = true
            case .unavailable:
                return ProviderSnapshot.error(provider: provider, error: MuseUsageError.invalidResponse)
            }
        }

        switch await loadOffMainActor({ [authStore] in authStore.loadBrowserCookie() }) {
        case .found(let cookie):
            sawCookie = true
            switch await attempt(auth: MuseAuth(sessionCookie: cookie)) {
            case .success(let mapped):
                return snapshot(from: mapped)
            case .authFailure:
                sawAuthFailure = true
            case .unavailable:
                return ProviderSnapshot.error(provider: provider, error: MuseUsageError.invalidResponse)
            }
        case .unreadable:
            sawUnreadable = true
        case .absent:
            break
        }

        if sawAuthFailure {
            return ProviderSnapshot.error(provider: provider, error: MuseUsageError.sessionExpired)
        }
        if sawUnreadable, !sawCookie {
            return ProviderSnapshot.error(provider: provider, error: MuseAuthError.browserBlocked)
        }
        return ProviderSnapshot.error(provider: provider, error: MuseAuthError.notLoggedIn)
    }

    private func attempt(auth: MuseAuth) async -> MuseAuthAttempt {
        do {
            let response = try await usageClient.fetchUsagePage(sessionCookie: auth.sessionCookie)
            if response.statusCode == 401 || response.statusCode == 403 {
                return .authFailure
            }
            guard (200..<300).contains(response.statusCode),
                  let html = String(data: response.body, encoding: .utf8)
            else {
                return .unavailable
            }
            do {
                return .success(try MuseUsageMapper.mapUsagePage(html))
            } catch MuseUsageError.sessionExpired {
                // The page loaded but carries no quota blob: the cookie was rejected.
                return .authFailure
            } catch {
                return .unavailable
            }
        } catch {
            return .unavailable
        }
    }

    private func snapshot(from mapped: MuseMappedUsage) -> ProviderSnapshot {
        ProviderSnapshot.make(provider: provider, plan: mapped.plan, lines: mapped.lines, refreshedAt: now())
    }
}

private enum MuseAuthAttempt {
    case success(MuseMappedUsage)
    case authFailure
    case unavailable
}

extension MuseProvider: APIKeyManaging {
    /// The manual cookie only (saved file > env): the browser cookie isn't a user-managed key,
    /// so the editor neither shows nor clears it — it stays a silent fallback underneath.
    var apiKeyStatus: APIKeyStatus { authStore.keyStatus() }
    func currentAPIKey() -> String? { authStore.currentAPIKey() }
    func saveAPIKey(_ key: String) throws { try authStore.saveAPIKey(key) }
    func deleteAPIKey() throws { try authStore.deleteAPIKey() }
}
