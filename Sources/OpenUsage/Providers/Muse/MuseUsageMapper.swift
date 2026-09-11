import Foundation

struct MuseMappedUsage: Equatable, Sendable {
    var plan: String?
    var lines: [MetricLine]
}

/// Maps the server-rendered usage page: the `LLMDCUsageQuery` preloader embeds
/// `subscription_quota_usage` (tier, 5h window + weekly used/limit/reset) as JSON in the HTML.
/// A page without that blob means the session cookie was rejected — every other shape problem
/// is an invalid response.
enum MuseUsageMapper {
    static let sessionPeriodMs = MetricPeriod.sessionMs
    static let weekPeriodMs = MetricPeriod.weekMs

    static func mapUsagePage(_ html: String) throws -> MuseMappedUsage {
        guard let quota = extractQuotaObject(html) else {
            throw MuseUsageError.sessionExpired
        }
        return try mapQuota(quota)
    }

    static func mapQuota(_ quota: [String: Any]) throws -> MuseMappedUsage {
        guard let windowUsed = ProviderParse.number(quota["window_weighted_used"]),
              let windowLimit = ProviderParse.number(quota["window_weighted_limit"]),
              let windowReset = ProviderParse.number(quota["window_resets_at"]),
              let weeklyUsed = ProviderParse.number(quota["weekly_weighted_used"]),
              let weeklyLimit = ProviderParse.number(quota["weekly_weighted_limit"]),
              let weeklyReset = ProviderParse.number(quota["weekly_resets_at"]),
              windowLimit > 0, weeklyLimit > 0
        else {
            throw MuseUsageError.invalidResponse
        }

        // The tier repeats the provider name ("Muse Code High Usage" beside "Muse"), so
        // cut the redundant prefix. Unknown shapes pass through untouched.
        var plan = (quota["tier"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
        if let tier = plan {
            // Cut the redundant prefix ("Muse Code High Usage" → "High Usage"); a bare tier
            // leaves no plan rather than a "Muse Muse Code" header. Unknown shapes pass through.
            let lower = tier.lowercased()
            if lower == "muse code" {
                plan = nil
            } else if lower.hasPrefix("muse code ") {
                plan = String(tier.dropFirst("muse code ".count)).trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
            }
        }
        return MuseMappedUsage(
            plan: plan,
            lines: [
                .progress(
                    label: "Session quota",
                    used: ProviderParse.clampPercent(windowUsed / windowLimit * 100),
                    limit: 100,
                    format: .percent,
                    resetsAt: Date(timeIntervalSince1970: windowReset),
                    periodDurationMs: sessionPeriodMs
                ),
                .progress(
                    label: "Weekly quota",
                    used: ProviderParse.clampPercent(weeklyUsed / weeklyLimit * 100),
                    limit: 100,
                    format: .percent,
                    resetsAt: Date(timeIntervalSince1970: weeklyReset),
                    periodDurationMs: weekPeriodMs
                )
            ]
        )
    }

    /// Extract the `"subscription_quota_usage": {...}` object with a string/escape-aware
    /// balanced-brace scan (the page holds several preloader blobs; the quota key is unique).
    static func extractQuotaObject(_ html: String) -> [String: Any]? {
        guard let keyRange = html.range(of: "\"subscription_quota_usage\":"),
              let open = html[keyRange.upperBound...].firstIndex(of: "{"),
              let raw = balancedObject(html, from: open),
              let data = raw.data(using: .utf8),
              let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            return nil
        }
        return object
    }

    private static func balancedObject(_ text: String, from open: String.Index) -> String? {
        var depth = 0
        var inString = false
        var escaped = false
        var index = open
        while index < text.endIndex {
            let char = text[index]
            if inString {
                if escaped {
                    escaped = false
                } else if char == "\\" {
                    escaped = true
                } else if char == "\"" {
                    inString = false
                }
            } else if char == "\"" {
                inString = true
            } else if char == "{" {
                depth += 1
            } else if char == "}" {
                depth -= 1
                if depth == 0 {
                    return String(text[open...index])
                }
            }
            index = text.index(after: index)
        }
        return nil
    }
}

enum MuseUsageError: Error, LocalizedError, Equatable {
    case sessionExpired
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .sessionExpired:
            return "Your dev.meta.ai session expired. Sign in again in your browser and refresh."
        case .invalidResponse:
            return "Muse usage data unavailable. Try again later."
        }
    }
}
