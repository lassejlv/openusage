import XCTest
@testable import OpenUsage

@MainActor
final class ProviderMarksTests: XCTestCase {
    func testProviderVectorMarksLoadWithoutFallbacks() throws {
        for id in ["claude", "codex", "cursor", "devin", "grok"] {
            let mark = try XCTUnwrap(ProviderMarks.mark(for: id), "\(id) should load a vector mark")
            XCTAssertFalse(mark.path.isEmpty, "\(id) mark must carry SVG path data")
        }
    }

    func testEveryShippedMarkLoads() throws {
        let dir = try XCTUnwrap(Bundle.openUsageResources.resourceURL?.appendingPathComponent("ProviderIcons"))
        let svgs = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasSuffix(".svg") }
        XCTAssertGreaterThanOrEqual(svgs.count, 12, "expected the full shipped icon set")
        for file in svgs {
            let id = String(file.dropLast(".svg".count))
            let mark = try XCTUnwrap(ProviderMarks.mark(for: id), "\(id) should load a vector mark")
            XCTAssertFalse(mark.path.isEmpty, "\(id) mark must carry SVG path data")
        }
    }

    func testMuseMarkSkipsGradientDefs() throws {
        // muse.svg carries linearGradient defs whose id="meta-…" attributes contain `d="`;
        // the extractor must only take <path> d attributes, or gradient ids parse as geometry.
        let mark = try XCTUnwrap(ProviderMarks.mark(for: "muse"))
        XCTAssertTrue(mark.path.contains("M27.651"), "first real subpath present")
        XCTAssertFalse(mark.path.contains("meta-a"))
        XCTAssertFalse(mark.path.contains("meta-b"))
    }
}
