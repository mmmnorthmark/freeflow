import Foundation

enum UpdateSecurityPolicy {
    static let expectedDMGAssetName = "FreeFlow.dmg"
    static let releaseOwner = "zachlatta"
    static let releaseRepository = "freeflow"

    static func isExpectedAssetName(_ name: String) -> Bool {
        name == expectedDMGAssetName
    }

    static func isAllowedInitialDownloadURL(_ url: URL, releaseTag: String) -> Bool {
        guard url.scheme?.lowercased() == "https",
              url.host?.lowercased() == "github.com",
              url.user == nil,
              url.password == nil,
              url.port == nil,
              url.query == nil,
              url.fragment == nil,
              !releaseTag.isEmpty,
              !releaseTag.contains("/") else {
            return false
        }

        let expectedPath = "/\(releaseOwner)/\(releaseRepository)/releases/download/\(releaseTag)/\(expectedDMGAssetName)"
        return url.path == expectedPath
    }

    static func isAllowedFinalDownloadURL(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == "https",
              let host = url.host?.lowercased(),
              url.user == nil,
              url.password == nil,
              url.port == nil else {
            return false
        }

        return host == "github.com"
            || host == "objects.githubusercontent.com"
            || host.hasSuffix(".githubusercontent.com")
    }

    static func hasExpectedDownloadSize(expected: Int, actual: Int) -> Bool {
        expected <= 0 || expected == actual
    }

    static func signingTeamIdentifier(fromCodesignOutput output: String) -> String? {
        for line in output.components(separatedBy: .newlines) {
            guard line.hasPrefix("TeamIdentifier=") else { continue }
            let value = String(line.dropFirst("TeamIdentifier=".count))
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return value == "not set" || value.isEmpty ? nil : value
        }
        return nil
    }
}
