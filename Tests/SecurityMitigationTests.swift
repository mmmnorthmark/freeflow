import Foundation

enum SecurityMitigationTests {
    static func run() {
        testSecureHTTPProviderURLs()
        testLoopbackHTTPProviderURLs()
        testInsecureHTTPProviderURLs()
        testSecureRealtimeProviderURLs()
        testLoopbackRealtimeProviderURLs()
        testInsecureRealtimeProviderURLs()
        testProviderHTTPErrorRedaction()
        testProviderRealtimeErrorRedaction()
        testTranscriptionErrorMessages()
        testUpdateAssetPolicy()
        testUpdateInitialDownloadURLPolicy()
        testUpdateRedirectURLPolicy()
        testUpdateDownloadSizePolicy()
        testSigningTeamIdentifierParsing()
        print("SecurityMitigationTests passed")
    }

    private static func testSecureHTTPProviderURLs() {
        expectURL(
            try? ProviderURLPolicy.normalizedHTTPBaseURL(from: "  HTTPS://api.example.com/v1///  "),
            "https://api.example.com/v1"
        )
        expectURL(
            try? ProviderURLPolicy.normalizedHTTPBaseURL(from: "https://api.example.com/"),
            "https://api.example.com"
        )
    }

    private static func testLoopbackHTTPProviderURLs() {
        let allowedHosts = [
            "localhost",
            "127.0.0.1",
            "127.1.2.3",
            "[::1]",
            "[0:0:0:0:0:0:0:1]"
        ]

        for host in allowedHosts {
            expect(
                (try? ProviderURLPolicy.normalizedHTTPBaseURL(from: "http://\(host):8080/v1")) != nil,
                "Expected loopback HTTP provider to be allowed: \(host)"
            )
        }
    }

    private static func testInsecureHTTPProviderURLs() {
        let rejectedURLs = [
            "",
            "api.example.com/v1",
            "ftp://api.example.com/v1",
            "http://api.example.com/v1",
            "http://127.attacker.example/v1",
            "http://127.0.0.999/v1",
            "http://127.0.0/v1"
        ]

        for value in rejectedURLs {
            expectThrows("Expected insecure provider URL to be rejected: \(value)") {
                _ = try ProviderURLPolicy.normalizedHTTPBaseURL(from: value)
            }
        }
    }

    private static func testSecureRealtimeProviderURLs() {
        expectURL(
            ProviderURLPolicy.normalizedRealtimeWebSocketURL(
                from: "https://api.example.com/v1/",
                model: "model",
                language: nil
            ),
            "wss://api.example.com/v1/realtime?intent=transcription"
        )
        expectURL(
            ProviderURLPolicy.normalizedRealtimeWebSocketURL(
                from: "wss://api.example.com/custom?intent=translation&token=public",
                model: "model",
                language: "en"
            ),
            "wss://api.example.com/custom/v1/realtime?intent=translation&token=public"
        )
    }

    private static func testLoopbackRealtimeProviderURLs() {
        expectURL(
            ProviderURLPolicy.normalizedRealtimeWebSocketURL(
                from: "http://127.0.0.2:8080/v1",
                model: "model",
                language: nil
            ),
            "ws://127.0.0.2:8080/v1/realtime?intent=transcription"
        )
        expectURL(
            ProviderURLPolicy.normalizedRealtimeWebSocketURL(
                from: "ws://[::1]:8080",
                model: "model",
                language: nil
            ),
            "ws://[::1]:8080/v1/realtime?intent=transcription"
        )
    }

    private static func testInsecureRealtimeProviderURLs() {
        let rejectedURLs = [
            "ws://api.example.com/v1",
            "http://api.example.com/v1",
            "ws://127.attacker.example/v1",
            "ftp://localhost/v1"
        ]

        for value in rejectedURLs {
            let url = ProviderURLPolicy.normalizedRealtimeWebSocketURL(
                from: value,
                model: "model",
                language: nil
            )
            expect(url == nil, "Expected insecure realtime URL to be rejected: \(value)")
        }
    }

    private static func testProviderHTTPErrorRedaction() {
        let secretBody = Data(#"{"error":"secret provider details"}"#.utf8)
        let message = ProviderErrorPolicy.httpMessage(statusCode: 500, data: secretBody)

        expect(message == "Provider returned HTTP 500 with \(secretBody.count) bytes of error details.", "Unexpected HTTP redaction message")
        expect(!message.contains("secret provider details"), "Raw HTTP provider error leaked")
        expect(
            ProviderErrorPolicy.httpMessage(statusCode: 502, data: Data())
                == "Provider returned HTTP 502 with no response body.",
            "Empty provider response was described incorrectly"
        )
    }

    private static func testProviderRealtimeErrorRedaction() {
        let rawMessage = "secret provider details 🔒"
        let message = ProviderErrorPolicy.realtimeMessage(rawMessage)

        expect(
            message == "Provider returned \(rawMessage.utf8.count) bytes of realtime error details.",
            "Unexpected realtime redaction message"
        )
        expect(!message.contains("secret provider details"), "Raw realtime provider error leaked")
        expect(
            ProviderErrorPolicy.realtimeMessage("") == "Provider returned an unknown realtime error.",
            "Empty realtime error was described incorrectly"
        )
    }

    private static func testTranscriptionErrorMessages() {
        let statuses = [400, 401, 403, 404, 413, 429, 500, 599, 418]
        for status in statuses {
            let message = TranscriptionService.friendlyHTTPMessage(
                status: status,
                host: "api.example.com"
            )
            expect(message.contains("api.example.com") || status == 400, "Provider host missing for HTTP \(status)")
            expect(!message.contains("{"), "Transcription error included a raw response body")
        }
    }

    private static func testUpdateAssetPolicy() {
        expect(UpdateSecurityPolicy.isExpectedAssetName("FreeFlow.dmg"), "Expected release asset was rejected")
        expect(!UpdateSecurityPolicy.isExpectedAssetName("FreeFlow-1.2.0.dmg"), "Versioned asset name was accepted")
        expect(!UpdateSecurityPolicy.isExpectedAssetName("FreeFlow.dmg.zip"), "Asset suffix was accepted")
        expect(!UpdateSecurityPolicy.isExpectedAssetName("freeflow.dmg"), "Case-altered asset was accepted")
    }

    private static func testUpdateInitialDownloadURLPolicy() {
        let allowed = URL(string: "https://github.com/zachlatta/freeflow/releases/download/v1.2.0/FreeFlow.dmg")!
        expect(
            UpdateSecurityPolicy.isAllowedInitialDownloadURL(allowed, releaseTag: "v1.2.0"),
            "Expected GitHub release URL was rejected"
        )

        let rejected = [
            "http://github.com/zachlatta/freeflow/releases/download/v1.2.0/FreeFlow.dmg",
            "https://github.com.evil.example/zachlatta/freeflow/releases/download/v1.2.0/FreeFlow.dmg",
            "https://github.com/attacker/freeflow/releases/download/v1.2.0/FreeFlow.dmg",
            "https://github.com/zachlatta/freeflow/releases/download/v1.2.0/Other.dmg",
            "https://user@github.com/zachlatta/freeflow/releases/download/v1.2.0/FreeFlow.dmg",
            "https://github.com:444/zachlatta/freeflow/releases/download/v1.2.0/FreeFlow.dmg",
            "https://github.com/zachlatta/freeflow/releases/download/v1.2.0/FreeFlow.dmg?redirect=evil"
        ]
        for value in rejected {
            expect(
                !UpdateSecurityPolicy.isAllowedInitialDownloadURL(URL(string: value)!, releaseTag: "v1.2.0"),
                "Untrusted initial update URL was accepted: \(value)"
            )
        }
        expect(
            !UpdateSecurityPolicy.isAllowedInitialDownloadURL(allowed, releaseTag: "v1.2.0/../../evil"),
            "Release tag path injection was accepted"
        )
    }

    private static func testUpdateRedirectURLPolicy() {
        let allowed = [
            "https://github.com/release",
            "https://objects.githubusercontent.com/release?signature=value",
            "https://release-assets.githubusercontent.com/release"
        ]
        for value in allowed {
            expect(
                UpdateSecurityPolicy.isAllowedFinalDownloadURL(URL(string: value)!),
                "Expected update redirect URL was rejected: \(value)"
            )
        }

        let rejected = [
            "http://objects.githubusercontent.com/release",
            "https://objects.githubusercontent.com.evil.example/release",
            "https://evilgithubusercontent.com/release",
            "https://user@objects.githubusercontent.com/release",
            "https://objects.githubusercontent.com:444/release"
        ]
        for value in rejected {
            expect(
                !UpdateSecurityPolicy.isAllowedFinalDownloadURL(URL(string: value)!),
                "Untrusted update redirect URL was accepted: \(value)"
            )
        }
    }

    private static func testUpdateDownloadSizePolicy() {
        expect(UpdateSecurityPolicy.hasExpectedDownloadSize(expected: 42, actual: 42), "Matching download size was rejected")
        expect(!UpdateSecurityPolicy.hasExpectedDownloadSize(expected: 42, actual: 41), "Truncated download was accepted")
        expect(!UpdateSecurityPolicy.hasExpectedDownloadSize(expected: 42, actual: 43), "Oversized download was accepted")
        expect(UpdateSecurityPolicy.hasExpectedDownloadSize(expected: 0, actual: 43), "Unknown expected size should not reject a download")
    }

    private static func testSigningTeamIdentifierParsing() {
        let signedOutput = """
        Executable=/Applications/FreeFlow.app/Contents/MacOS/FreeFlow
        Identifier=com.zachlatta.freeflow
        TeamIdentifier=ABC123XYZ
        """
        expect(
            UpdateSecurityPolicy.signingTeamIdentifier(fromCodesignOutput: signedOutput) == "ABC123XYZ",
            "Signing team identifier was not parsed"
        )
        expect(
            UpdateSecurityPolicy.signingTeamIdentifier(fromCodesignOutput: "TeamIdentifier=not set") == nil,
            "Unsigned marker was treated as a signing team"
        )
        expect(
            UpdateSecurityPolicy.signingTeamIdentifier(fromCodesignOutput: "Identifier=com.example") == nil,
            "Missing signing team produced a value"
        )
    }

    private static func expectURL(
        _ actual: URL?,
        _ expected: String,
        file: StaticString = #file,
        line: UInt = #line
    ) {
        expect(
            actual?.absoluteString == expected,
            "Expected \(expected.debugDescription), got \((actual?.absoluteString ?? "nil").debugDescription)",
            file: file,
            line: line
        )
    }

    private static func expectThrows(
        _ message: String,
        file: StaticString = #file,
        line: UInt = #line,
        _ operation: () throws -> Void
    ) {
        do {
            try operation()
            expect(false, message, file: file, line: line)
        } catch {
            return
        }
    }

    private static func expect(
        _ condition: Bool,
        _ message: String,
        file: StaticString = #file,
        line: UInt = #line
    ) {
        if !condition {
            fatalError("\(file):\(line): \(message)")
        }
    }
}
