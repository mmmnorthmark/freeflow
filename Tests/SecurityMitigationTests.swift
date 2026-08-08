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
