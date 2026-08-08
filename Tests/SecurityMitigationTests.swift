import Foundation

enum SecurityMitigationTests {
    static func run() {
        testSecureHTTPProviderURLs()
        testLoopbackHTTPProviderURLs()
        testInsecureHTTPProviderURLs()
        testSecureRealtimeProviderURLs()
        testLoopbackRealtimeProviderURLs()
        testInsecureRealtimeProviderURLs()
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
