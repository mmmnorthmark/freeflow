import Foundation

enum ProviderErrorPolicy {
    static func httpMessage(statusCode: Int, data: Data) -> String {
        if data.isEmpty {
            return "Provider returned HTTP \(statusCode) with no response body."
        }
        return "Provider returned HTTP \(statusCode) with \(data.count) bytes of error details."
    }

    static func realtimeMessage(_ rawMessage: String) -> String {
        if rawMessage.isEmpty {
            return "Provider returned an unknown realtime error."
        }
        return "Provider returned \(rawMessage.utf8.count) bytes of realtime error details."
    }
}
