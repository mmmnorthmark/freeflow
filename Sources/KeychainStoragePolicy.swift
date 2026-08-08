import Foundation
import Security

struct PlaintextSettingMigrationPlan {
    let updatedSettings: [String: String]
    let valueToSaveInKeychain: String?
}

enum KeychainStoragePolicy {
    static func plaintextMigrationPlan(
        settings: [String: String],
        account: String,
        existingKeychainValue: String?
    ) -> PlaintextSettingMigrationPlan? {
        guard let plaintextValue = settings[account] else { return nil }

        var updatedSettings = settings
        updatedSettings.removeValue(forKey: account)
        updatedSettings.removeValue(forKey: "keychain_migration_done")

        let existingValue = existingKeychainValue?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let plaintextIsEmpty = plaintextValue
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .isEmpty

        return PlaintextSettingMigrationPlan(
            updatedSettings: updatedSettings,
            valueToSaveInKeychain: existingValue.isEmpty && !plaintextIsEmpty ? plaintextValue : nil
        )
    }

    static func baseQuery(service: String, account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }

    static func addQuery(service: String, account: String, data: Data) -> [String: Any] {
        var query = baseQuery(service: service, account: account)
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        query[kSecValueData as String] = data
        return query
    }
}
