import Foundation

struct PipelineHistoryStartupResult {
    let history: [PipelineHistoryItem]
    let audioFileNamesToDelete: [String]
}

enum PipelineHistoryRetentionPolicy {
    static func prepareForStartup(
        retentionEnabled: Bool,
        maxCount: Int,
        trim: (Int) throws -> [String],
        clear: () throws -> [String],
        load: () -> [PipelineHistoryItem],
        reportError: (String) -> Void
    ) -> PipelineHistoryStartupResult {
        if retentionEnabled {
            let removedAudioFileNames: [String]
            do {
                removedAudioFileNames = try trim(maxCount)
            } catch {
                reportError("Failed to trim pipeline history during init: \(error)")
                removedAudioFileNames = []
            }
            return PipelineHistoryStartupResult(
                history: load(),
                audioFileNamesToDelete: removedAudioFileNames
            )
        }

        let removedAudioFileNames: [String]
        do {
            removedAudioFileNames = try clear()
        } catch {
            reportError("Failed to clear disabled pipeline history during init: \(error)")
            removedAudioFileNames = []
        }
        return PipelineHistoryStartupResult(
            history: [],
            audioFileNamesToDelete: removedAudioFileNames
        )
    }

    static func discardAudioIfRetentionDisabled(
        retentionEnabled: Bool,
        audioFileName: String?,
        deleteAudioFile: (String) -> Void
    ) -> Bool {
        guard !retentionEnabled else { return false }
        if let audioFileName {
            deleteAudioFile(audioFileName)
        }
        return true
    }
}
