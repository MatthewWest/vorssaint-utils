// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Vorssaint

import Foundation
import SQLite3

/// Reads Google Antigravity conversation and trajectory state from local SQLite databases
/// (~/.gemini/antigravity/conversations/<uuid>.db and ~/.gemini/antigravity-cli/conversations/<uuid>.db).
enum AgentAntigravityReader {
    /// SQLite busy timeout in milliseconds to tolerate concurrent WAL flushes.
    static let busyTimeoutMs: Int32 = 2000

    /// Maximum parent traversal hops in conversation summaries to prevent circular cycles.
    static let maxParentHops: Int = 8

    // MARK: - Modification & Discovery

    /// When the database or its WAL last changed; nil when the file does not exist.
    static func modified(_ path: String) -> Date? {
        var info = stat()
        guard stat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return nil }
        var wal = stat()
        let walModified = stat(path + "-wal", &wal) == 0 ? date(wal.st_mtimespec) : .distantPast
        return max(date(info.st_mtimespec), walModified)
    }

    /// When sibling conversation_summaries.db (or its WAL) last changed.
    static func summaryModified(for path: String) -> Date? {
        let summaryPath = summaryDbPath(for: path)
        return modified(summaryPath)
    }

    /// Resolves the sibling conversation_summaries.db path for a given conversation database path.
    static func summaryDbPath(for path: String) -> String {
        let conversationsDir = (path as NSString).deletingLastPathComponent
        let rootDir = (conversationsDir as NSString).deletingLastPathComponent
        return (rootDir as NSString).appendingPathComponent("conversation_summaries.db")
    }

    private static func date(_ time: timespec) -> Date {
        Date(timeIntervalSince1970: TimeInterval(time.tv_sec) + TimeInterval(time.tv_nsec) / 1_000_000_000)
    }

    /// Checks if a path is accepted by an Antigravity log root.
    /// Strictly filters out encrypted `<uuid>.pb` application state files.
    static func accepts(root: AgentLogRoot, path: String) -> Bool {
        let prefix = root.url.path + "/conversations/"
        guard path.hasPrefix(prefix) else { return false }
        let filename = (path as NSString).lastPathComponent
        guard filename.hasSuffix(".db") && !filename.hasSuffix(".pb") else { return false }
        return true
    }

    /// Discovers Antigravity conversation databases modified since horizon.
    /// Strictly ignores encrypted `<uuid>.pb` blobs.
    static func discover(root: AgentLogRoot, since horizon: Date) -> [(path: String, provider: AgentProvider)] {
        let convDir = root.url.appending(path: "conversations", directoryHint: .isDirectory)
        guard let files = try? FileManager.default.contentsOfDirectory(
            at: convDir,
            includingPropertiesForKeys: [.contentModificationDateKey, .isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else { return [] }

        var result: [(path: String, provider: AgentProvider)] = []
        for file in files {
            let path = file.path
            guard path.hasSuffix(".db") && !path.hasSuffix(".pb") else { continue }
            guard let mtime = modified(path), mtime >= horizon else { continue }
            result.append((path: path, provider: .antigravity))
        }
        return result
    }

    // MARK: - Zero-Copy Protobuf Wire Scanner

    struct ParsedModelUsage {
        var modelEnum: Int = 0
        var inputTokens: Int = 0
        var outputTokens: Int = 0
        var cacheReadTokens: Int = 0
        var thinkingTokens: Int = 0
        var responseOutputTokens: Int = 0
        var modelCost: Double? = nil
    }

    struct ParsedStepMetadata {
        var createdAt: Date? = nil
        var finishedAt: Date? = nil
        var lastCompletedChunkAt: Date? = nil
        var usage: ParsedModelUsage? = nil
        var generatorModelEnum: Int = 0
        var modelCost: Double? = nil
    }

    struct ParsedGenMetadata {
        var stepIndices: [Int64] = []
        var responseModel: String = ""
        var modelEnum: Int = 0
        var usageFallback: ParsedModelUsage? = nil
    }

    struct ParsedTrajectoryMetadata {
        var workspaceFolder: String = ""
        var gitRoot: String = ""
        var branchName: String = ""
        var createdAt: Date? = nil
        var parentConversationID: String = ""
        var rootConversationID: String = ""
        var nestingDepth: Int = 0
    }

    /// 64-bit FNV-1a hash over raw buffer slice.
    static func fnv1a64(_ buffer: UnsafeRawBufferPointer) -> UInt64 {
        var hash: UInt64 = 14695981039346656037
        for byte in buffer {
            hash ^= UInt64(byte)
            hash = hash &* 1099511628211
        }
        return hash
    }

    /// Reads an unsigned varint from the buffer, advancing pos.
    /// Guards against invalid 10th varint byte to prevent malformed overflows.
    static func readVarint(_ pos: inout Int, buffer: UnsafeRawBufferPointer) -> UInt64? {
        var result: UInt64 = 0
        var shift = 0
        let count = buffer.count
        while pos < count {
            let byte = buffer[pos]
            pos += 1
            if shift == 63 {
                if (byte & 0x7F) > 1 { return nil }
                result |= UInt64(byte & 0x7F) << shift
                return result
            }
            result |= UInt64(byte & 0x7F) << shift
            if (byte & 0x80) == 0 { return result }
            shift += 7
        }
        return nil
    }

    /// Skips a field of the given wire type.
    static func skipField(wireType: Int, pos: inout Int, buffer: UnsafeRawBufferPointer) -> Bool {
        switch wireType {
        case 0: // Varint
            return readVarint(&pos, buffer: buffer) != nil
        case 1: // 64-bit
            guard pos + 8 <= buffer.count else { return false }
            pos += 8
            return true
        case 2: // Length-delimited
            guard let rawLen = readVarint(&pos, buffer: buffer) else { return false }
            guard rawLen <= UInt64(buffer.count - pos) else { return false }
            pos += Int(rawLen)
            return true
        case 5: // 32-bit
            guard pos + 4 <= buffer.count else { return false }
            pos += 4
            return true
        default:
            return false
        }
    }

    /// Reads a length-delimited submessage buffer slice.
    static func readSubmessage(pos: inout Int, buffer: UnsafeRawBufferPointer) -> UnsafeRawBufferPointer? {
        guard let rawLen = readVarint(&pos, buffer: buffer) else { return nil }
        guard rawLen <= UInt64(buffer.count - pos) else { return nil }
        let len = Int(rawLen)
        let sub = UnsafeRawBufferPointer(rebasing: buffer[pos ..< pos + len])
        pos += len
        return sub
    }

    /// Reads a length-delimited UTF-8 string.
    static func readString(pos: inout Int, buffer: UnsafeRawBufferPointer) -> String? {
        guard let sub = readSubmessage(pos: &pos, buffer: buffer) else { return nil }
        guard let base = sub.baseAddress else { return "" }
        return String(decoding: UnsafeBufferPointer(start: base.assumingMemoryBound(to: UInt8.self), count: sub.count), as: UTF8.self)
    }

    /// Decodes a google.protobuf.Timestamp submessage.
    static func parseTimestamp(_ buffer: UnsafeRawBufferPointer) -> Date? {
        var pos = 0
        var seconds: Int64 = 0
        var nanos: Int32 = 0
        while pos < buffer.count {
            guard let tag = readVarint(&pos, buffer: buffer) else { break }
            let fieldNum = Int(tag >> 3)
            let wireType = Int(tag & 0x7)
            if fieldNum == 1 && wireType == 0 {
                guard let sec = readVarint(&pos, buffer: buffer) else { break }
                seconds = Int64(bitPattern: sec)
            } else if fieldNum == 2 && wireType == 0 {
                guard let n = readVarint(&pos, buffer: buffer) else { break }
                nanos = Int32(truncatingIfNeeded: n)
            } else {
                guard skipField(wireType: wireType, pos: &pos, buffer: buffer) else { break }
            }
        }
        guard seconds > 0 else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(seconds) + TimeInterval(nanos) / 1_000_000_000)
    }

    /// Decodes a ModelUsageStats submessage with zero double-counting.
    static func parseModelUsageStats(_ buffer: UnsafeRawBufferPointer) -> ParsedModelUsage {
        var pos = 0
        var stats = ParsedModelUsage()
        while pos < buffer.count {
            guard let tag = readVarint(&pos, buffer: buffer) else { break }
            let fieldNum = Int(tag >> 3)
            let wireType = Int(tag & 0x7)
            switch (fieldNum, wireType) {
            case (1, 0):
                if let v = readVarint(&pos, buffer: buffer) { stats.modelEnum = Int(v) }
            case (2, 0):
                if let v = readVarint(&pos, buffer: buffer) { stats.inputTokens = Int(v) }
            case (3, 0):
                if let v = readVarint(&pos, buffer: buffer) { stats.outputTokens = Int(v) }
            case (4, 0), (6, 0):
                if let v = readVarint(&pos, buffer: buffer) { stats.cacheReadTokens = Int(v) }
            case (9, 0):
                if let v = readVarint(&pos, buffer: buffer) { stats.thinkingTokens = Int(v) }
            case (10, 0):
                if let v = readVarint(&pos, buffer: buffer) { stats.responseOutputTokens = Int(v) }
            case (10, 5):
                guard pos + 4 <= buffer.count else { break }
                let bits = buffer.loadUnaligned(fromByteOffset: pos, as: UInt32.self)
                pos += 4
                let cost = Double(Float(bitPattern: UInt32(littleEndian: bits)))
                if cost.isFinite && cost > 0 && cost < 1_000_000 {
                    stats.modelCost = cost
                }
            default:
                guard skipField(wireType: wireType, pos: &pos, buffer: buffer) else { return stats }
            }
        }
        return stats
    }

    /// Decodes CortexStepMetadata from steps.metadata blob.
    static func parseStepMetadata(_ buffer: UnsafeRawBufferPointer) -> ParsedStepMetadata {
        var pos = 0
        var meta = ParsedStepMetadata()
        while pos < buffer.count {
            guard let tag = readVarint(&pos, buffer: buffer) else { break }
            let fieldNum = Int(tag >> 3)
            let wireType = Int(tag & 0x7)
            switch (fieldNum, wireType) {
            case (1, 2):
                if let sub = readSubmessage(pos: &pos, buffer: buffer) {
                    meta.createdAt = parseTimestamp(sub)
                }
            case (5, 2), (7, 2):
                if let sub = readSubmessage(pos: &pos, buffer: buffer) {
                    meta.finishedAt = parseTimestamp(sub)
                }
            case (8, 2):
                if let sub = readSubmessage(pos: &pos, buffer: buffer) {
                    meta.lastCompletedChunkAt = parseTimestamp(sub)
                }
            case (9, 2), (12, 2):
                if let sub = readSubmessage(pos: &pos, buffer: buffer) {
                    meta.usage = parseModelUsageStats(sub)
                }
            case (6, 0), (11, 0):
                if let v = readVarint(&pos, buffer: buffer) {
                    meta.generatorModelEnum = Int(v)
                }
            case (10, 5):
                guard pos + 4 <= buffer.count else { break }
                let bits = buffer.loadUnaligned(fromByteOffset: pos, as: UInt32.self)
                pos += 4
                let cost = Double(Float(bitPattern: UInt32(littleEndian: bits)))
                if cost.isFinite && cost > 0 && cost < 1_000_000 {
                    meta.modelCost = cost
                }
            default:
                guard skipField(wireType: wireType, pos: &pos, buffer: buffer) else { return meta }
            }
        }
        return meta
    }

    /// Decodes ChatGeneratorMetadata from gen_metadata.data blob.
    static func parseGenMetadata(_ buffer: UnsafeRawBufferPointer) -> ParsedGenMetadata {
        var pos = 0
        var gen = ParsedGenMetadata()
        while pos < buffer.count {
            guard let tag = readVarint(&pos, buffer: buffer) else { break }
            let fieldNum = Int(tag >> 3)
            let wireType = Int(tag & 0x7)
            switch (fieldNum, wireType) {
            case (2, 2): // Packed step_indices
                if let sub = readSubmessage(pos: &pos, buffer: buffer) {
                    var subPos = 0
                    while subPos < sub.count {
                        if let idx = readVarint(&subPos, buffer: sub) {
                            gen.stepIndices.append(Int64(bitPattern: idx))
                        }
                    }
                }
            case (2, 0): // Repeated step_indices
                if let idx = readVarint(&pos, buffer: buffer) {
                    gen.stepIndices.append(Int64(bitPattern: idx))
                }
            case (1, 2): // ChatModelMetadata
                if let sub = readSubmessage(pos: &pos, buffer: buffer) {
                    parseChatModelMetadata(sub, into: &gen)
                }
            default:
                guard skipField(wireType: wireType, pos: &pos, buffer: buffer) else { return gen }
            }
        }
        return gen
    }

    private static func parseChatModelMetadata(_ buffer: UnsafeRawBufferPointer, into gen: inout ParsedGenMetadata) {
        var pos = 0
        while pos < buffer.count {
            guard let tag = readVarint(&pos, buffer: buffer) else { break }
            let fieldNum = Int(tag >> 3)
            let wireType = Int(tag & 0x7)
            switch (fieldNum, wireType) {
            case (3, 0):
                if let v = readVarint(&pos, buffer: buffer) { gen.modelEnum = Int(v) }
            case (4, 2):
                if let sub = readSubmessage(pos: &pos, buffer: buffer) {
                    gen.usageFallback = parseModelUsageStats(sub)
                }
            case (14, 2), (19, 2):
                if let str = readString(pos: &pos, buffer: buffer), !str.isEmpty {
                    gen.responseModel = str
                }
            default:
                guard skipField(wireType: wireType, pos: &pos, buffer: buffer) else { return }
            }
        }
    }

    /// Decodes WorkspaceMetadata submessage from trajectory_metadata_blob.
    static func parseTrajectoryMetadata(_ buffer: UnsafeRawBufferPointer) -> ParsedTrajectoryMetadata {
        var pos = 0
        var traj = ParsedTrajectoryMetadata()
        while pos < buffer.count {
            guard let tag = readVarint(&pos, buffer: buffer) else { break }
            let fieldNum = Int(tag >> 3)
            let wireType = Int(tag & 0x7)
            switch (fieldNum, wireType) {
            case (1, 2): // WorkspaceMetadata submessage
                if let sub = readSubmessage(pos: &pos, buffer: buffer) {
                    parseWorkspaceMetadata(sub, into: &traj)
                }
            case (2, 2): // CreatedAt timestamp
                if let sub = readSubmessage(pos: &pos, buffer: buffer) {
                    traj.createdAt = parseTimestamp(sub)
                }
            case (5, 2): // parent_conversation_id
                if let str = readString(pos: &pos, buffer: buffer) {
                    traj.parentConversationID = str
                }
            case (6, 2): // root_conversation_id
                if let str = readString(pos: &pos, buffer: buffer) {
                    traj.rootConversationID = str
                }
            case (7, 2): // direct workspace URI fallback
                if let str = readString(pos: &pos, buffer: buffer), traj.workspaceFolder.isEmpty {
                    traj.workspaceFolder = decodeWorkspaceURI(str)
                }
            case (10, 0), (17, 0): // nesting_depth
                if let v = readVarint(&pos, buffer: buffer) {
                    traj.nestingDepth = Int(v)
                }
            default:
                guard skipField(wireType: wireType, pos: &pos, buffer: buffer) else { return traj }
            }
        }
        return traj
    }

    private static func parseWorkspaceMetadata(_ buffer: UnsafeRawBufferPointer, into traj: inout ParsedTrajectoryMetadata) {
        var pos = 0
        while pos < buffer.count {
            guard let tag = readVarint(&pos, buffer: buffer) else { break }
            let fieldNum = Int(tag >> 3)
            let wireType = Int(tag & 0x7)
            switch (fieldNum, wireType) {
            case (1, 2): // workspace_folder_absolute_uri
                if let str = readString(pos: &pos, buffer: buffer) {
                    traj.workspaceFolder = decodeWorkspaceURI(str)
                }
            case (2, 2): // git_root_absolute_uri
                if let str = readString(pos: &pos, buffer: buffer) {
                    traj.gitRoot = decodeWorkspaceURI(str)
                }
            case (3, 2), (5, 2): // branch_name
                if let str = readString(pos: &pos, buffer: buffer) {
                    traj.branchName = str
                }
            default:
                guard skipField(wireType: wireType, pos: &pos, buffer: buffer) else { return }
            }
        }
    }

    /// Percent-decodes a file:// URI into a clean POSIX path.
    static func decodeWorkspaceURI(_ uri: String) -> String {
        guard uri.hasPrefix("file://") else { return uri }
        let raw = String(uri.dropFirst(7))
        return raw.removingPercentEncoding ?? raw
    }

    /// Maps Antigravity model enum to canonical family identifier fallback.
    static func fallbackModelName(from enumValue: Int) -> String {
        switch enumValue {
        case 1319, 344: return "gemini-3.8-flash"
        case 1018: return "gemini-3.1-pro"
        case 1007: return "gemini-3-flash"
        case 342: return "gpt-oss-120b-medium"
        case 1318, 319, 284: return "claude-opus-4-6"
        case 283: return "claude-sonnet-4-6"
        default: return ""
        }
    }

    // MARK: - Main Reader Pipeline

    /// Reads Antigravity steps, late gen_metadata attribution, and sibling conversation summaries.
    /// Emits structured AgentLogEntry updates to consume closure.
    static func read(path: String, cursor: AgentLogCursor, now: Date, since horizon: Date,
                     shouldContinue: () -> Bool = { true },
                     consume: ([AgentLogEntry]) -> Void) {
        guard shouldContinue() else { return }
        var info = stat()
        guard stat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return }
        let identity = UInt64(info.st_ino)

        let sessionID = ((path as NSString).lastPathComponent as NSString).deletingPathExtension
        if cursor.antigravity.sessionID.isEmpty {
            cursor.antigravity.sessionID = sessionID
        }

        // Check if database was replaced or recreated
        if identity != cursor.identity {
            let replaced = cursor.identity != 0
            cursor.identity = identity
            if replaced {
                cursor.antigravity = AgentAntigravityProgress()
                cursor.antigravity.sessionID = sessionID
                cursor.state = AgentLogState()
                consume([.reset(now)])
            }
        }
        cursor.modified = modified(path) ?? date(info.st_mtimespec)

        var db: OpaquePointer?
        defer { sqlite3_close(db) }
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nil) == SQLITE_OK else {
            return
        }
        sqlite3_busy_timeout(db, busyTimeoutMs)

        // Rewind / revert detection: if highest step index in table is less than cursor's lastStepIndex
        if cursor.antigravity.lastStepIndex >= 0 {
            var checkStmt: OpaquePointer?
            if sqlite3_prepare_v2(db, "SELECT max(idx) FROM steps", -1, &checkStmt, nil) == SQLITE_OK {
                defer { sqlite3_finalize(checkStmt) }
                let stepRc = sqlite3_step(checkStmt)
                if stepRc == SQLITE_ROW {
                    let colType = sqlite3_column_type(checkStmt, 0)
                    let maxIdx = sqlite3_column_int64(checkStmt, 0)
                    if colType == SQLITE_NULL || maxIdx < cursor.antigravity.lastStepIndex {
                        cursor.antigravity.lastStepIndex = -1
                        cursor.antigravity.lastGenIndex = -1
                        cursor.antigravity.openSteps.removeAll()
                        cursor.state = AgentLogState()
                        consume([.reset(now)])
                    }
                }
            }
        }

        // 1. Scan trajectory_metadata_blob if workspace/subagent metadata is missing
        if cursor.antigravity.workspaceFolder.isEmpty || cursor.antigravity.rootID.isEmpty {
            readTrajectoryMetadata(db, cursor: cursor, sessionID: sessionID)
        }

        // 2. Scan sibling conversation_summaries.db for authoritative status & subagent lineage
        let summaryModified = summaryModified(for: path) ?? .distantPast
        cursor.antigravity.summaryModified = summaryModified
        let summaryInfo = readConversationSummary(cursor: cursor, sessionID: sessionID, now: now)

        var reportedUsage = Set<Int64>()

        // 3. Scan steps
        readSteps(db, cursor: cursor, sessionID: sessionID, now: now, since: horizon,
                  summaryInfo: summaryInfo, reportedUsage: &reportedUsage,
                  shouldContinue: shouldContinue, consume: consume)

        // 4. Scan gen_metadata for late canonical model attribution
        readGenMetadata(db, cursor: cursor, sessionID: sessionID, now: now,
                        reportedUsage: reportedUsage, shouldContinue: shouldContinue, consume: consume)
    }

    /// Compatibility interface matching standard readAppended pattern.
    static func readAppended(_ cursor: AgentLogCursor, since horizon: Date = .distantPast,
                             shouldContinue: () -> Bool = { true },
                             line: (Data) -> Void) {
        read(path: cursor.path, cursor: cursor, now: Date(), since: horizon, shouldContinue: shouldContinue) { entries in
            for entry in entries {
                switch entry {
                case .reset:
                    line(Data(#"{"type":"reset"}"#.utf8))
                default:
                    break
                }
            }
        }
    }

    // MARK: - Internal Query Helpers

    private static func readTrajectoryMetadata(_ db: OpaquePointer?, cursor: AgentLogCursor, sessionID: String) {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT data FROM trajectory_metadata_blob LIMIT 1", -1, &stmt, nil) == SQLITE_OK else {
            return
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW,
              let blobPtr = sqlite3_column_blob(stmt, 0) else { return }
        let blobBytes = Int(sqlite3_column_bytes(stmt, 0))
        let buffer = UnsafeRawBufferPointer(start: blobPtr, count: blobBytes)
        let traj = parseTrajectoryMetadata(buffer)

        if !traj.workspaceFolder.isEmpty {
            cursor.antigravity.workspaceFolder = traj.workspaceFolder
        }
        if !traj.branchName.isEmpty {
            cursor.antigravity.branchName = traj.branchName
        }
        if !traj.rootConversationID.isEmpty {
            cursor.antigravity.rootID = traj.rootConversationID
        }

        // Subagent invariant check:
        // parent_conversation_id != "" || (root_conversation_id != "" && root_conversation_id != sessionID)
        // Root sessions have root_conversation_id == sessionID, do NOT treat root sessions as subagents!
        let parentID = traj.parentConversationID
        let rootID = traj.rootConversationID
        let isSubagent = !parentID.isEmpty || (!rootID.isEmpty && rootID != sessionID)
        if isSubagent {
            cursor.antigravity.isSubagent = true
            cursor.antigravity.parentSession = !parentID.isEmpty ? parentID : rootID
            let convDir = (cursor.path as NSString).deletingLastPathComponent
            cursor.antigravity.parentPath = (convDir as NSString).appendingPathComponent("\(cursor.antigravity.parentSession).db")
        }
    }

    struct SummaryInfo {
        var isRunning: Bool = false
        var killed: Bool = false
    }

    private static func readConversationSummary(cursor: AgentLogCursor, sessionID: String, now: Date) -> SummaryInfo {
        let summaryDbPath = summaryDbPath(for: cursor.path)
        guard FileManager.default.fileExists(atPath: summaryDbPath) else { return SummaryInfo() }

        var sdb: OpaquePointer?
        defer { sqlite3_close(sdb) }
        guard sqlite3_open_v2(summaryDbPath, &sdb, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nil) == SQLITE_OK else {
            return SummaryInfo()
        }
        sqlite3_busy_timeout(sdb, busyTimeoutMs)

        // PRIVACY INVARIANT: NEVER select title, preview, or raw_summary
        let query = """
        SELECT status, not_fully_idle, killed, parent_conversation_id, nesting_depth, workspace_uris
        FROM conversation_summaries WHERE conversation_id = ?1 LIMIT 1
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(sdb, query, -1, &stmt, nil) == SQLITE_OK else { return SummaryInfo() }
        defer { sqlite3_finalize(stmt) }

        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(stmt, 1, sessionID, -1, transient)

        guard sqlite3_step(stmt) == SQLITE_ROW else { return SummaryInfo() }
        let status = sqlite3_column_text(stmt, 0).map { String(cString: $0) } ?? ""
        let notFullyIdle = sqlite3_column_int64(stmt, 1) != 0
        let killed = sqlite3_column_int64(stmt, 2) != 0
        let parentID = sqlite3_column_text(stmt, 3).map { String(cString: $0) } ?? ""
        let workspaceUris = sqlite3_column_text(stmt, 5).map { String(cString: $0) } ?? ""

        if cursor.antigravity.workspaceFolder.isEmpty && !workspaceUris.isEmpty {
            // workspace_uris is JSON array of strings e.g. ["file:///Users/..."]
            if let data = workspaceUris.data(using: .utf8),
               let array = (try? JSONSerialization.jsonObject(with: data)) as? [String],
               let first = array.first {
                cursor.antigravity.workspaceFolder = decodeWorkspaceURI(first)
            }
        }

        // Bounded parent traversal up to maxParentHops (8) to locate the top-level parent session
        if !parentID.isEmpty || cursor.antigravity.isSubagent {
            cursor.antigravity.isSubagent = true
            var currentParent = !parentID.isEmpty ? parentID : cursor.antigravity.parentSession
            var visited = Set<String>([sessionID])
            var hops = 0

            while hops < maxParentHops && !currentParent.isEmpty && !visited.contains(currentParent) {
                visited.insert(currentParent)
                hops += 1

                let parentQuery = "SELECT parent_conversation_id FROM conversation_summaries WHERE conversation_id = ?1 LIMIT 1"
                var pStmt: OpaquePointer?
                if sqlite3_prepare_v2(sdb, parentQuery, -1, &pStmt, nil) == SQLITE_OK {
                    defer { sqlite3_finalize(pStmt) }
                    sqlite3_bind_text(pStmt, 1, currentParent, -1, transient)
                    if sqlite3_step(pStmt) == SQLITE_ROW {
                        if let nextParent = sqlite3_column_text(pStmt, 0).map({ String(cString: $0) }), !nextParent.isEmpty {
                            currentParent = nextParent
                            continue
                        }
                    }
                }
                break
            }

            if !currentParent.isEmpty {
                cursor.antigravity.parentSession = currentParent
                let convDir = (cursor.path as NSString).deletingLastPathComponent
                cursor.antigravity.parentPath = (convDir as NSString).appendingPathComponent("\(currentParent).db")
            }
        }

        let isRunning = (status == "CASCADE_RUN_STATUS_RUNNING" || notFullyIdle) && !killed
        return SummaryInfo(isRunning: isRunning, killed: killed)
    }

    private static func emitUsage(
        usage: ParsedModelUsage,
        meta: ParsedStepMetadata,
        stepDate: Date,
        idx: Int64,
        sessionID: String,
        projectName: String,
        overrideModel: String = "",
        entries: inout [AgentLogEntry]
    ) {
        let reasoning = usage.thinkingTokens
        let unthoughtOutput = usage.responseOutputTokens > 0
            ? usage.responseOutputTokens
            : max(0, usage.outputTokens - usage.thinkingTokens)
        let tokens = AgentTokens(
            input: usage.inputTokens,
            cacheWrite: 0,
            cacheRead: usage.cacheReadTokens,
            output: unthoughtOutput,
            reasoning: reasoning
        )

        let fallback = fallbackModelName(from: usage.modelEnum != 0 ? usage.modelEnum : meta.generatorModelEnum)
        let modelName = !overrideModel.isEmpty ? overrideModel : fallback
        let modelCost = meta.modelCost ?? usage.modelCost

        var billableTokens = tokens
        billableTokens.output = unthoughtOutput + reasoning
        let billable = AgentBillable(tokens: billableTokens)

        if tokens.total > 0 || modelCost != nil {
            let key = "\(sessionID)#\(idx)"
            let priced = modelCost != nil ? (cost: modelCost, savings: 0.0) : AgentPricing.cost(billable, model: modelName)
            let record = AgentUsageRecord(
                provider: .antigravity,
                date: stepDate,
                model: modelName,
                project: projectName,
                session: sessionID,
                requests: 1,
                tokens: tokens,
                cost: priced.cost,
                savings: priced.savings,
                reportedCost: modelCost != nil
            )
            entries.append(.usage(key: key, record: record, billable: billable))
        }
    }

    private struct StepRow {
        let idx: Int64
        let stepType: Int
        let status: Int
        let hasSubtrajectory: Bool
        let metadata: Data?
    }

    private static func readSteps(_ db: OpaquePointer?, cursor: AgentLogCursor, sessionID: String, now: Date,
                                  since horizon: Date, summaryInfo: SummaryInfo,
                                  reportedUsage: inout Set<Int64>,
                                  shouldContinue: () -> Bool,
                                  consume: ([AgentLogEntry]) -> Void) {
        var entries: [AgentLogEntry] = []
        let projectName = !cursor.antigravity.workspaceFolder.isEmpty
            ? (cursor.antigravity.workspaceFolder as NSString).lastPathComponent
            : "Antigravity"

        // 1. Re-query in-progress steps in openSteps to capture in-place updates
        if !cursor.antigravity.openSteps.isEmpty {
            let openKeys = Array(cursor.antigravity.openSteps.keys).sorted()
            let placeholders = openKeys.map { _ in "?" }.joined(separator: ",")
            let openQuery = """
            SELECT idx, step_type, status, has_subtrajectory, metadata
            FROM steps WHERE idx IN (\(placeholders)) ORDER BY idx
            """
            var openStmt: OpaquePointer?
            if sqlite3_prepare_v2(db, openQuery, -1, &openStmt, nil) == SQLITE_OK {
                defer { sqlite3_finalize(openStmt) }
                for (i, key) in openKeys.enumerated() {
                    sqlite3_bind_int64(openStmt, Int32(i + 1), key)
                }

                while shouldContinue() && sqlite3_step(openStmt) == SQLITE_ROW {
                    let idx = sqlite3_column_int64(openStmt, 0)
                    guard let openInfo = cursor.antigravity.openSteps[idx] else { continue }
                    let stepType = Int(sqlite3_column_int64(openStmt, 1))
                    let status = Int(sqlite3_column_int64(openStmt, 2))

                    var meta = ParsedStepMetadata()
                    var digest: UInt64 = 0
                    if let blobPtr = sqlite3_column_blob(openStmt, 4) {
                        let blobBytes = Int(sqlite3_column_bytes(openStmt, 4))
                        let buffer = UnsafeRawBufferPointer(start: blobPtr, count: blobBytes)
                        digest = fnv1a64(buffer)
                        meta = parseStepMetadata(buffer)
                    }

                    let stepDate = meta.createdAt ?? openInfo.time
                    let statusChanged = status != openInfo.status
                    let digestChanged = digest != openInfo.digest

                    if statusChanged || digestChanged {
                        if let usage = meta.usage, (digestChanged || openInfo.digest == 0) {
                            emitUsage(usage: usage, meta: meta, stepDate: stepDate, idx: idx, sessionID: sessionID,
                                      projectName: projectName, entries: &entries)
                            reportedUsage.insert(idx)
                        }

                        let isTerminal = status == 3 || status == 6 || status == 7 || status == 12
                        if isTerminal {
                            cursor.antigravity.openSteps[idx] = nil
                            if status == 6 || status == 7 || status == 12 {
                                let finishedDate = meta.finishedAt ?? meta.lastCompletedChunkAt ?? stepDate
                                entries.append(.turnEnded(finishedDate, completed: false, duration: nil))
                                cursor.state.turnOpen = false
                            } else if stepType == 15 {
                                if !summaryInfo.isRunning {
                                    let finishedDate = meta.finishedAt ?? meta.lastCompletedChunkAt ?? stepDate
                                    entries.append(.turnEnded(finishedDate, completed: true, duration: nil))
                                    cursor.state.turnOpen = false
                                }
                            }
                        } else {
                            cursor.antigravity.openSteps[idx] = (stepType, status, digest, stepDate)
                        }
                    }
                }
            }
        }

        // 2. Query newly appended steps
        // PRIVACY INVARIANT: NEVER select step_payload, error_details, permissions, task_details, render_info
        let query = """
        SELECT idx, step_type, status, has_subtrajectory, metadata
        FROM steps WHERE idx > ?1 ORDER BY idx
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK else {
            if !entries.isEmpty { consume(entries) }
            return
        }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_int64(stmt, 1, cursor.antigravity.lastStepIndex)

        var newRows: [StepRow] = []
        while shouldContinue() && sqlite3_step(stmt) == SQLITE_ROW {
            let idx = sqlite3_column_int64(stmt, 0)
            let stepType = Int(sqlite3_column_int64(stmt, 1))
            let status = Int(sqlite3_column_int64(stmt, 2))
            let hasSub = sqlite3_column_int64(stmt, 3) != 0
            var metadataData: Data? = nil
            if let blobPtr = sqlite3_column_blob(stmt, 4) {
                let blobBytes = Int(sqlite3_column_bytes(stmt, 4))
                metadataData = Data(bytes: blobPtr, count: blobBytes)
            }
            newRows.append(StepRow(idx: idx, stepType: stepType, status: status, hasSubtrajectory: hasSub, metadata: metadataData))
        }

        for (i, row) in newRows.enumerated() {
            let idx = row.idx
            let stepType = row.stepType
            let status = row.status

            var meta = ParsedStepMetadata()
            var digest: UInt64 = 0
            if let data = row.metadata {
                data.withUnsafeBytes { buffer in
                    digest = fnv1a64(buffer)
                    meta = parseStepMetadata(buffer)
                }
            }

            let stepDate = meta.createdAt ?? now
            cursor.antigravity.lastStepIndex = max(cursor.antigravity.lastStepIndex, idx)

            // Horizon filtering: ignore steps prior to 13-week cutoff
            guard stepDate >= horizon else { continue }

            if stepType == 14 {
                // User prompt starts a live turn
                entries.append(.turnBegan(stepDate))
                cursor.state.turnOpen = true
            }

            if let usage = meta.usage {
                emitUsage(usage: usage, meta: meta, stepDate: stepDate, idx: idx, sessionID: sessionID,
                          projectName: projectName, entries: &entries)
                reportedUsage.insert(idx)
            }

            let isTerminal = status == 3 || status == 6 || status == 7 || status == 12
            if isTerminal {
                cursor.antigravity.openSteps[idx] = nil
                if status == 6 || status == 7 || status == 12 {
                    let finishedDate = meta.finishedAt ?? meta.lastCompletedChunkAt ?? stepDate
                    entries.append(.turnEnded(finishedDate, completed: false, duration: nil))
                    cursor.state.turnOpen = false
                } else if stepType == 15 {
                    let hasFollowingStepsInBatch = newRows[(i + 1)...].contains { $0.stepType != 14 }
                    if !hasFollowingStepsInBatch && !summaryInfo.isRunning {
                        let finishedDate = meta.finishedAt ?? meta.lastCompletedChunkAt ?? stepDate
                        entries.append(.turnEnded(finishedDate, completed: true, duration: nil))
                        cursor.state.turnOpen = false
                    }
                }
            } else {
                cursor.antigravity.openSteps[idx] = (stepType, status, digest, stepDate)
                if !cursor.state.turnOpen {
                    entries.append(.turnBegan(stepDate))
                    cursor.state.turnOpen = true
                }
            }
        }

        // Settle or abort lingering open turn if conversation is killed or inactive/timed out
        if cursor.state.turnOpen {
            if summaryInfo.killed {
                entries.append(.turnEnded(now, completed: false, duration: nil))
                cursor.state.turnOpen = false
                cursor.antigravity.openSteps.removeAll()
            } else if cursor.antigravity.openSteps.isEmpty && (!summaryInfo.isRunning || now.timeIntervalSince(cursor.modified) >= NotchAgentSupport.idleTurn) {
                entries.append(.turnSettled(now))
                cursor.state.turnOpen = false
            }
        }

        if !entries.isEmpty {
            consume(entries)
        }
    }

    private static func readGenMetadata(_ db: OpaquePointer?, cursor: AgentLogCursor, sessionID: String, now: Date,
                                        reportedUsage: Set<Int64>,
                                        shouldContinue: () -> Bool,
                                        consume: ([AgentLogEntry]) -> Void) {
        let query = """
        SELECT idx, data, size FROM gen_metadata WHERE idx > ?1 ORDER BY idx
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_int64(stmt, 1, cursor.antigravity.lastGenIndex)

        let projectName = !cursor.antigravity.workspaceFolder.isEmpty
            ? (cursor.antigravity.workspaceFolder as NSString).lastPathComponent
            : "Antigravity"

        var entries: [AgentLogEntry] = []
        while shouldContinue() && sqlite3_step(stmt) == SQLITE_ROW {
            let idx = sqlite3_column_int64(stmt, 0)
            cursor.antigravity.lastGenIndex = max(cursor.antigravity.lastGenIndex, idx)

            guard let blobPtr = sqlite3_column_blob(stmt, 1) else { continue }
            let blobBytes = Int(sqlite3_column_bytes(stmt, 1))
            let buffer = UnsafeRawBufferPointer(start: blobPtr, count: blobBytes)
            let gen = parseGenMetadata(buffer)

            for stepIdx in gen.stepIndices {
                let key = "\(sessionID)#\(stepIdx)"
                // If the step did not already report usage in steps.metadata, emit fallback usage
                if !reportedUsage.contains(stepIdx), let fallback = gen.usageFallback {
                    var meta = ParsedStepMetadata()
                    meta.generatorModelEnum = gen.modelEnum
                    emitUsage(usage: fallback, meta: meta, stepDate: now, idx: stepIdx, sessionID: sessionID,
                              projectName: projectName, overrideModel: gen.responseModel, entries: &entries)
                }
                if !gen.responseModel.isEmpty {
                    entries.append(.usageModel(key: key, model: gen.responseModel))
                }
            }
        }

        if !entries.isEmpty {
            consume(entries)
        }
    }
}
