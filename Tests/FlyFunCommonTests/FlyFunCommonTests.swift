import Testing
@testable import FlyFunCommon

@Test func versionPresent() {
    #expect(!FlyFunCommon.version.isEmpty)
}
