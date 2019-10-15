import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(OCI_Request_SignerTests.allTests),
    ]
}
#endif
