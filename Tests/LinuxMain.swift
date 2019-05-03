import XCTest

import OpaqueTests

var tests = [XCTestCaseEntry]()
tests += OpaqueTests.allTests()
XCTMain(tests)
