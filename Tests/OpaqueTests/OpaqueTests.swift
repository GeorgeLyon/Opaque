import XCTest
@testable import Opaque

final class OpaqueTests: XCTestCase {
    func testExample() throws {
        print(try Salt.random())
        
        XCTAssertEqual(Opaque().text, "Hello, World!")
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
