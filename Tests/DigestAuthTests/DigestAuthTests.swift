import XCTest
@testable import DigestAuth

final class DigestAuthTests: XCTestCase {
    func testDigestAgainstExample() {
        let digest = digest(username: "Mufasa",
               authenticationRealm: "testrealm@host.com",
               password: "Circle Of Life",
               method: "GET",
               digestURI: "/dir/index.html",
               serverNonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093",
               nc: "00000001",
               clientNonce: "0a4f113b",
               qop: "auth"
        )
        XCTAssert(digest == "6629fae49393a05397450978507c4ef1")
    }
    
    func testNonceUnique() {
        for _ in 0...10_000 {
            let nonce1 = generateNonce(timeStamp: String(getUnixTimestamp()), privateKey: "test")
            let nonce2 = generateNonce(timeStamp: String(getUnixTimestamp()), privateKey: "test")
            XCTAssertNotEqual(nonce1, nonce2)
        }
    }
    
    func testNonceDependentOnPrivateKey() {
        let ts = String(getUnixTimestamp())
        let nonce1 = generateNonce(timeStamp: ts, privateKey: "test")
        let nonce2 = generateNonce(timeStamp: ts, privateKey: "test2")
        XCTAssertNotEqual(nonce1, nonce2)
    }
    
    func testValidateTime() {
        let key = "test"
        let nonce = generateNonce(timeStamp: String(getUnixTimestamp()), privateKey: key)
        let ttl = 0.01
        XCTAssert(validateNonce(nonce: nonce, privateKey: key, ttl: ttl))
        Thread.sleep(forTimeInterval: ttl)
        XCTAssertFalse(validateNonce(nonce: nonce, privateKey: key, ttl: ttl))

    }

    func testValidateKey() {
        let key = "test"
        let key2 = "test2"
        let nonce = generateNonce(timeStamp: String(getUnixTimestamp()), privateKey: key)
        let ttl = 0.01
        XCTAssertFalse(validateNonce(nonce: nonce, privateKey: key2, ttl: ttl))
    }
}
