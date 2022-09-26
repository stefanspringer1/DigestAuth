//
//  File.swift
//
//
//  Created by Lukas Salchow on 19.09.22.
//

import Foundation
import Vapor


fileprivate let privateKey : String? = "privateKey"
fileprivate let digestKeys = ["username", "realm", "uri", "nonce", "nc", "cnonce", "qop"]

func getUnixTimestamp() -> Double {
    return Date().timeIntervalSince1970
}

func MD5(string: String) -> String {
    let digest = Insecure.MD5.hash(data: string.data(using: .utf8) ?? Data())

    return digest.map {
        String(format: "%02hhx", $0)
    }.joined()
}

extension StringProtocol {

    func after(substring: String) -> String {
        if let range = self.range(of: substring) {
            return String(self[range.upperBound..<self.endIndex])
        }
        else {
            return String(self)
        }
    }
    
    func until(substring: String) -> String {
        if let range = self.range(of: substring) {
            return String(self[self.startIndex..<range.lowerBound])
        }
        else {
            return String(self)
        }
    }
    
    func triming() -> String {
        return self.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    
}

func generateClientNonce() -> String {
    return MD5(string: String(getUnixTimestamp()))
}

func generateNonce(timeStamp: String, privateKey: String) -> String {
    let hash = MD5(string: "\(timeStamp):\(privateKey)")
    return "\(timeStamp):\(hash)"
}

func validateNonce(nonce: String, privateKey: String, ttl: Double = 5) -> Bool {
    // nonce has the from time-stamp : H(time-stamp ":" private-key)
    // it is valid if the time-stamp is newer than ttl and the hash value agrees with a recalulated hash

    let nonceSplit = nonce.split(separator: ":")
    guard nonceSplit.count == 2, let timeStamp = Double(nonceSplit[0]) else {
        return false
    }
    return getUnixTimestamp()-timeStamp < ttl && nonce == generateNonce(timeStamp: String(timeStamp), privateKey: privateKey)
}


func getDigestDict(headers: HTTPHeaders, key: String) -> [String:String]? {
//    print(headers,key)
    return (headers.first(name: key)?
        .after(substring: "Digest ").split(separator: ",")
        .map{x in x.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)}
        .map{x in (x[0].triming(), x[1].after(substring: "\"").until(substring: "\""))}
        .reduce(into: [:]){$0[$1.0] = $1.1})
}

func queryRequestBuilder(app: Application, digestDict:[String:String], uri: URI, user: String, pw: String) -> ((inout ClientRequest) -> ()) {
    return { request in
        let clientNonce = generateClientNonce()
        let nonce = digestDict["nonce"] ?? ""
        let nc = "00000001"
        let method = "GET"
        var uriString = uri.path
        if uri.query != nil {
            uriString += "?" + uri.query!
        }
        
        let digestResponse = digest(
            username: user,
            authenticationRealm: digestDict["realm"]!,
            password: pw,
            method: method, // GET or POST
            digestURI: uriString,
            serverNonce: nonce,
            nc: nc,
            clientNonce: clientNonce,
            qop: digestDict["qop"] ?? ""
        )
        
        request.headers.add(name: "Accept", value: "*/*")
        
        let digestString = "Digest "
                            + "username=\"\(user)\", "
                            + "realm=\"\(digestDict["realm"] ?? "")\", "
                            + "nonce=\"\(digestDict["nonce"] ?? "")\", "
                            + "uri=\"\(uriString)\", "
                            + "cnonce=\"\(clientNonce)\", "
                            + "nc=\"\(nc)\", "
                            + "qop=\"\(digestDict["qop"] ?? "")\", "
                            + "response=\"\(digestResponse)\", "
                            + "opaque=\"\(digestDict["opaque"] ?? "")\""

        request.headers.add(name: "Authorization", value: digestString)
    }
}


func digest(username: String,
            authenticationRealm: String,
            password: String,
            method: String,
            digestURI: String,
            serverNonce: String,
            nc: String,
            clientNonce: String,
            qop: String) -> String {
    let a1 = "\(username):\(authenticationRealm):\(password)"
    let HA1 = MD5(string: a1)
    let a2 = "\(method):\(digestURI)"
    let HA2 = MD5(string: a2)
    let a3 = "\(HA1):\(serverNonce):\(nc):\(clientNonce):\(qop):\(HA2)"
    let HA3 = MD5(string: a3)
//        print("   A1 \(a1) HA1 \(HA1)")
//        print("   A2 \(a2) HA2 \(HA2)")
//        print("   A3 \(a3) HA3 \(HA3)")
    return HA3
}


func makeDigestQuery(app: Application, request: Request, uri: URI, user: String, pw: String) async -> String {
//    app.logger.info("making first request to obtain nonce, qop, opaque and algorithm ")
    guard let queryResult = try? await request.client.get(uri) else {
        return "could not run query"
    }

    let digestDict = getDigestDict(headers: queryResult.headers, key: "WWW-Authenticate")
    guard let digestDict = digestDict else {
        return "error: no www-auth header"
    }

    guard digestDict["qop"] == "auth" else {
        return "not implmented for qos=\(String(describing: digestDict["qop"]))"
    }
     
//    app.logger.info("making second request with digest authetification")
    let requestBuilder = queryRequestBuilder(app: app, digestDict:digestDict, uri: uri, user: user, pw: pw)
    guard let queryResult = try? await request.client.get(uri, beforeSend: requestBuilder) else {
        return "could not run query"
    }
//    app.logger.info("queryResult: \(queryResult)")
    guard let theContent = queryResult.body, let result = theContent.getString(at: 0, length: theContent.readableBytes, encoding: .utf8) else {
        return "could not get content of query result"
    }

    return result
}


func digestResponder(req: Request, userPassword: (String?) -> String?, responder: (Request) async throws -> Response) async throws -> Response {
    let realm = "localhost/testAuthAsServer"
    print("headers", req.headers)
    if req.headers.first(name: "Authorization") == nil {
        let nonce = generateNonce(timeStamp: String(getUnixTimestamp()), privateKey: privateKey!)
        var headers = HTTPHeaders()
        headers.add(name: "www-authenticate", value: "Digest realm=\"\(realm)\", nonce=\"\(nonce)\", qop=\"auth\", opaque=\"\", algorithm=MD5, stale=FALSE")
        return try await nonce.encodeResponse(status: HTTPResponseStatus.unauthorized, headers: headers, for: req)
    } else {
        let digestDict = getDigestDict(headers: req.headers, key: "Authorization")
        
        guard let digestDict = digestDict else {
            return try await ("error: no authorization header").encodeResponse(status: HTTPStatus.unauthorized, for: req)
        }
        
        guard digestKeys.allSatisfy({digestDict.keys.contains($0)}) else {
            return try await ("error: " + digestKeys.filter{!digestDict.keys.contains($0)}.joined(separator: ", ") + " not in authorization header").encodeResponse(status: HTTPStatus.unauthorized, for: req)
        }
        
        guard validateNonce(nonce: digestDict["nonce"]!, privateKey: privateKey!) else {
            let nonce = generateNonce(timeStamp: String(getUnixTimestamp()), privateKey: privateKey!)
            var headers = HTTPHeaders()
            headers.add(name: "www-authenticate", value: "Digest realm=\"\(realm)\", nonce=\"\(nonce)\", qop=\"auth\", opaque=\"\", algorithm=MD5, stale=TRUE")
        
            return try await ("error: \(digestDict["nonce"]!) is not in a valid nonce").encodeResponse(status: HTTPStatus.unauthorized, headers: headers, for: req)
        }
        
        guard let password = userPassword(digestDict["username"]) else {
            return try await ("error: \(digestDict["username"]!) is an invalid username").encodeResponse(status: HTTPStatus.unauthorized, for: req)
        }
        
        let digestResponse = digest(
            username: digestDict["username"]!,
            authenticationRealm: digestDict["realm"]!,
            password: password, //authDict[digestDict["username"]!]!,
            method: "GET",
            digestURI: digestDict["uri"]!,
            serverNonce: digestDict["nonce"]!,
            nc: digestDict["nc"]!,
            clientNonce: digestDict["cnonce"]!,
            qop: digestDict["qop"]!
        )
                   
        if digestDict["response"]! == digestResponse {
//            return try await "valid authentification".encodeResponse(for: req)
            return try await responder(req)
        }
        return try await "unauthorized".encodeResponse(status: HTTPStatus.unauthorized, for: req)
    }
}
