//
//  OciRequestSignerTests.swift
//  OciRequestSignerTests
//
//  Created by Scott Harwell on 9/22/19.
//  Copyright © 2019 Scott Harwell. All rights reserved.
//

import XCTest
import os
@testable import OciRequestSigner

class OciRequestSignerTests: XCTestCase {
    
    var bundle: Bundle!
    var validGetSig: String!
    var validPostSig: String!
    var validEmptyPostSig: String!
    
    let tenancyOCID = "ocid1.tenancy.oc1..aaaaaaaaba3pv6wkcr4jqae5f15p2b2m2yt2j6rx32uzr4h25vqstifsfdsq"
    let userOCID = "ocid1.user.oc1..aaaaaaaat5nvwcna5j6aqzjcaty5eqbb6qt2jvpkanghtgdaqedqw3rynjq"
    let certFingerprint = "73:61:a2:21:67:e0:df:be:7e:4b:93:1e:15:98:a5:b7"

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
        bundle = Bundle(for: type(of: self))
        
        let signer = URLRequestSigner.shared
        signer.tenancyId = self.tenancyOCID
        signer.userId = self.userOCID
        signer.thumbprint = self.certFingerprint
        
        do {
            try signer.setKey(fileName: "pk", fileExtention: "pem", bundle: bundle)
            
            guard let getStrPath = bundle.path(forResource: "valid_get", ofType: "txt") else {
                XCTFail()
                return
            }
            let getStr = try String(contentsOfFile: getStrPath).trimmingCharacters(in: .whitespacesAndNewlines)
            validGetSig = getStr
            
            guard let postStrPath = bundle.path(forResource: "valid_post", ofType: "txt") else {
                XCTFail()
                return
            }
            let postStr = try String(contentsOfFile: postStrPath).trimmingCharacters(in: .whitespacesAndNewlines)
            validPostSig = postStr
            
            guard let emptyPostStrPath = bundle.path(forResource: "valid_empty_post", ofType: "txt") else {
                XCTFail()
                return
            }
            let emptyPostStr = try String(contentsOfFile: emptyPostStrPath).trimmingCharacters(in: .whitespacesAndNewlines)
            validEmptyPostSig = emptyPostStr
        } catch {
            os_log(.error, "%@", error.localizedDescription)
            XCTFail()
        }
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testHardCodedGet() {
        let url = URL(string: "https://iaas.us-phoenix-1.oraclecloud.com/20160918/instances?availabilityDomain=Pjwf%3A%20PHX-AD-1&compartmentId=ocid1.compartment.oc1..aaaaaaaam3we6vgnherjq5q2idnccdflvjsnog7mlr6rtdb25gilchfeyjxa&displayName=TeamXInstances&volumeId=ocid1.volume.oc1.phx.abyhqljrgvttnlx73nmrwfaux7kcvzfs3s66izvxf2h4lgvyndsdsnoiwr5q")
        var request = URLRequest(url: url!)
        request.addValue("Thu, 05 Jan 2014 21:31:40 GMT", forHTTPHeaderField: "date")
        request.addValue(url!.host!, forHTTPHeaderField: "host")
        
        do {
            let getRequest = try URLRequestSigner.shared.sign(request)
            guard let header = getRequest.value(forHTTPHeaderField: "Authorization") else {
                XCTFail()
                return
            }
            
            XCTAssertEqual(header, validGetSig, "GET signature is wrong")
        } catch {
            os_log(.error, "%@", error.localizedDescription)
            XCTFail()
        }
    }
    
    func testDynamicGet() {
        do {
            let url = URL(string: "https://iaas.us-phoenix-1.oraclecloud.com/20160918/instances?availabilityDomain=Pjwf%3A%20PHX-AD-1&compartmentId=ocid1.compartment.oc1..aaaaaaaam3we6vgnherjq5q2idnccdflvjsnog7mlr6rtdb25gilchfeyjxa&displayName=TeamXInstances&volumeId=ocid1.volume.oc1.phx.abyhqljrgvttnlx73nmrwfaux7kcvzfs3s66izvxf2h4lgvyndsdsnoiwr5q")
            var request = try URLRequestSigner.shared.getUrlRequest(url: url!)
            request.setValue("Thu, 05 Jan 2014 21:31:40 GMT", forHTTPHeaderField: "date")
            
            request = try URLRequestSigner.shared.sign(request)
            
            guard let header = request.value(forHTTPHeaderField: "Authorization") else {
                XCTFail()
                return
            }
            
            XCTAssertEqual(header, validGetSig, "GET signature is wrong")
        } catch {
            os_log(.error, "%@", error.localizedDescription)
            XCTFail()
        }
    }
    
    func testHardCodedPost() {
        let postURL = URL(string: "https://iaas.us-phoenix-1.oraclecloud.com/20160918/volumeAttachments")
        var postRequest = URLRequest(url: postURL!)
        postRequest.httpMethod = "POST"
        postRequest.setValue("Thu, 05 Jan 2014 21:31:40 GMT", forHTTPHeaderField: "date")
        postRequest.setValue(postURL!.host!, forHTTPHeaderField: "host")
        postRequest.setValue("application/json", forHTTPHeaderField: "content-type")
        
        do {
            let path = bundle.path(forResource: "request", ofType: "txt")
            let data = try String(contentsOfFile: path!).trimmingCharacters(in: .newlines).data(using: .utf8)
            postRequest.httpBody = data
            postRequest.setValue(String(data!.count), forHTTPHeaderField: "content-length")
            postRequest = URLRequestSigner.shared.addXContentHeader(postRequest)
            
            let postRequest = try URLRequestSigner.shared.sign(postRequest)
            
            guard let header = postRequest.value(forHTTPHeaderField: "Authorization") else {
                XCTFail()
                return
            }
            
            XCTAssertEqual(header, validPostSig, "POST signature is wrong")
        } catch {
            os_log(.error, "%@", error.localizedDescription)
            XCTFail()
        }
    }

    func testDynamicPost() {
        do {
            let url = URL(string: "https://iaas.us-phoenix-1.oraclecloud.com/20160918/volumeAttachments")
            var postRequest = try URLRequestSigner.shared.getUrlRequest(url: url!)
            postRequest.httpMethod = "POST"
            postRequest.setValue("Thu, 05 Jan 2014 21:31:40 GMT", forHTTPHeaderField: "date")
            
            bundle = Bundle(for: type(of: self))
            let path = bundle.path(forResource: "request", ofType: "txt")
            let data = try String(contentsOfFile: path!).trimmingCharacters(in: .newlines).data(using: .utf8)
            postRequest.httpBody = data
            
            postRequest = try URLRequestSigner.shared.sign(postRequest)
            
            guard let header = postRequest.value(forHTTPHeaderField: "Authorization") else {
                XCTFail()
                return
            }
            
            XCTAssertEqual(header, validPostSig, "POST signature is wrong")
        } catch {
            print(error.localizedDescription)
            os_log(.error, "%@", error.localizedDescription)
            XCTFail()
        }
    }
    
    func testEmptyPost() {
        do {
            let url = URL(string: "https://iaas.us-phoenix-1.oraclecloud.com/20160918/volumeAttachments")
            var postRequest = try URLRequestSigner.shared.getUrlRequest(url: url!)
            postRequest.httpMethod = "POST"
            postRequest.setValue("Thu, 05 Jan 2014 21:31:40 GMT", forHTTPHeaderField: "date")            
            postRequest = try URLRequestSigner.shared.sign(postRequest)
            
            guard let header = postRequest.value(forHTTPHeaderField: "Authorization") else {
                XCTFail()
                return
            }
            
            XCTAssertEqual(header, validEmptyPostSig, "POST signature is wrong")
        } catch {
            print(error.localizedDescription)
            os_log(.error, "%@", error.localizedDescription)
            XCTFail()
        }
    }
}
