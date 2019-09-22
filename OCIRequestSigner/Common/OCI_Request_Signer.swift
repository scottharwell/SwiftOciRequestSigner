//
//  OCI_Request_Signer.swift
//  OCI Request Signer
//
//  Created by Scott Harwell on 9/21/19.
//  Copyright © 2019 Scott Harwell. All rights reserved.
//

import Foundation
import CryptorRSA
import CryptoSwift

enum OCI_URLRequestSignerError: Error {
    case noKeyAtPath,
    paramsNotSet,
    httpBodyMissing,
    httpMethodMissing,
    httpUrlMissing,
    httpQueryMissing,
    signingHeaderMissing,
    signingError
}

class OCI_URLRequestSigner {
    
    // MARK: - Properties
    
    /**
     Singleton instance of this class.
    */
    static let shared = OCI_URLRequestSigner();
    
    /**
     The OCI signature version that this class implements.
     As of 9/4/2019, version 1 is the only version
     */
    private(set) var signatureVersion: Int8 = 1
    
    /**
     The tenancy ID that will be used to generate signing requests.
     */
    var tenancyId: String?
    
    /**
     The user ID that will be used to generate signing requests.
     */
    var userId: String?
    
    /**
     The certificate thumbprint of the user that will be used to generate signing requests.
     */
    var thumbprint: String?
    
    /**
     Local path to the private key used for signing requests.
     */
    private var keyPath: String?
    
    /**
     Instance of the private key that will be used to sign requests.
     */
    private var key: CryptorRSA.PrivateKey?
    
    // MARK: - Initializers
    
    private init() {
        
    }
    
    // MARK: - Methods
    
    /**
     Sets the signing key to a local file accessible to this application.
     
     - Parameter fileName: The name of the key file without the extension.
     - Parameter fileExtension: The extension of the key file.
     - Parameter bundle: The bundle that includes the key file. The main bundle is used by default.
     
     - Throws: OCI_URLRequestSignerError when key cannot be found. CryptorRSA error when unable to convert to key.
    */
    public func setKey(fileName: String, fileExtention: String, bundle: Bundle = Bundle.main) throws {
        guard let path = bundle.path(forResource: fileName, ofType: fileExtention) else {
            throw OCI_URLRequestSignerError.noKeyAtPath
        }
        
        do {
            let pemStr = try String.init(contentsOfFile: path)
            let k = try CryptorRSA.createPrivateKey(withPEM: pemStr)
            
            self.keyPath = path
            self.key = k
        } catch {
            throw error
        }
    }
    
    /**
     Sets the signing key to a local file accessible to this application.
     
     - Parameter key: The string value of the key to use to sign requests.
     
     - Throws: OCI_URLRequestSignerError when key cannot be found. CryptorRSA error when unable to convert to key.
     */
    public func setKey(key: String) throws {
        do {
            let k = try CryptorRSA.createPrivateKey(withPEM: key)
            
            self.keyPath = nil
            self.key = k
        } catch {
            throw error
        }
    }
    
    /**
     Adds the x-content-sha256 header based on the http request body.
     
     - Parameter request: The URL request to add the header to.
     
     - Throws: OCI_URLRequestSignerError when http body missing.
     */
    public func addXContentHeader(_ request: URLRequest) throws -> URLRequest {
        var newRequest = request
        guard let newHeader = request.httpBody?.sha256().base64EncodedString() else { throw OCI_URLRequestSignerError.httpBodyMissing }
        newRequest.addValue(newHeader, forHTTPHeaderField: "x-content-sha256")
        
        return newRequest
    }
    
    /**
     Performs the signing process on the URL request.
     
     - Parameter request: The URL request to add the Authorization header to.
     
     - Throws: OCI_URLRequestSignerError based on the error.
     */
    public func sign(_ request: URLRequest) throws -> URLRequest {
        var newRequest = request
        
        guard let tenancy = self.tenancyId, let user = self.userId, let thumb = self.thumbprint, let k = self.key else {
            throw OCI_URLRequestSignerError.paramsNotSet
        }
        
        var headersToSign = [
            "date",
            "(request-target)",
            "host"
        ]
        
        if request.value(forHTTPHeaderField: "x-date") != nil {
            headersToSign[0] = "x-date"
        }
        
        let addHeaders = {
            headersToSign.append("content-length")
            headersToSign.append("content-type")
            headersToSign.append("x-content-sha256")
        }
        
        switch request.httpMethod {
        case "POST":
            addHeaders()
            break
        case "PUT":
            addHeaders()
            break
        default:
            // Do nothing as we already have the headers to sign for other methods above
            break
        }
        
        let apiKeyId = String(format: "%@/%@/%@", tenancy, user, thumb)
        
        var signingStr = ""
        
        for header in headersToSign {
            switch header {
            case "(request-target)":
                guard let method = request.httpMethod?.lowercased() else { throw OCI_URLRequestSignerError.httpMethodMissing }
                guard let url = request.url else { throw OCI_URLRequestSignerError.httpUrlMissing }
                let urlPath = url.path
                
                var rtHeader = String(format: "%@ %@", method, urlPath)
                if let query = url.query {
                    rtHeader = String(format: "%@?%@", rtHeader, query)
                }
                
                signingStr = String(format: "%@%@: %@", signingStr, header, rtHeader)
                break
            default:
                guard let val = request.value(forHTTPHeaderField: header) else { throw OCI_URLRequestSignerError.signingHeaderMissing }
                signingStr = String(format: "%@%@: %@", signingStr, header, val)
                break
            }
            
            if header != headersToSign.last {
                signingStr = signingStr + "\n"
            }
        }
        
        let myPlaintext = try CryptorRSA.createPlaintext(with: signingStr, using: .utf8)
        let signedData = try myPlaintext.signed(with: k, algorithm: .sha256)
        guard let base64Sig = signedData?.base64String else { throw OCI_URLRequestSignerError.signingError }
        
        let authHeader = String(format: "Signature version=\"%d\",headers=\"%@\",keyId=\"%@\",algorithm=\"rsa-sha256\",signature=\"%@\"", self.signatureVersion, headersToSign.joined(separator: " "), apiKeyId, base64Sig)
        
        newRequest.addValue(authHeader, forHTTPHeaderField: "Authorization")
        
        return newRequest
    }
}
