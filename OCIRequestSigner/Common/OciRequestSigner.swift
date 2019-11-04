//
//  OciRequestSigner.swift
//  OCI URLRequest Signer
//
//  Created by Scott Harwell on 9/21/19.
//  Copyright © 2019 Scott Harwell. All rights reserved.
//

import Foundation
import os
import CryptorRSA
import CryptoSwift

public enum OciRequestSignerError: Error {
    case noKeyAtPath,
    paramsNotSet,
    httpBodyMissing,
    httpHostMissing,
    httpMethodMissing,
    httpUrlMissing,
    httpQueryMissing,
    signingHeaderMissing,
    signingError
}

public class OciRequestSigner {
    
    // MARK: - Properties
    
    /// Singleton instance of this class.
    public static let shared = OciRequestSigner();
    
    /// The OCI signature version that this class implements. As of 9/4/2019, version 1 is the only version.
    public var signatureVersion: ApiVersions = ApiVersions.one

    /// The tenancy ID that will be used to generate signing requests.
    public var tenancyId: String?

    /// The user ID that will be used to generate signing requests.
    public var userId: String?

    /// The certificate thumbprint of the user that will be used to generate signing requests.
    public var thumbprint: String?

    /// Local path to the private key used for signing requests.
    private var keyPath: String?

    /// Instance of the private key that will be used to sign requests.
    private var key: CryptorRSA.PrivateKey?
    
    // MARK: - Initializers
    
    private init() {
        
    }
    
    // MARK: - Private Key Methods
    
    /// Sets the signing key to a local file accessible to this application.
    /// - Parameter fileName: The name of the key file without the extension.
    /// - Parameter fileExtention: The extension of the key file.
    /// - Parameter bundle: The bundle that includes the key file. The main bundle is used by default.
    /// - Throws: OciRequestSignerError when key cannot be found. CryptorRSA error when unable to convert to key.
    public func setKey(fileName: String, fileExtention: String, bundle: Bundle = Bundle.main) throws {
        guard let path = bundle.path(forResource: fileName, ofType: fileExtention) else {
            throw OciRequestSignerError.noKeyAtPath
        }
        
        do {
            let pemStr = try String.init(contentsOfFile: path)
            let k = try CryptorRSA.createPrivateKey(withPEM: pemStr)
            
            self.keyPath = path
            self.key = k
        } catch {
            os_log(.error, "Error setting key: %@", error.localizedDescription)
            throw error
        }
    }
    
    /// Sets the signing key to a local file accessible to this application.
    /// - Parameter key: The string value of the key to use to sign requests.
    /// - Throws: OciRequestSignerError when key cannot be found. CryptorRSA error when unable to convert to key.
    public func setKey(key: String) throws {
        do {
            let k = try CryptorRSA.createPrivateKey(withPEM: key)
            
            self.keyPath = nil
            self.key = k
        } catch {
            os_log(.error, "Error setting key: %@", error.localizedDescription)
            throw error
        }
    }
    
    // MARK: - URLRequest Methods
    
    /// Creates a generic URL request with headers expected in OCI REST requests.
    /// - Parameter endPoint: The URL string to the OCI REST API endpoint.
    /// - Parameter timeoutInterval: The length of time the request should wait before timeout.  Default is 30 seconds (OCI Functions default).
    /// - Returns: A URLRequest object or nil.
    /// - Throws: OciRequestSignerError based on the error.
    public func getUrlRequest(endPoint: String, timeoutInterval: Double = 30) throws -> URLRequest? {
        guard let endPoint = endPoint
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)
            else {
                return nil
        }
        
        guard let url = URL(string: endPoint) else { throw OciRequestSignerError.httpUrlMissing }
        
        do {
            return try self.getUrlRequest(url: url)
        } catch {
            os_log(.error, "Error getting URL request: %@", error.localizedDescription)
            throw error
        }
    }
    
    /// Creates a generic URL request with headers expected in OCI REST requests.
    /// - Parameter url: The URL object to the OCI REST API endpoint.
    /// - Parameter timeoutInterval: The length of time the request should wait before timeout.  Default is 30 seconds (OCI Functions default).
    /// - Returns: A URLRequest object.
    /// - Throws: OciRequestSignerError based on the error.
    public func getUrlRequest(url: URL, timeoutInterval: Double = 30) throws -> URLRequest {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringCacheData, timeoutInterval: timeoutInterval)
        
        let timezone = TimeZone(abbreviation: "UTC")
        let rfcDateFormat = DateFormatter()
        rfcDateFormat.dateFormat = "EEE, dd MMM yyyy HH:mm:ss z"
        rfcDateFormat.timeZone = timezone
        let dateStr = rfcDateFormat.string(from: Date())
        
        request.setValue(dateStr, forHTTPHeaderField: "date")
        request.setValue(url.host!, forHTTPHeaderField: "host")
        
        return request
    }
    
    /// Adds the x-content-sha256 header based on the http request body.
    /// - Parameter request: The URL request to add the header to.
    /// - Returns: A URLRequest object containing the calculated x-content-sha256 based on the http body.
    public func addXContentHeader(_ request: URLRequest) -> URLRequest {
        var newRequest = request
        let data = request.httpBody ?? Data()
        let newHeader = data.sha256().base64EncodedString()
        newRequest.setValue(newHeader, forHTTPHeaderField: "x-content-sha256")
        
        return newRequest
    }
    
    /// Performs the signing process on the URL request.
    /// - Parameter request: The URL request to add the Authorization header to.
    /// - Throws: OciRequestSignerError based on the error.
    public func sign(_ request: URLRequest) throws -> URLRequest {
        var newRequest = request
        
        guard let tenancy = self.tenancyId, let user = self.userId, let thumb = self.thumbprint, let k = self.key else {
            throw OciRequestSignerError.paramsNotSet
        }
        
        var headersToSign = [
            "date",
            "(request-target)",
            "host"
        ]
        
        if newRequest.value(forHTTPHeaderField: "x-date") != nil {
            headersToSign[0] = "x-date"
        }
        
        let addHeaders = {
            headersToSign.append("content-length")
            headersToSign.append("content-type")
            headersToSign.append("x-content-sha256")
            
            // Ensure that the request has the content-length header
            if newRequest.value(forHTTPHeaderField: "content-length") == nil {
                let count = request.httpBody != nil ? String(request.httpBody!.count) : "0"
                newRequest.setValue(count, forHTTPHeaderField: "content-length")
            }
            
            // Ensure that the request has the content-type header
            if newRequest.value(forHTTPHeaderField: "content-type") == nil {
                newRequest.setValue("application/json", forHTTPHeaderField: "content-type")
            }
            
            // Ensure that the request has the x-content-sha256 header
            if newRequest.value(forHTTPHeaderField: "x-content-sha256") == nil {
                newRequest = self.addXContentHeader(newRequest)
            }
        }
        
        switch newRequest.httpMethod {
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
                guard let method = newRequest.httpMethod?.lowercased() else { throw OciRequestSignerError.httpMethodMissing }
                guard let url = newRequest.url else { throw OciRequestSignerError.httpUrlMissing }
                let urlPath = url.path
                
                var rtHeader = String(format: "%@ %@", method, urlPath)
                if let query = url.query {
                    rtHeader = String(format: "%@?%@", rtHeader.lowercased(), query)
                }
                
                signingStr = String(format: "%@%@: %@", signingStr, header.lowercased(), rtHeader)
                break
            default:
                guard let val = newRequest.value(forHTTPHeaderField: header) else { throw OciRequestSignerError.signingHeaderMissing }
                signingStr = String(format: "%@%@: %@", signingStr, header.lowercased(), val)
                break
            }
            
            if header != headersToSign.last {
                signingStr = signingStr + "\n"
            }
        }
        
        let myPlaintext = try CryptorRSA.createPlaintext(with: signingStr, using: .utf8)
        let signedData = try myPlaintext.signed(with: k, algorithm: .sha256)
        guard let base64Sig = signedData?.base64String else { throw OciRequestSignerError.signingError }
        
        let authHeader = String(format: "Signature version=\"%.0f\",headers=\"%@\",keyId=\"%@\",algorithm=\"rsa-sha256\",signature=\"%@\"", self.signatureVersion.rawValue, headersToSign.joined(separator: " "), apiKeyId, base64Sig)
        
        newRequest.setValue(authHeader, forHTTPHeaderField: "Authorization")
        
        return newRequest
    }
}
